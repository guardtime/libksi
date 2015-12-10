/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

#include <string.h>

#include "internal.h"

#include "net.h"
#include "net_uri.h"
#include "net_uri_impl.h"
#include "net_tcp.h"
#include "net_http.h"
#include "http_parser.h"

static int prepareExtendRequest(KSI_NetworkClient *client, KSI_ExtendReq *req, KSI_RequestHandle **handle) {
	KSI_UriClient *uriClient = client->impl;
	return KSI_NetworkClient_sendExtendRequest(uriClient->pExtendClient, req, handle);
}

static int prepareAggregationRequest(KSI_NetworkClient *client, KSI_AggregationReq *req, KSI_RequestHandle **handle) {
	KSI_UriClient *uriClient = client->impl;
	return KSI_NetworkClient_sendSignRequest(uriClient->pAggregationClient, req, handle);
}

static int sendPublicationRequest(KSI_NetworkClient *client, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_UriClient *uriClient = client->impl;

	res = KSI_NetworkClient_sendPublicationsFileRequest((KSI_NetworkClient *)uriClient->httpClient, handle);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static void uriClient_free(KSI_UriClient *client) {
	if (client != NULL) {
		KSI_NetworkClient_free(client->httpClient);
		KSI_NetworkClient_free(client->tcpClient);
		KSI_free(client);
	}
}

int KSI_UriClient_new(KSI_CTX *ctx, KSI_NetworkClient **client) {
	int res;
	KSI_NetworkClient *tmp = NULL;
	KSI_UriClient *u = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || client == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_AbstractNetworkClient_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	u = KSI_new(KSI_UriClient);
	if (u == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	u->httpClient = NULL;
	u->tcpClient = NULL;
	u->pAggregationClient = NULL;
	u->pExtendClient = NULL;

	res = KSI_HttpClient_new(ctx, &u->httpClient);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	u->pExtendClient = u->httpClient;
	u->pAggregationClient = u->httpClient;

	tmp->sendExtendRequest = prepareExtendRequest;
	tmp->sendSignRequest = prepareAggregationRequest;
	tmp->sendPublicationRequest = sendPublicationRequest;
	tmp->requestCount = 0;

	tmp->impl = u;
	tmp->implFree = (void (*)(void *))uriClient_free;
	u = NULL;

	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*client = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_NetworkClient_free(tmp);
	uriClient_free(u);

	return res;
}

int KSI_UriClient_setPublicationUrl(KSI_NetworkClient *client, const char *val) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_UriClient *uri = NULL;

	if (client == NULL || val == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	uri = client->impl;

	res = KSI_HttpClient_setPublicationUrl(uri->httpClient, val);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

enum serviceMethod_e {
	SRV_EXTEND,
	SRV_AGGREGATE
};

static int getClientByUriScheme(const char *uri, const char *scheme, const char **replaceScheme) {
	int res;
	int netClient = -1;

	static const struct {
		const char *scheme;
		const char *replace;
		enum client_e client;
	} schemeMap[] = {
			{"ksi", "http", URI_HTTP },
			{"ksi+http", "http",URI_HTTP},
			{"ksi+https", "https", URI_HTTP},
			{"ksi+tcp", NULL, URI_TCP},
			{NULL, NULL, -1}
	};

	if (scheme != NULL) {
		int i = 0;
		while (schemeMap[i].scheme != NULL) {
			if (strcmp(schemeMap[i].scheme, scheme) == 0) {
				netClient = schemeMap[i].client;
				*replaceScheme = schemeMap[i].replace;
				break;
			}
			i++;
		}
	}

	if (netClient == -1) {
		netClient = URI_HTTP;
	}

	return netClient;
}

static int uriClient_setService(KSI_NetworkClient *client, const char *uri, const char *loginId, const char *key,
		int (*HttpClient_setService)(KSI_NetworkClient *client, const char *url, const char *user, const char *pass),
		int (*TcpClient_setService)(KSI_NetworkClient *client, const char *host, unsigned port, const char *user, const char *pass),
		KSI_NetworkClient **serviceClient) {
	int res;
	KSI_UriClient *uri_client = NULL;
	char *schm = NULL;
	char *ksi_user = NULL;
	char *ksi_pass = NULL;
	char *host = NULL;
	unsigned port = 0;
	char *path = NULL;
	char *query = NULL;
	char *fragment = NULL;
	const char *replace = NULL;
	const char *scheme = NULL;
	char addr[0xffff];
	int unableToParse = 0;
	int c;

	if (client == NULL || serviceClient == NULL || uri == NULL || HttpClient_setService == NULL || TcpClient_setService == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	uri_client = client->impl;

	res = client->uriSplit(uri, &schm, &ksi_user, &ksi_pass, &host, &port, &path, &query, &fragment);
	if (res != KSI_OK) unableToParse = 1;

	c = getClientByUriScheme(uri, schm, &replace);
	scheme = (replace != NULL) ? replace : schm;


	switch (c) {
		case URI_HTTP:

			if (unableToParse == 0) {
				/* Create a new URL where the scheme is replaced with the correct one and KSI user and pass is removed. */
				res = client->uriCompose(scheme, NULL, NULL, host, port, path, query, fragment, addr, sizeof(addr));
				if (res != KSI_OK) goto cleanup;
			}
			res = HttpClient_setService(uri_client->httpClient,
					unableToParse == 1 ? uri : addr,
					loginId != NULL ? loginId : ksi_user,
					key != NULL ? key : ksi_pass);
			if (res != KSI_OK) goto cleanup;

			/* Set the client to be used in extending requests. */
			*serviceClient = (KSI_NetworkClient *)uri_client->httpClient;

			break;
		case URI_TCP:

			if (host == NULL || port == 0) {
				res = KSI_INVALID_ARGUMENT;
				goto cleanup;
			}

			/* Make sure the TCP client is initialized. */
			if (uri_client->tcpClient == NULL) {
				res = KSI_TcpClient_new(client->ctx, &uri_client->tcpClient);
				if (res != KSI_OK) goto cleanup;
			}

			res = TcpClient_setService(uri_client->tcpClient, host, port,
					loginId != NULL ? loginId : ksi_user,
					key != NULL ? key : ksi_pass);
			if (res != KSI_OK) goto cleanup;

			/* Set the client to be used in extending requests. */
			*serviceClient = (KSI_NetworkClient *)uri_client->tcpClient;

			break;
		default:
			res = KSI_UNKNOWN_ERROR;
			goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_free(schm);
	KSI_free(ksi_user);
	KSI_free(ksi_pass);
	KSI_free(host);
	KSI_free(path);
	KSI_free(query);
	KSI_free(fragment);

	return res;
}

int KSI_UriClient_setExtender(KSI_NetworkClient *client, const char *uri, const char *loginId, const char *key) {
	if (client == NULL || client->impl == NULL || uri == NULL) return KSI_INVALID_ARGUMENT;
	return uriClient_setService(client, uri, loginId, key,
			KSI_HttpClient_setExtender,
			KSI_TcpClient_setExtender,
			&((KSI_UriClient*)(client->impl))->pExtendClient);
}

int KSI_UriClient_setAggregator(KSI_NetworkClient *client, const char *uri, const char *loginId, const char *key) {
	if (client == NULL || client->impl == NULL || uri == NULL) return KSI_INVALID_ARGUMENT;
	return uriClient_setService(client, uri, loginId, key,
			KSI_HttpClient_setAggregator,
			KSI_TcpClient_setAggregator,
			&((KSI_UriClient*)(client->impl))->pAggregationClient);
}

int KSI_UriClient_setConnectionTimeoutSeconds(KSI_NetworkClient *client, int timeout) {
	int res;
	KSI_UriClient *uri = NULL;

	if (client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	uri = client->impl;

	if (uri->httpClient) {
		res = KSI_HttpClient_setConnectTimeoutSeconds(uri->httpClient, timeout);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_UriClient_setTransferTimeoutSeconds(KSI_NetworkClient *client, int timeout) {
	int res;
	KSI_UriClient *uri = NULL;

	if (client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	uri = client->impl;

	if (uri->httpClient) {
		res = KSI_HttpClient_setReadTimeoutSeconds(uri->httpClient, timeout);
		if (res != KSI_OK) goto cleanup;
	}
	if (uri->tcpClient){
		res = KSI_TcpClient_setTransferTimeoutSeconds(uri->tcpClient, timeout);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}
