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

#include "net_impl.h"
#include "net_uri.h"
#include "net_uri_impl.h"
#include "net_tcp.h"
#include "net_http.h"
#include "net_file.h"
#include "http_parser.h"
#include "net_async.h"

static int getClientByUriScheme(const char *scheme, const char **replaceScheme);

static int prepareExtendRequest(KSI_NetworkClient *client, KSI_ExtendReq *req, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_UriClient *uriClient = NULL;

	if (client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	uriClient = client->impl;

	res = KSI_NetworkClient_sendExtendRequest(uriClient->pExtendClient, req, handle);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;
cleanup:
	return res;
}

static int prepareAggregationRequest(KSI_NetworkClient *client, KSI_AggregationReq *req, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_UriClient *uriClient = NULL;

	if (client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	uriClient = client->impl;

	res = KSI_NetworkClient_sendSignRequest(uriClient->pAggregationClient, req, handle);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;
cleanup:
	return res;
}

static int sendPublicationRequest(KSI_NetworkClient *client, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_UriClient *uriClient = NULL;

	if (client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	uriClient = client->impl;

	res = KSI_NetworkClient_sendPublicationsFileRequest(uriClient->pPublicationClient, handle);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static void uriClient_free(KSI_UriClient *client) {
	if (client != NULL) {
		KSI_NetworkClient_free(client->httpClient);
		KSI_NetworkClient_free(client->tcpClient);
		KSI_NetworkClient_free(client->fsClient);
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
	u->fsClient = NULL;
	u->pAggregationClient = NULL;
	u->pExtendClient = NULL;
	u->pPublicationClient = NULL;

	res = KSI_HttpClient_new(ctx, &u->httpClient);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	u->pExtendClient = u->httpClient;
	u->pAggregationClient = u->httpClient;
	u->pPublicationClient = u->httpClient;

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
	KSI_UriClient *uriClient = NULL;
	int c;
	char *schm = NULL;
	char *host = NULL;
	unsigned port = 0;
	char *path = NULL;
	const char *replace = NULL;
	KSI_NetworkClient *pubClient = NULL;

	if (client == NULL || val == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	uriClient = client->impl;

	KSI_UriSplitBasic(val, &schm, &host, &port, &path);
	c = getClientByUriScheme(schm, &replace);

	switch (c) {
		case URI_HTTP:
		case URI_TCP:
		case URI_UNKNOWN:
			pubClient = uriClient->httpClient;
			res = KSI_HttpClient_setPublicationUrl(pubClient, val);
			if (res != KSI_OK) goto cleanup;
			break;
		case URI_FILE:
			if (path != NULL) {
				KSI_free(path);
				path = NULL;
			}
			KSI_FsClient_extractPath(val, &path);

			if (path == NULL) {
				res = KSI_INVALID_ARGUMENT;
				goto cleanup;
			}

			/* Make sure the File client is initialized. */
			if (uriClient->fsClient == NULL) {
				res = KSI_FsClient_new(client->ctx, &uriClient->fsClient);
				if (res != KSI_OK) goto cleanup;
			}
			pubClient = uriClient->fsClient;

			res = KSI_FsClient_setPublicationUrl(pubClient, path);
			if (res != KSI_OK) goto cleanup;
			break;
		default:
			res = KSI_UNKNOWN_ERROR;
			goto cleanup;
			break;
	}
	uriClient->pPublicationClient = pubClient;

	res = KSI_OK;

cleanup:
	KSI_free(schm);
	KSI_free(host);
	KSI_free(path);

	return res;
}

static int getClientByUriScheme(const char *scheme, const char **replaceScheme) {
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
			{"file", NULL, URI_FILE},
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
		netClient = URI_UNKNOWN;
	}

	return netClient;
}

static int uriClient_setService(KSI_NetworkClient *client, const char *uri, const char *loginId, const char *key,
		int (*HttpClient_setService)(KSI_NetworkClient *client, const char *url, const char *user, const char *pass),
		int (*TcpClient_setService)(KSI_NetworkClient *client, const char *host, unsigned port, const char *user, const char *pass),
		int (*FsClient_setService)(KSI_NetworkClient *client, const char *path, const char *user, const char *pass),
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

	if (client == NULL || serviceClient == NULL || uri == NULL ||
		HttpClient_setService == NULL || TcpClient_setService == NULL || FsClient_setService == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	uri_client = client->impl;

	res = client->uriSplit(uri, &schm, &ksi_user, &ksi_pass, &host, &port, &path, &query, &fragment);
	if (res != KSI_OK) unableToParse = 1;

	c = getClientByUriScheme(schm, &replace);
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

		case URI_UNKNOWN:
			res = HttpClient_setService(uri_client->httpClient, uri, loginId, key);
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
		case URI_FILE:

			if (path != NULL) {
				KSI_free(path);
				path = NULL;
			}
			KSI_FsClient_extractPath(uri, &path);

			if (path == NULL) {
				res = KSI_INVALID_ARGUMENT;
				goto cleanup;
			}

			/* Make sure the File client is initialized. */
			if (uri_client->fsClient == NULL) {
				res = KSI_FsClient_new(client->ctx, &uri_client->fsClient);
				if (res != KSI_OK) goto cleanup;
			}

			res = FsClient_setService(uri_client->fsClient, path, loginId, key);
			if (res != KSI_OK) goto cleanup;

			/* Set the client to be used in extending requests. */
			*serviceClient = (KSI_NetworkClient *)uri_client->fsClient;

			break;
		default:
			res = KSI_INVALID_FORMAT;
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
			KSI_FsClient_setExtender,
			&((KSI_UriClient*)(client->impl))->pExtendClient);
}

int KSI_UriClient_setAggregator(KSI_NetworkClient *client, const char *uri, const char *loginId, const char *key) {
	if (client == NULL || client->impl == NULL || uri == NULL) return KSI_INVALID_ARGUMENT;
	return uriClient_setService(client, uri, loginId, key,
			KSI_HttpClient_setAggregator,
			KSI_TcpClient_setAggregator,
			KSI_FsClient_setAggregator,
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

static int uri_setAsyncService(KSI_AsyncService *s, const char *uri, const char *loginId, const char *key) {
	int res = KSI_UNKNOWN_ERROR;
	char *schm = NULL;
	char *ksi_user = NULL;
	char *ksi_pass = NULL;
	char *host = NULL;
	unsigned port = 0;
	char *path = NULL;
	char *query = NULL;
	char *fragment = NULL;
	const char *replace = NULL;
	int c;

	if (s == NULL || uri == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	s->uriSplit(uri, &schm, &ksi_user, &ksi_pass, &host, &port, &path, &query, &fragment);
	c = getClientByUriScheme(schm, &replace);

	switch (c) {
		case URI_TCP:
			if (host == NULL || port == 0) {
				res = KSI_INVALID_ARGUMENT;
				goto cleanup;
			}

			if (s->impl == NULL) {
				s->impl_free = (void (*)(void*))KSI_AsyncClient_free;
				res = KSI_TcpAsyncClient_new(s->ctx, (KSI_AsyncClient **)&s->impl);
				if (res != KSI_OK) goto cleanup;
			}

			res = KSI_TcpAsyncClient_setService(s->impl, host, port,
					loginId != NULL ? loginId : ksi_user,
					key != NULL ? key : ksi_pass);
			if (res != KSI_OK) goto cleanup;
			break;

		case URI_HTTP:
		case URI_FILE:
		case URI_UNKNOWN:
		default:
			res = KSI_INVALID_FORMAT;
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

int KSI_AsyncService_setEndpoint(KSI_AsyncService *s, const char *uri, const char *loginId, const char *key) {
	if (s == NULL || uri == NULL) return KSI_INVALID_ARGUMENT;
	return uri_setAsyncService(s, uri, loginId, key);
}
