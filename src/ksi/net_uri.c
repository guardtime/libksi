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
	KSI_UriClient *uriClient = (KSI_UriClient *)client;
	return KSI_NetworkClient_sendExtendRequest(uriClient->pExtendClient, req, handle);
}

static int prepareAggregationRequest(KSI_NetworkClient *client, KSI_AggregationReq *req, KSI_RequestHandle **handle) {
	KSI_UriClient *uriClient = (KSI_UriClient *)client;
	return KSI_NetworkClient_sendSignRequest(uriClient->pAggregationClient, req, handle);
}

static int sendPublicationRequest(KSI_NetworkClient *client, KSI_RequestHandle **handle) {
	int res;
	KSI_UriClient *uriClient = (KSI_UriClient *)client;

	res = KSI_NetworkClient_sendPublicationsFileRequest((KSI_NetworkClient *)uriClient->httpClient, handle);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_UriClient_new(KSI_CTX *ctx, KSI_UriClient **client) {
	int res;
	KSI_UriClient *tmp = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || client == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_UriClient);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->httpClient = NULL;
	tmp->tcpClient = NULL;
	tmp->pAggregationClient = NULL;
	tmp->pExtendClient = NULL;

	res = KSI_UriClient_init(ctx, tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*client = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_UriClient_free(tmp);

	return res;
}

static void uriClient_free(KSI_UriClient *client) {
	if (client != NULL) {
		KSI_HttpClient_free(client->httpClient);
		KSI_TcpClient_free(client->tcpClient);
		KSI_free(client);
	}
}

int KSI_UriClient_init(KSI_CTX *ctx, KSI_UriClient *client) {
	int res;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || client == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_NetworkClient_init(ctx, &client->parent);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_HttpClient_new(ctx, &client->httpClient);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	client->pExtendClient = (KSI_NetworkClient *)client->httpClient;
	client->pAggregationClient = (KSI_NetworkClient *)client->httpClient;

	client->parent.sendExtendRequest = prepareExtendRequest;
	client->parent.sendSignRequest = prepareAggregationRequest;
	client->parent.sendPublicationRequest = sendPublicationRequest;
	client->parent.implFree = (void (*)(void *))uriClient_free;

	res = KSI_OK;

cleanup:

	return res;
}

void KSI_UriClient_free(KSI_UriClient *client) {
	KSI_NetworkClient_free((KSI_NetworkClient *) client);
}
int KSI_UriClient_setPublicationUrl(KSI_UriClient *client, const char *val) {
	int res = KSI_UNKNOWN_ERROR;

	if (client == NULL || val == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_HttpClient_setPublicationUrl(client->httpClient, val);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

enum serviceMethod_e {
	SRV_EXTEND,
	SRV_AGGREGATE
};

int getClientByUriScheme(const char *uri, struct http_parser_url *u, const char **replaceScheme) {
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

	memset(u, 0, sizeof(struct http_parser_url));
	res = http_parser_parse_url(uri, strlen(uri), 0, u);
	if (res == 0 && (u->field_set & (1 << UF_SCHEMA)) != 0) {
		int i = 0;
		while (schemeMap[i].scheme != NULL) {
			if (strlen(schemeMap[i].scheme) == u->field_data[UF_SCHEMA].len &&
					!strncmp(schemeMap[i].scheme, uri + u->field_data[UF_SCHEMA].off, strlen(schemeMap[i].scheme))) {
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

int KSI_UriClient_setExtender(KSI_UriClient *client, const char *uri, const char *loginId, const char *key) {
	int res;
	char addr[0xffff];
	struct http_parser_url u;
	const char *replace = NULL;
	int c;

	c = getClientByUriScheme(uri, &u, &replace);

	switch (c) {
		case URI_HTTP:
			if (replace != NULL) {
				/* Create a new URL where the scheme is replaced with the correct one. */
				KSI_snprintf(addr, sizeof(addr), "%s%s", replace, uri + u.field_data[UF_SCHEMA].off + u.field_data[UF_SCHEMA].len);
			}

			res = KSI_HttpClient_setExtender(client->httpClient, replace != NULL ? addr : uri, loginId, key);
			if (res != KSI_OK) goto cleanup;

			/* Set the client to be used in extending requests. */
			client->pExtendClient = (KSI_NetworkClient *)client->httpClient;

			break;
		case URI_TCP:
			if ((u.field_set & (1 << UF_HOST)) == 0 || u.port == 0) {
				res = KSI_INVALID_ARGUMENT;
				goto cleanup;
			}

			/* Make sure the TCP client is initialized. */
			if (client->tcpClient == NULL) {
				res = KSI_TcpClient_new(client->parent.ctx, &client->tcpClient);
				if (res != KSI_OK) goto cleanup;
			}

			/* Extract the host to a proper null-terminated string. */
			KSI_snprintf(addr, sizeof(addr), "%.*s", u.field_data[UF_HOST].len, uri + u.field_data[UF_HOST].off);

			res = KSI_TcpClient_setExtender(client->tcpClient, addr, u.port, loginId, key);
			if (res != KSI_OK) goto cleanup;

			/* Set the client to be used in extending requests. */
			client->pExtendClient = (KSI_NetworkClient *)client->tcpClient;

			break;
		default:
			res = KSI_UNKNOWN_ERROR;
			goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_UriClient_setAggregator(KSI_UriClient *client, const char *uri, const char *loginId, const char *key) {
	int res;
	char addr[0xffff];
	struct http_parser_url u;
	const char *replace = NULL;
	int c;

	c = getClientByUriScheme(uri, &u, &replace);

	switch (c) {
		case URI_HTTP:
			if (replace != NULL) {
				/* Create a new URL where the scheme is replaced with the correct one. */
				KSI_snprintf(addr, sizeof(addr), "%s%s", replace, uri + u.field_data[UF_SCHEMA].off + u.field_data[UF_SCHEMA].len);
			}

			res = KSI_HttpClient_setAggregator(client->httpClient, replace != NULL ? addr : uri, loginId, key);
			if (res != KSI_OK) goto cleanup;

			/* Set the client to be used in extending requests. */
			client->pAggregationClient = (KSI_NetworkClient *)client->httpClient;

			break;
		case URI_TCP:
			if ((u.field_set & (1 << UF_HOST)) == 0 || u.port == 0) {
				res = KSI_INVALID_ARGUMENT;
				goto cleanup;
			}

			/* Make sure the TCP client is initialized. */
			if (client->tcpClient == NULL) {
				res = KSI_TcpClient_new(client->parent.ctx, &client->tcpClient);
				if (res != KSI_OK) goto cleanup;
			}

			/* Extract the host to a proper null-terminated string. */
			KSI_snprintf(addr, sizeof(addr), "%.*s", u.field_data[UF_HOST].len, uri + u.field_data[UF_HOST].off);

			res = KSI_TcpClient_setAggregator(client->tcpClient, addr, u.port, loginId, key);
			if (res != KSI_OK) goto cleanup;

			/* Set the client to be used in extending requests. */
			client->pAggregationClient = (KSI_NetworkClient *)client->tcpClient;

			break;
		default:
			res = KSI_UNKNOWN_ERROR;
			goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_UriClient_setConnectionTimeoutSeconds(KSI_UriClient *client, int timeout) {
	int res;

	if (client->httpClient){
		res = KSI_HttpClient_setConnectTimeoutSeconds(client->httpClient, timeout);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_UriClient_setTransferTimeoutSeconds(KSI_UriClient *client, int timeout) {
	int res;

	if (client->httpClient){
		res = KSI_HttpClient_setReadTimeoutSeconds(client->httpClient, timeout);
		if (res != KSI_OK) goto cleanup;
	}
	if (client->tcpClient){
		res = KSI_TcpClient_setTransferTimeoutSeconds(client->tcpClient, timeout);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}
