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
#include "net_http_impl.h"
#include <assert.h>
#include "ctx_impl.h"

static int setStringParam(char **param, const char *val) {
	char *tmp = NULL;
	int res = KSI_UNKNOWN_ERROR;

	tmp = KSI_calloc(strlen(val) + 1, 1);
	if (tmp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	memcpy(tmp, val, strlen(val) + 1);

	if (*param != NULL) {
		KSI_free(*param);
	}

	*param = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);

	return res;
}

static int setIntParam(int *param, int val) {
	*param = val;
	return KSI_OK;
}

static int prepareRequest(
		KSI_NetworkClient *client,
		void *pdu,
		int (*serialize)(void *, unsigned char **, size_t *),
		KSI_RequestHandle **handle,
		char *url,
		const char *desc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HttpClient *http = client->impl;
	KSI_RequestHandle *tmp = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;

	if (client == NULL || pdu == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(client->ctx);

	res = serialize(pdu, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logBlob(client->ctx, KSI_LOG_DEBUG, desc, raw, raw_len);

	/* Create a new request handle */
	res = KSI_RequestHandle_new(client->ctx, raw, raw_len, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	if (http->sendRequest == NULL) {
		KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}

	res = http->sendRequest(client, tmp, url);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	*handle = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_RequestHandle_free(tmp);
	KSI_free(raw);

	return res;
}

static int prepareExtendRequest(KSI_NetworkClient *client, KSI_ExtendReq *req, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendPdu *pdu = NULL;
	KSI_Integer *pReqId = NULL;
	KSI_Integer *reqId = NULL;

	if (client == NULL || req == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (((KSI_HttpClient*)client)->urlExtender == NULL) {
		res = KSI_EXTENDER_NOT_CONFIGURED;
		goto cleanup;
	}

	res = KSI_ExtendReq_getRequestId(req, &pReqId);
	if (res != KSI_OK) goto cleanup;

	if (pReqId == NULL) {
		res = KSI_Integer_new(client->ctx, ++client->requestCount, &reqId);
		if (res != KSI_OK) goto cleanup;

		res = KSI_ExtendReq_setRequestId(req, reqId);
		if (res != KSI_OK) goto cleanup;

		reqId = NULL;
	}

	res = KSI_ExtendReq_enclose(req, client->extUser, client->extPass, &pdu);
	if (res != KSI_OK) goto cleanup;

	res = prepareRequest(
			client,
			pdu,
			(int (*)(void *, unsigned char **, size_t *))KSI_ExtendPdu_serialize,
			handle,
			((KSI_HttpClient*)client)->urlExtender,
			"Extend request");

	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	KSI_Integer_free(reqId);
	KSI_ExtendPdu_setRequest(pdu, NULL);
	KSI_ExtendPdu_free(pdu);

	return res;
}

static int prepareAggregationRequest(KSI_NetworkClient *client, KSI_AggregationReq *req, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationPdu *pdu = NULL;
	KSI_Integer *pReqId = NULL;
	KSI_Integer *reqId = NULL;
	KSI_HttpClient *http = NULL;

	if (client == NULL || req == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	http = client->impl;

	if (http->urlAggregator == NULL) {
		res = KSI_AGGREGATOR_NOT_CONFIGURED;
		goto cleanup;
	}

	res = KSI_AggregationReq_getRequestId(req, &pReqId);
	if (res != KSI_OK) goto cleanup;

	if (pReqId == NULL) {
		res = KSI_Integer_new(client->ctx, ++client->requestCount, &reqId);
		if (res != KSI_OK) goto cleanup;

		res = KSI_AggregationReq_setRequestId(req, reqId);
		if (res != KSI_OK) goto cleanup;

		reqId = NULL;
	}

	res = KSI_AggregationReq_enclose(req, client->aggrUser, client->aggrPass, &pdu);
	if (res != KSI_OK) goto cleanup;

	res = prepareRequest(
			client,
			pdu,
			(int (*)(void *, unsigned char **, size_t *))KSI_AggregationPdu_serialize,
			handle,
			http->urlAggregator,
			"Aggregation request");
cleanup:

	KSI_Integer_free(reqId);
	KSI_AggregationPdu_setRequest(pdu, NULL);
	KSI_AggregationPdu_free(pdu);

	return res;
}

static int preparePublicationsFileRequest(KSI_NetworkClient *client, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HttpClient *http = NULL;
	KSI_RequestHandle *tmp = NULL;

	if (client == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(client->ctx);

	http = client->impl;

	if (http->urlPublication == NULL) {
		KSI_pushError(client->ctx, res = KSI_PUBLICATIONS_FILE_NOT_CONFIGURED, "The publications file URL has not been configured.");
		goto cleanup;
	}

	if (http->sendRequest == NULL) {
		KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}

	res = KSI_RequestHandle_new(client->ctx, NULL, 0, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	res = http->sendRequest(client, tmp, http->urlPublication);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	*handle = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	return res;
}

static void httpClient_free(KSI_HttpClient *http) {
	if (http != NULL) {
		KSI_free(http->urlAggregator);
		KSI_free(http->urlExtender);
		KSI_free(http->urlPublication);
		KSI_free(http->agentName);
		
		if (http->implCtx_free != NULL) http->implCtx_free(http->implCtx);
		KSI_free(http);
	}
}

int KSI_AbstractHttpClient_new(KSI_CTX *ctx, KSI_NetworkClient **http) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_NetworkClient *tmp = NULL;
	KSI_HttpClient *c = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || http == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_AbstractNetworkClient_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	c = KSI_new(KSI_HttpClient);
	if (c == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	c->agentName = NULL;
	c->sendRequest = NULL;
	c->urlExtender = NULL;
	c->urlPublication = NULL;
	c->urlAggregator = NULL;
	c->implCtx = NULL;
	c->implCtx_free = NULL;

	tmp->sendExtendRequest = prepareExtendRequest;
	tmp->sendSignRequest = prepareAggregationRequest;
	tmp->sendPublicationRequest = preparePublicationsFileRequest;

	setIntParam(&c->connectionTimeoutSeconds, 10); /* FIXME! Magic constants. */
	setIntParam(&c->readTimeoutSeconds, 10);
	setStringParam(&c->agentName, "KSI HTTP Client"); /** Should be only user provided */

	tmp->impl = c;
	tmp->implFree = (void (*)(void*))httpClient_free;
	c = NULL;

	*http = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	httpClient_free(c);
	KSI_NetworkClient_free(tmp);

	return res;
}


#define KSI_NET_IMPLEMENT_SETTER(name, type, var, fn) 													\
		int KSI_HttpClient_set##name(KSI_NetworkClient *client, type val) {								\
			int res = KSI_UNKNOWN_ERROR;																\
			KSI_HttpClient *http = NULL;																\
			if (client == NULL) {																		\
				res = KSI_INVALID_ARGUMENT;																\
				goto cleanup;																			\
			}																							\
			http = client->impl;																		\
			res = (fn)(&http->var, val);																\
		cleanup:																						\
			return res;																					\
		}																								\

KSI_NET_IMPLEMENT_SETTER(PublicationUrl, const char *, urlPublication, setStringParam);
KSI_NET_IMPLEMENT_SETTER(ConnectTimeoutSeconds, int, connectionTimeoutSeconds, setIntParam);
KSI_NET_IMPLEMENT_SETTER(ReadTimeoutSeconds, int, readTimeoutSeconds, setIntParam);

int KSI_HttpClient_setExtender(KSI_NetworkClient *client, const char *url, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HttpClient *http = NULL;
	if (client == NULL || url == NULL || user == NULL || pass == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	http = client->impl;

	res = setStringParam(&http->urlExtender, url);
	if (res != KSI_OK) goto cleanup;

	res = setStringParam(&client->extUser, user);
	if (res != KSI_OK) goto cleanup;

	res = setStringParam(&client->extPass, pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_HttpClient_setAggregator(KSI_NetworkClient *client, const char *url, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HttpClient *http = NULL;
	if (client == NULL || url == NULL || user == NULL || pass == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	http = client->impl;

	res = setStringParam(&http->urlAggregator, url);
	if (res != KSI_OK) goto cleanup;

	res = setStringParam(&client->aggrUser, user);
	if (res != KSI_OK) goto cleanup;

	res = setStringParam(&client->aggrPass, pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}
