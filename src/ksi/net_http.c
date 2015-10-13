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
	KSI_HttpClient *http = (KSI_HttpClient *)client;
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

	if (client == NULL || req == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (((KSI_HttpClient*)client)->urlAggregator == NULL) {
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
			((KSI_HttpClient*)client)->urlAggregator,
			"Aggregation request");
cleanup:

	KSI_Integer_free(reqId);
	KSI_AggregationPdu_setRequest(pdu, NULL);
	KSI_AggregationPdu_free(pdu);

	return res;
}

static int preparePublicationsFileRequest(KSI_NetworkClient *client, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HttpClient *http = (KSI_HttpClient *) client;
	KSI_RequestHandle *tmp = NULL;

	if (client == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(client->ctx);

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

void KSI_HttpClient_free(KSI_HttpClient *http) {
	KSI_NetworkClient_free((KSI_NetworkClient*)http);
}

static int getHttpStatusCode(KSI_NetworkClient *client){
	KSI_HttpClient *http = (KSI_HttpClient*)client;
	return http->httpStatus;
}


/**
 *
 */
int KSI_HttpClient_init(KSI_CTX *ctx, KSI_HttpClient *client) {
	int res = KSI_UNKNOWN_ERROR;

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

	client->agentName = NULL;
	client->sendRequest = NULL;
	client->urlExtender = NULL;
	client->urlPublication = NULL;
	client->urlAggregator = NULL;
	client->httpStatus = 0;
	client->implCtx = NULL;
	client->implCtx_free = NULL;

	client->parent.performAll = NULL;
	client->parent.sendExtendRequest = prepareExtendRequest;
	client->parent.sendSignRequest = prepareAggregationRequest;
	client->parent.sendPublicationRequest = preparePublicationsFileRequest;
	client->parent.getStausCode = getHttpStatusCode;
	client->parent.implFree = (void (*)(void *))httpClient_free;

	setIntParam(&client->connectionTimeoutSeconds, 10);
	setIntParam(&client->readTimeoutSeconds, 10);
	setStringParam(&client->agentName, "KSI HTTP Client"); /** Should be only user provided */

	res = KSI_HttpClientImpl_init(client);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

/**
 *
 */
int KSI_HttpClient_new(KSI_CTX *ctx, KSI_HttpClient **http) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HttpClient *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || http == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_HttpClient);
	if (tmp == NULL) {
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
		goto cleanup;
	}

	res = KSI_HttpClient_init(ctx, tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*http = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_HttpClient_free(tmp);

	return res;
}


#define KSI_NET_IMPLEMENT_SETTER(name, type, var, fn) 													\
		int KSI_HttpClient_set##name(KSI_HttpClient *client, type val) {								\
			int res = KSI_UNKNOWN_ERROR;																\
			if (client == NULL) {																		\
				res = KSI_INVALID_ARGUMENT;																\
				goto cleanup;																			\
			}																							\
			res = (fn)(&client->var, val);																\
		cleanup:																						\
			return res;																					\
		}																								\

KSI_NET_IMPLEMENT_SETTER(PublicationUrl, const char *, urlPublication, setStringParam);
KSI_NET_IMPLEMENT_SETTER(ConnectTimeoutSeconds, int, connectionTimeoutSeconds, setIntParam);
KSI_NET_IMPLEMENT_SETTER(ReadTimeoutSeconds, int, readTimeoutSeconds, setIntParam);

int KSI_HttpClient_setExtender(KSI_HttpClient *client, const char *url, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;
	if (client == NULL || url == NULL || user == NULL || pass == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = setStringParam(&client->urlExtender, url);
	if (res != KSI_OK) goto cleanup;

	res = setStringParam(&client->parent.extUser, user);
	if (res != KSI_OK) goto cleanup;

	res = setStringParam(&client->parent.extPass, pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_HttpClient_setAggregator(KSI_HttpClient *client, const char *url, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;
	if (client == NULL || url == NULL || user == NULL || pass == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = setStringParam(&client->urlAggregator, url);
	if (res != KSI_OK) goto cleanup;

	res = setStringParam(&client->parent.aggrUser, user);
	if (res != KSI_OK) goto cleanup;

	res = setStringParam(&client->parent.aggrPass, pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}
