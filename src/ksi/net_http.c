/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
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
		int (*serialize)(void *, unsigned char **, unsigned *),
		KSI_RequestHandle **handle,
		char *url,
		const char *desc) {
	KSI_ERR err;
	int res;
	KSI_HttpClient *http = (KSI_HttpClient *)client;
	KSI_RequestHandle *tmp = NULL;
	unsigned char *raw = NULL;
	unsigned raw_len = 0;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_PRE(&err, pdu != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	res = serialize(pdu, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(client->ctx, KSI_LOG_DEBUG, desc, raw, raw_len);

	/* Create a new request handle */
	res = KSI_RequestHandle_new(client->ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	if (http->sendRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}

	res = http->sendRequest(client, tmp, url);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RequestHandle_free(tmp);
	KSI_free(raw);

	return KSI_RETURN(&err);
}

static int prepareExtendRequest(KSI_NetworkClient *client, KSI_ExtendReq *req, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendPdu *pdu = NULL;

	res = KSI_ExtendReq_enclose(req, client->extUser, client->extPass, &pdu);
	if (res != KSI_OK) goto cleanup;

	res = prepareRequest(
			client,
			pdu,
			(int (*)(void *, unsigned char **, unsigned *))KSI_ExtendPdu_serialize,
			handle,
			((KSI_HttpClient*)client)->urlExtender,
			"Extend request");

	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	KSI_ExtendPdu_setRequest(pdu, NULL);
	KSI_ExtendPdu_free(pdu);

	return res;
}

static int prepareAggregationRequest(KSI_NetworkClient *client, KSI_AggregationReq *req, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationPdu *pdu = NULL;

	res = KSI_AggregationReq_enclose(req, client->aggrUser, client->aggrPass, &pdu);
	if (res != KSI_OK) goto cleanup;

	res = prepareRequest(
			client,
			pdu,
			(int (*)(void *, unsigned char **, unsigned *))KSI_AggregationPdu_serialize,
			handle,
			((KSI_HttpClient*)client)->urlAggregator,
			"Aggregation request");
cleanup:

	KSI_AggregationPdu_setRequest(pdu, NULL);
	KSI_AggregationPdu_free(pdu);

	return res;
}

static int preparePublicationsFileRequest(KSI_NetworkClient *client, KSI_RequestHandle **handle) {
	KSI_ERR err;
	int res = KSI_UNKNOWN_ERROR;
	KSI_HttpClient *http = (KSI_HttpClient *) client;
	KSI_RequestHandle *tmp = NULL;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	if (http->sendRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}

	res = KSI_RequestHandle_new(client->ctx, NULL, 0, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = http->sendRequest(client, tmp, http->urlPublication);
	if (res != KSI_OK) goto cleanup;

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
	KSI_ERR err;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_NetworkClient_init(ctx, &client->parent);
	KSI_CATCH(&err, res) goto cleanup;

	client->agentName = NULL;
	client->sendRequest = NULL;
	client->urlExtender = NULL;
	client->urlPublication = NULL;
	client->urlAggregator = NULL;
	client->httpStatus = 0;

	client->parent.sendExtendRequest = prepareExtendRequest;
	client->parent.sendSignRequest = prepareAggregationRequest;
	client->parent.sendPublicationRequest = preparePublicationsFileRequest;
	client->parent.getStausCode = getHttpStatusCode;
	client->parent.implFree = (void (*)(void *))httpClient_free;


	setIntParam(&client->connectionTimeoutSeconds, 10);
	setIntParam(&client->readTimeoutSeconds, 10);
	setStringParam(&client->urlPublication, KSI_DEFAULT_URI_PUBLICATIONS_FILE);
	setStringParam(&client->agentName, "KSI HTTP Client"); /** Should be only user provided */

	res = KSI_HttpClientImpl_init(client);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_HttpClient_new(KSI_CTX *ctx, KSI_HttpClient **http) {
	KSI_ERR err;
	KSI_HttpClient *tmp = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_HttpClient);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = KSI_HttpClient_init(ctx, tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*http = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_HttpClient_free(tmp);

	return KSI_RETURN(&err);
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

KSI_NET_IMPLEMENT_SETTER(SignerUrl, const char *, urlAggregator, setStringParam);
KSI_NET_IMPLEMENT_SETTER(ExtenderUrl, const char *, urlExtender, setStringParam);
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
