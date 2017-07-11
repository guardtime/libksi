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

#include "http_parser.h"
#include "internal.h"
#include "net_impl.h"
#include "tlv.h"
#include "ctx_impl.h"

KSI_IMPLEMENT_GET_CTX(KSI_NetworkClient);
KSI_IMPLEMENT_GET_CTX(KSI_RequestHandle);

static int newStringFromExisting(char **string, const char *val, int val_len) {
	char *tmp = NULL;
	int res = KSI_UNKNOWN_ERROR;
	size_t new_len = (val_len < 0) ? (strlen(val) + 1) : (val_len);

	tmp = KSI_malloc(strlen(val) + 1);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	memcpy(tmp, val, new_len);
	tmp[new_len - 1] = '\0';

	if (*string != NULL) KSI_free(*string);

	*string = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);

	return res;
}

static int setStringParam(char **param, const char *val) {
	return newStringFromExisting(param, val, -1);
}

static int uriSplit(const char *uri, char **scheme, char **user, char **pass, char **host, unsigned *port, char **path, char **query, char **fragment) {
	int res = KSI_UNKNOWN_ERROR;
	struct http_parser_url parser;
	char *tmpHost = NULL;
	char *tmpSchema = NULL;
	char *tmpPath = NULL;
	char *tmpQuery = NULL;
	char *tmpFragment = NULL;
	char *tmpUserInfo = NULL;
	char *tmpUser = NULL;
	char *tmpPass = NULL;

	if (uri == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&parser, 0, sizeof(struct http_parser_url));

	res = http_parser_parse_url(uri, strlen(uri), 0, &parser);
	if (res != 0) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	/* Extract host. */
	if ((parser.field_set & (1 << UF_HOST)) && (host != NULL)) {
		res = newStringFromExisting(&tmpHost, uri + parser.field_data[UF_HOST].off, parser.field_data[UF_HOST].len + 1);
		if (res != KSI_OK) goto cleanup;
	}

	/* Extract user info. */
	if ((parser.field_set & (1 << UF_USERINFO)) && (user != NULL || pass != NULL)) {
		char *startOfPass = NULL;
		res = newStringFromExisting(&tmpUserInfo, uri + parser.field_data[UF_USERINFO].off, parser.field_data[UF_USERINFO].len + 1);
		if (res != KSI_OK) goto cleanup;

		startOfPass = strchr(tmpUserInfo, ':');
		if (startOfPass == NULL) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}

		*startOfPass++ = '\0';

		if (user != NULL) {
			res = newStringFromExisting(&tmpUser, tmpUserInfo, -1);
			if (res != KSI_OK) goto cleanup;
		}

		if (pass != NULL) {
			res = newStringFromExisting(&tmpPass, startOfPass, -1);
			if (res != KSI_OK) goto cleanup;
		}
	}

	/* Extract schema. */
	if ((parser.field_set & (1 << UF_SCHEMA)) && (scheme != NULL)) {
		res = newStringFromExisting(&tmpSchema, uri + parser.field_data[UF_SCHEMA].off, parser.field_data[UF_SCHEMA].len + 1);
		if (res != KSI_OK) goto cleanup;
	}

	/* Extract path. */
	if ((parser.field_set & (1 << UF_PATH)) && (path != NULL)) {
		res = newStringFromExisting(&tmpPath, uri + parser.field_data[UF_PATH].off, parser.field_data[UF_PATH].len + 1);
		if (res != KSI_OK) goto cleanup;
	}

	/* Extract query. */
	if ((parser.field_set & (1 << UF_QUERY)) && (query != NULL)) {
		res = newStringFromExisting(&tmpQuery, uri + parser.field_data[UF_QUERY].off, parser.field_data[UF_QUERY].len + 1);
		if (res != KSI_OK) goto cleanup;
	}

	/* Extract fragment. */
	if ((parser.field_set & (1 << UF_FRAGMENT)) && (fragment != NULL)) {
		res = newStringFromExisting(&tmpFragment, uri + parser.field_data[UF_FRAGMENT].off, parser.field_data[UF_FRAGMENT].len + 1);
		if (res != KSI_OK) goto cleanup;
	}

	if (host != NULL) {
		*host = tmpHost;
		tmpHost = NULL;
	}

	if (scheme != NULL) {
		*scheme = tmpSchema;
		tmpSchema = NULL;
	}

	if (path != NULL) {
		*path = tmpPath;
		tmpPath = NULL;
	}

	if (query != NULL) {
		*query = tmpQuery;
		tmpQuery = NULL;
	}

	if (fragment != NULL) {
		*fragment = tmpFragment;
		tmpFragment = NULL;
	}

	if (user != NULL) {
		*user = tmpUser;
		tmpUser = NULL;
	}

	if (pass != NULL) {
		*pass = tmpPass;
		tmpPass = NULL;
	}

	if (port != NULL) *port = parser.port;

	res = KSI_OK;

cleanup:

	KSI_free(tmpHost);
	KSI_free(tmpSchema);
	KSI_free(tmpPath);
	KSI_free(tmpUserInfo);
	KSI_free(tmpQuery);
	KSI_free(tmpFragment);
	KSI_free(tmpUser);
	KSI_free(tmpPass);

	return res;
}

static int uriCompose(const char *scheme, const char *user, const char *pass, const char *host, unsigned port, const char *path, const char *query, const char *fragment, char *buf, size_t len) {
	size_t count = 0;
	//scheme:[//[user:password@]host[:port]][/]path[?query][#fragment]

	if (host == NULL || (user != NULL && pass == NULL) || (pass != NULL && user == NULL)) {
		return KSI_INVALID_ARGUMENT;
	}

	if (scheme != NULL) {
		count += KSI_snprintf(buf + count, len - count, "%s://", scheme);
	}

	if (user != NULL && pass != NULL) {
		count += KSI_snprintf(buf + count, len - count, "%s:%s@", user, pass);
	}

	count += KSI_snprintf(buf + count, len - count, "%s", host);

	if (port != 0) {
		count += KSI_snprintf(buf + count, len - count, ":%d", port);
	}

	if (path != NULL) {
		count += KSI_snprintf(buf + count, len - count, "%s%s", (path[0] == '/') ? "" : "/", path);
	}

	if (query != NULL) {
		count += KSI_snprintf(buf + count, len - count, "?%s", query);
	}

	if (fragment != NULL) {
		KSI_snprintf(buf + count, len - count, "#%s", fragment);
	}

	return KSI_OK;
}

void KSI_NetEndpoint_free(KSI_NetEndpoint *endPoint) {
	if (endPoint == NULL) return;

	KSI_free(endPoint->ksi_pass);
	KSI_free(endPoint->ksi_user);

	if (endPoint->implCtx_free != NULL) {
		endPoint->implCtx_free(endPoint->implCtx);
	}

	KSI_free(endPoint);
}

int KSI_AbstractNetEndpoint_new(KSI_CTX *ctx, KSI_NetEndpoint **endPoint) {
	int res;
	KSI_NetEndpoint *tmp = NULL;

	if (ctx == NULL || endPoint == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(KSI_NetEndpoint);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ksi_pass = NULL;
	tmp->ksi_user = NULL;
	tmp->implCtx = NULL;
	tmp->implCtx_free = NULL;

	*endPoint = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_NetEndpoint_free(tmp);

	return res;
}

int KSI_NetEndpoint_setImplContext(KSI_NetEndpoint *endPoint, void *implCtx, void (*implCtx_free)(void *)) {
	int res;

	if (endPoint == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(endPoint->ctx);

	if (endPoint->implCtx != implCtx && endPoint->implCtx != NULL && endPoint->implCtx_free != NULL) {
		endPoint->implCtx_free(endPoint->implCtx);
	}

	endPoint->implCtx = implCtx;
	endPoint->implCtx_free = implCtx_free;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_RequestHandle_new(KSI_CTX *ctx, const unsigned char *request, size_t request_length, KSI_RequestHandle **handle) {
	int res;
	KSI_RequestHandle *tmp = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || handle == NULL || (request == NULL && request_length != 0) || (request != NULL && request_length == 0)) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_RequestHandle);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;
	tmp->implCtx = NULL;
	tmp->implCtx_free = NULL;
	tmp->request = NULL;
	tmp->request_length = 0;
	if (request != NULL && request_length > 0) {
		tmp->request = KSI_calloc(request_length, 1);
		if (tmp->request == NULL) {
			KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}
		memcpy(tmp->request, request, request_length);
		tmp->request_length = request_length;
	}

	tmp->response = NULL;
	tmp->response_length = 0;
	tmp->completed = false;
	tmp->err.code = 0;
	memset(tmp->err.errm, 0, sizeof(tmp->err.errm));
	tmp->err.res = KSI_UNKNOWN_ERROR;
	tmp->status = NULL;

	tmp->client = NULL;

	tmp->reqCtx = NULL;
	tmp->reqCtx_free = NULL;

	*handle = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_RequestHandle_free(tmp);

	return res;
}

int KSI_RequestHandle_getNetContext(const KSI_RequestHandle *handle, void **c) {
	if (handle == NULL || c == NULL) return KSI_INVALID_ARGUMENT;
	*c = handle->implCtx;
	return KSI_OK;
}

/**
 *
 */
void KSI_RequestHandle_free(KSI_RequestHandle *handle) {
	if (handle != NULL && --handle->ref == 0) {
		if (handle->implCtx_free != NULL) {
			handle->implCtx_free(handle->implCtx);
		}
		if (handle->reqCtx_free != NULL) {
			handle->reqCtx_free(handle->reqCtx);
		}
		KSI_free(handle->request);
		KSI_free(handle->response);
		KSI_free(handle);
	}
}

int KSI_NetworkClient_sendSignRequest(KSI_NetworkClient *provider, KSI_AggregationReq *request, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RequestHandle *tmp = NULL;

	if (provider == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	if (request == NULL || handle == NULL) {
		KSI_pushError(provider->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	KSI_ERR_clearErrors(provider->ctx);

	if (provider->sendSignRequest == NULL) {
		KSI_pushError(provider->ctx, res = KSI_UNKNOWN_ERROR, "Signed request sender not initialized.");
		goto cleanup;
	}

	res = provider->sendSignRequest(provider, request, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(provider->ctx, res, NULL);
		goto cleanup;
	}

	*handle = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_RequestHandle_free(tmp);

	return res;
}

int KSI_NetworkClient_sendExtendRequest(KSI_NetworkClient *provider, KSI_ExtendReq *request, KSI_RequestHandle **handle) {
	int res;
	KSI_RequestHandle *tmp = NULL;

	if (provider == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(provider->ctx);

	if (request == NULL || handle == NULL) {
		KSI_pushError(provider->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	if (provider->sendExtendRequest == NULL) {
		KSI_pushError(provider->ctx, res = KSI_UNKNOWN_ERROR, "Extend request sender not initialized.");
		goto cleanup;
	}

	res = provider->sendExtendRequest(provider, request, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(provider->ctx, res, NULL);
		goto cleanup;
	}

	*handle = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_RequestHandle_free(tmp);

	return res;
}

int KSI_NetworkClient_sendPublicationsFileRequest(KSI_NetworkClient *provider, KSI_RequestHandle **handle) {
	int res;
	KSI_RequestHandle *tmp = NULL;

	if (provider == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(provider->ctx);

	if (handle == NULL) {
		KSI_pushError(provider->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	if (provider->sendPublicationRequest == NULL) {
		KSI_pushError(provider->ctx, res = KSI_UNKNOWN_ERROR, "Publications file request sender not initialized.");
		goto cleanup;
	}

	res = provider->sendPublicationRequest(provider, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(provider->ctx, res, NULL);
		goto cleanup;
	}

	*handle = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_RequestHandle_free(tmp);

	return res;
}

void KSI_NetworkClient_free(KSI_NetworkClient *provider) {
	if (provider != NULL) {
		KSI_NetEndpoint_free(provider->aggregator);
		KSI_NetEndpoint_free(provider->extender);
		KSI_NetEndpoint_free(provider->publicationsFile);

		if (provider->implFree != NULL) {
			provider->implFree(provider->impl);
		}

		KSI_free(provider);
	}
}

int KSI_RequestHandle_setResponse(KSI_RequestHandle *handle, const unsigned char *response, size_t response_len) {
	int res;
	unsigned char *resp = NULL;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);


	if (response != NULL && response_len > 0) {
		resp = KSI_calloc(response_len, 1);
		if (resp == NULL) {
			KSI_pushError(handle->ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}
		memcpy(resp, response, response_len);
	}

	handle->response = resp;
	handle->response_length = response_len;

	resp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(resp);

	return res;
}

int KSI_RequestHandle_setImplContext(KSI_RequestHandle *handle, void *netCtx, void (*netCtx_free)(void *)) {
	int res;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	if (handle->implCtx != netCtx && handle->implCtx != NULL && handle->implCtx_free != NULL) {
		handle->implCtx_free(handle->implCtx);
	}
	handle->implCtx = netCtx;
	handle->implCtx_free = netCtx_free;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_RequestHandle_setReadResponseFn(KSI_RequestHandle *handle, int (*fn)(KSI_RequestHandle *)) {
	int res;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	handle->readResponse = fn;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_RequestHandle_getRequest(const KSI_RequestHandle *handle, const unsigned char **request, size_t *request_len) {
	int res;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	*request = handle->request;
	*request_len = handle->request_length;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_RequestHandle_perform(KSI_RequestHandle *handle) {
	int res;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	if (handle->readResponse == NULL) {
		KSI_pushError(handle->ctx, res = KSI_UNKNOWN_ERROR, NULL);
		goto cleanup;
	}


	res = handle->readResponse(handle);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	handle->completed = true;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_RequestHandle_getResponseStatus(const KSI_RequestHandle *handle, const KSI_RequestHandleStatus **err) {
	int res = KSI_UNKNOWN_ERROR;
	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	*err = &handle->err;

	res = KSI_OK;

cleanup:

	return res;
}


int KSI_RequestHandle_getResponse(const KSI_RequestHandle *handle, const unsigned char **response, size_t *response_len) {
	int res = KSI_UNKNOWN_ERROR;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	if (response == NULL || response_len == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	*response = handle->response;
	*response_len = handle->response_length;

	res = KSI_OK;

cleanup:

	return res;
}

static int pdu_verify_hmac(KSI_CTX *ctx, const KSI_DataHash *hmac, const char *key, KSI_HashAlgorithm conf_alg,
		int (*calculateHmac)(const void*, int, const char*, KSI_DataHash**) ,void *PDU){
	int res;
	KSI_DataHash *actualHmac = NULL;
	KSI_HashAlgorithm algo_id;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || hmac == NULL || key == NULL || calculateHmac == NULL || PDU == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_getHashAlg(hmac, &algo_id);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* If configured, check if HMAC algorithm matches. */
	if (conf_alg != KSI_HASHALG_INVALID && algo_id != conf_alg)	{
		KSI_LOG_debug(ctx, "HMAC algorithm mismatch. Expected %s, received %s",
				KSI_getHashAlgorithmName(conf_alg), KSI_getHashAlgorithmName(algo_id));
		KSI_pushError(ctx, res = KSI_HMAC_ALGORITHM_MISMATCH, "HMAC algorithm mismatch.");
		goto cleanup;
	}

	res = calculateHmac(PDU, algo_id, key, &actualHmac);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Check HMAC. */
	if (!KSI_DataHash_equals(hmac, actualHmac)){
		KSI_LOG_debug(ctx, "Verifying HMAC failed.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calculated HMAC", actualHmac);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "HMAC from response", hmac);
		KSI_pushError(ctx, res = KSI_HMAC_MISMATCH, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(actualHmac);

	return res;
}

int KSI_RequestHandle_getExtendResponse(const KSI_RequestHandle *handle, KSI_ExtendResp **resp) {
	int res;
	KSI_ExtendPdu *pdu = NULL;
	KSI_ErrorPdu *error = NULL;
	KSI_DataHash *respHmac = NULL;
	KSI_Header *header = NULL;
	KSI_Config *tmpConf = NULL;
	KSI_ExtendResp *tmp = NULL;
	const unsigned char *raw = NULL;
	size_t len = 0;
	KSI_ExtendReq *req = NULL;
	KSI_Integer *reqAggrTime = NULL;
	KSI_Config *reqConf = NULL;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	if (resp == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_RequestHandle_getResponse(handle, &raw, &len);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logBlob(handle->ctx, KSI_LOG_DEBUG, "Parsing extend response from", raw, len);

	/*Get response PDU*/
	res = KSI_ExtendPdu_parse(handle->ctx, raw, len, &pdu);
	if (res != KSI_OK) {
		int networkStatus = handle->err.code;

		if (networkStatus >= 400 && networkStatus < 600) {
			KSI_ERR_push(handle->ctx, res = KSI_HTTP_ERROR, networkStatus, __FILE__, __LINE__, "HTTP returned error. Unable to parse extend pdu.");
		} else {
			KSI_ERR_push(handle->ctx, res, networkStatus, __FILE__, __LINE__, "Unable to parse extend pdu.");
		}

		goto cleanup;
	}

	res = KSI_ExtendPdu_getError(pdu, &error);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	if (error != NULL) {
		KSI_Utf8String *errorMsg = NULL;
		KSI_Integer *status = NULL;

		res = KSI_ErrorPdu_getErrorMessage(error, &errorMsg);
		if (res != KSI_OK) {
			KSI_pushError(handle->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_ErrorPdu_getStatus(error, &status);
		if (res != KSI_OK) {
			KSI_pushError(handle->ctx, res, NULL);
			goto cleanup;
		}

		KSI_ERR_push(handle->ctx, res = KSI_convertExtenderStatusCode(status), (long)KSI_Integer_getUInt64(status), __FILE__, __LINE__, KSI_Utf8String_cstr(errorMsg));
		goto cleanup;
	}

	res = KSI_ExtendPdu_getHeader(pdu, &header);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_ExtendPdu_getHmac(pdu, &respHmac);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	if (header == NULL){
		KSI_pushError(handle->ctx, res = KSI_INVALID_FORMAT, "A successful extension response must have a Header.");
		goto cleanup;
	}

	if (respHmac == NULL){
		KSI_pushError(handle->ctx, res = KSI_INVALID_FORMAT, "A successful extension response must have a HMAC.");
		goto cleanup;
	}

	res = pdu_verify_hmac(handle->ctx, respHmac, handle->client->extender->ksi_pass,
			(KSI_HashAlgorithm)handle->ctx->options[KSI_OPT_EXT_HMAC_ALGORITHM],
			(int (*)(const void*, int, const char*, KSI_DataHash**))KSI_ExtendPdu_calculateHmac,
			(void*)pdu);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	req = (KSI_ExtendReq*)handle->reqCtx;
	if (req == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_STATE, "Request context is not initialized.");
		goto cleanup;
	}

	/* Get response object. */
	res = KSI_ExtendPdu_getResponse(pdu, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_ExtendPdu_setResponse(pdu, NULL);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_ExtendPdu_getConfResponse(pdu, &tmpConf);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_ExtendPdu_setConfResponse(pdu, NULL);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_ExtendReq_getAggregationTime(req, &reqAggrTime);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_ExtendReq_getConfig(req, &reqConf);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	/* Handle warning logging in case of unexpected response. */
	if (reqAggrTime != NULL && tmp == NULL) {
		KSI_LOG_warn(handle->ctx, "Expected signature extend response. Response PDU is missing extend response.");
	}
	if (reqConf != NULL && tmpConf == NULL) {
		KSI_LOG_warn(handle->ctx, "Expected extender configuration. Response PDU is missing extender configuration.");
	}
	if (reqConf != NULL && tmp != NULL) {
		KSI_LOG_warn(handle->ctx, "Expected extender configuration. Response PDU includes unexpected signature extend response.");
	}

	if (tmpConf != NULL) {
		/* Check if conf has been requested. */
		if (reqConf == NULL) {
			KSI_Config_Callback confCallback = (KSI_Config_Callback)handle->ctx->options[KSI_OPT_EXT_CONF_RECEIVED_CALLBACK];
			/* It is push conf which was not explicitly requested. Invoke the user conf receive callback. */
			if (confCallback != NULL) {
				res = confCallback(handle->ctx, tmpConf);
				if (res != KSI_OK) {
					KSI_pushError(handle->ctx, res, NULL);
					goto cleanup;
				}
			}
		} else {
			if (tmp == NULL) {
				res = KSI_ExtendResp_new(handle->ctx, &tmp);
				if (res != KSI_OK) {
					KSI_pushError(handle->ctx, res, NULL);
					goto cleanup;
				}
			}
			res = KSI_ExtendResp_setConfig(tmp, tmpConf);
			if (res != KSI_OK) {
				KSI_pushError(handle->ctx, res, NULL);
				goto cleanup;
			}
			tmpConf = NULL;
		}
	}

	*resp = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_ExtendResp_free(tmp);
	KSI_Config_free(tmpConf);

	KSI_ExtendPdu_free(pdu);

	return res;
}

int KSI_RequestHandle_getAggregationResponse(const KSI_RequestHandle *handle, KSI_AggregationResp **resp) {
	int res;
	KSI_AggregationPdu *pdu = NULL;
	KSI_ErrorPdu *error = NULL;
	KSI_Header *header = NULL;
	KSI_Config *tmpConf = NULL;
	KSI_DataHash *respHmac = NULL;
	KSI_AggregationResp *tmp = NULL;
	const unsigned char *raw = NULL;
	size_t len;
	KSI_AggregationReq *req = NULL;
	KSI_DataHash *reqHash = NULL;
	KSI_Config *reqConf = NULL;
	bool logWarn = false;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	if (handle->client == NULL || handle->client->aggregator->ksi_pass == NULL || resp == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_RequestHandle_getResponse(handle, &raw, &len);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logBlob(handle->ctx, KSI_LOG_DEBUG, "Parsing aggregation response:", raw, len);

	/* Get PDU object. */
	res = KSI_AggregationPdu_parse(handle->ctx, raw, len, &pdu);
	if(res != KSI_OK){
		int networkStatus = handle->err.code;

		if(networkStatus >= 400 && networkStatus < 600)
			KSI_ERR_push(handle->ctx, res = KSI_HTTP_ERROR, networkStatus, __FILE__, __LINE__, "HTTP returned error. Unable to parse aggregation pdu.");
		else
			KSI_ERR_push(handle->ctx, res, networkStatus, __FILE__, __LINE__, "Unable to parse aggregation pdu.");

		goto cleanup;
	}

	res = KSI_AggregationPdu_getError(pdu, &error);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	if (error != NULL){
		KSI_Utf8String *errorMsg = NULL;
		KSI_Integer *status = NULL;
		KSI_ErrorPdu_getErrorMessage(error, &errorMsg);
		KSI_ErrorPdu_getStatus(error, &status);
		KSI_ERR_push(handle->ctx, res = KSI_convertAggregatorStatusCode(status), (long)KSI_Integer_getUInt64(status), __FILE__, __LINE__, KSI_Utf8String_cstr(errorMsg));
		goto cleanup;
	}

	res = KSI_AggregationPdu_getHeader(pdu, &header);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationPdu_getHmac(pdu, &respHmac);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	if (header == NULL){
		KSI_pushError(handle->ctx, res = KSI_INVALID_FORMAT, "A successful aggregation response must have a Header.");
		goto cleanup;
	}

	/* Check HMAC. */
	if (respHmac == NULL){
		KSI_pushError(handle->ctx, res = KSI_INVALID_FORMAT, "A successful aggregation response must have a HMAC.");
		goto cleanup;
	}

	res = pdu_verify_hmac(handle->ctx, respHmac, handle->client->aggregator->ksi_pass,
			(KSI_HashAlgorithm)handle->ctx->options[KSI_OPT_AGGR_HMAC_ALGORITHM],
			(int (*)(const void*, int, const char*, KSI_DataHash**))KSI_AggregationPdu_calculateHmac,
			(void*)pdu);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	req = (KSI_AggregationReq*)handle->reqCtx;
	if (req == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_STATE, "Request context is not initialized.");
		goto cleanup;
	}

	/*Get response object*/
	res = KSI_AggregationPdu_getResponse(pdu, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationPdu_setResponse(pdu, NULL);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationPdu_getConfResponse(pdu, &tmpConf);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationPdu_setConfResponse(pdu, NULL);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationReq_getRequestHash(req, &reqHash);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationReq_getConfig(req, &reqConf);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	/* Handle warning logging in case of unexpected response. */
	if (reqHash != NULL && tmp == NULL) {
		logWarn = true;
		KSI_LOG_warn(handle->ctx, "Expected aggregation response. Response PDU is missing aggregation response.");
	}
	if (reqConf != NULL && tmpConf == NULL) {
		logWarn = true;
		KSI_LOG_warn(handle->ctx, "Expected aggregator configuration. Response PDU is missing aggregator configuration.");
	}
	if (reqConf != NULL && tmp != NULL) {
		logWarn = true;
		KSI_LOG_warn(handle->ctx, "Expected aggregator configuration. Response PDU includes unexpected aggregation response.");
	}
	if (logWarn) {
		KSI_LOG_logBlob(handle->ctx, KSI_LOG_WARN, "Response:", raw, len);

		res = KSI_RequestHandle_getRequest(handle, &raw, &len);
		if (res != KSI_OK) {
			KSI_pushError(handle->ctx, res, NULL);
			goto cleanup;
		}
		KSI_LOG_logBlob(handle->ctx, KSI_LOG_WARN, "Request :", raw, len);
	}

	if (tmpConf != NULL) {
		KSI_Config_Callback confCallback = (KSI_Config_Callback)(handle->ctx->options[KSI_OPT_AGGR_CONF_RECEIVED_CALLBACK]);
		/* Check if conf has been requested. */
		if (reqConf == NULL) {
			/* It is push conf which was not explicitly requested. Invoke the user conf receive callback. */
			if (confCallback != NULL) {
				res = confCallback(handle->ctx, tmpConf);
				if (res != KSI_OK) {
					KSI_pushError(handle->ctx, res, NULL);
					goto cleanup;
				}
			}
		} else {
			if (tmp == NULL) {
				res = KSI_AggregationResp_new(handle->ctx, &tmp);
				if (res != KSI_OK) {
					KSI_pushError(handle->ctx, res, NULL);
					goto cleanup;
				}
			}
			res = KSI_AggregationResp_setConfig(tmp, tmpConf);
			if (res != KSI_OK) {
				KSI_pushError(handle->ctx, res, NULL);
				goto cleanup;
			}
			tmpConf = NULL;
		}
	}

	*resp = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:
	KSI_AggregationResp_free(tmp);
	KSI_Config_free(tmpConf);
	KSI_AggregationPdu_free(pdu);

	return res;
}

int KSI_NetworkClient_setSendSignRequestFn(KSI_NetworkClient *client, int (*fn)(KSI_NetworkClient *, KSI_AggregationReq *, KSI_RequestHandle **)) {
	int res;

	if (client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	client->sendSignRequest = fn;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_NetworkClient_setSendExtendRequestFn(KSI_NetworkClient *client, int (*fn)(KSI_NetworkClient *, KSI_ExtendReq *, KSI_RequestHandle **)) {
	int res;

	if (client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	client->sendExtendRequest = fn;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_NetworkClient_setSendPublicationRequestFn(KSI_NetworkClient *client, int (*fn)(KSI_NetworkClient *, KSI_RequestHandle **)) {
	int res;

	if (client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	client->sendPublicationRequest = fn;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_AbstractNetworkClient_new(KSI_CTX *ctx, KSI_NetworkClient **client) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_NetworkClient *tmp = NULL;
	KSI_NetEndpoint *aggrEndpoint = NULL;
	KSI_NetEndpoint *extEndpoint = NULL;
	KSI_NetEndpoint *pubEndpoint = NULL;

	if (ctx == NULL || client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Create and initialize abstract network provider. */
	tmp = KSI_new(KSI_NetworkClient);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->implFree = NULL;
	tmp->sendExtendRequest = NULL;
	tmp->sendPublicationRequest = NULL;
	tmp->sendSignRequest = NULL;
	tmp->requestCount = 0;

	/* Configure private helper functions. */
	tmp->setStringParam = setStringParam;
	tmp->uriSplit = uriSplit;
	tmp->uriCompose = uriCompose;

	/* Create Abstract endpoints. */
	res = KSI_AbstractNetEndpoint_new(ctx, &aggrEndpoint);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AbstractNetEndpoint_new(ctx, &extEndpoint);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AbstractNetEndpoint_new(ctx, &pubEndpoint);
	if (res != KSI_OK) goto cleanup;

	/* Set Abstract endpoints. */
	tmp->aggregator = aggrEndpoint;
	tmp->extender = extEndpoint;
	tmp->publicationsFile = pubEndpoint;
	aggrEndpoint = NULL;
	extEndpoint = NULL;
	pubEndpoint = NULL;


	*client = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_NetworkClient_free(tmp);
	KSI_NetEndpoint_free(aggrEndpoint);
	KSI_NetEndpoint_free(extEndpoint);
	KSI_NetEndpoint_free(pubEndpoint);

	return res;

}

int KSI_convertAggregatorStatusCode(const KSI_Integer *statusCode) {
	if (statusCode == NULL) return KSI_OK;
	switch (KSI_Integer_getUInt64(statusCode)) {
		case 0x00: return KSI_OK;
		case 0x0101: return KSI_SERVICE_INVALID_REQUEST;
		case 0x0102: return KSI_SERVICE_AUTHENTICATION_FAILURE;
		case 0x0103: return KSI_SERVICE_INVALID_PAYLOAD;
		case 0x0104: return KSI_SERVICE_AGGR_REQUEST_TOO_LARGE;
		case 0x0105: return KSI_SERVICE_AGGR_REQUEST_OVER_QUOTA;
		case 0x0106: return KSI_SERVICE_AGGR_TOO_MANY_REQUESTS;
		case 0x0107: return KSI_SERVICE_AGGR_INPUT_TOO_LONG;
		case 0x0200: return KSI_SERVICE_INTERNAL_ERROR;
		case 0x0300: return KSI_SERVICE_UPSTREAM_ERROR;
		case 0x0301: return KSI_SERVICE_UPSTREAM_TIMEOUT;
		default: return KSI_SERVICE_UNKNOWN_ERROR;
	}
}

int KSI_convertExtenderStatusCode(const KSI_Integer *statusCode) {
	if (statusCode == NULL) return KSI_OK;
	switch (KSI_Integer_getUInt64(statusCode)) {
		case 0x00: return KSI_OK;
		case 0x0101: return KSI_SERVICE_INVALID_REQUEST;
		case 0x0102: return KSI_SERVICE_AUTHENTICATION_FAILURE;
		case 0x0103: return KSI_SERVICE_INVALID_PAYLOAD;
		case 0x0104: return KSI_SERVICE_EXTENDER_INVALID_TIME_RANGE;
		case 0x0105: return KSI_SERVICE_EXTENDER_REQUEST_TIME_TOO_OLD;
		case 0x0106: return KSI_SERVICE_EXTENDER_REQUEST_TIME_TOO_NEW;
		case 0x0107: return KSI_SERVICE_EXTENDER_REQUEST_TIME_IN_FUTURE;
		case 0x0200: return KSI_SERVICE_INTERNAL_ERROR;
		case 0x0201: return KSI_SERVICE_EXTENDER_DATABASE_MISSING;
		case 0x0202: return KSI_SERVICE_EXTENDER_DATABASE_CORRUPT;
		case 0x0300: return KSI_SERVICE_UPSTREAM_ERROR;
		case 0x0301: return KSI_SERVICE_UPSTREAM_TIMEOUT;
		default: return KSI_SERVICE_UNKNOWN_ERROR;
	}
}

int KSI_UriSplitBasic(const char *uri, char **scheme, char **host, unsigned *port, char **path) {
	return uriSplit(uri, scheme, NULL, NULL, host, port, path, NULL, NULL);
}

#define KSI_NET_OBJ_IMPLEMENT_SETTER(obj, name, type, var, fn) 														\
		int obj##_set##name(obj *client, type val) {								\
			int res = KSI_UNKNOWN_ERROR;																\
			if (client == NULL) {																		\
				res = KSI_INVALID_ARGUMENT;																\
				goto cleanup;																			\
			}																							\
			\
		res = (fn)(&client->var, val);																\
		cleanup:																						\
			return res;																					\
		}

#define KSI_NET_IMPLEMENT_GETTER(baseType, valueType, valueName, alias)			\
	KSI_DEFINE_GETTER(baseType, valueType, alias, alias) {					\
	int res = KSI_UNKNOWN_ERROR;											\
	if (o == NULL || alias == NULL) {									\
		res = KSI_INVALID_ARGUMENT;											\
		goto cleanup;														\
	}																		\
	*alias = o->valueName;												\
	res = KSI_OK;															\
cleanup:																	\
	return res;																\
}

/* KSI_NetEndpoint */
KSI_NET_OBJ_IMPLEMENT_SETTER(KSI_NetEndpoint, User, const char *, ksi_user, setStringParam);
KSI_NET_OBJ_IMPLEMENT_SETTER(KSI_NetEndpoint, Pass, const char *, ksi_pass, setStringParam);

KSI_IMPLEMENT_GETTER(KSI_NetEndpoint, const char *, ksi_user, User);
KSI_IMPLEMENT_GETTER(KSI_NetEndpoint, const char *, ksi_pass, Pass);


/* KSI_NetworkClient */
KSI_NET_OBJ_IMPLEMENT_SETTER(KSI_NetworkClient, ExtenderUser, const char *, extender->ksi_user, setStringParam);
KSI_NET_OBJ_IMPLEMENT_SETTER(KSI_NetworkClient, ExtenderPass, const char *, extender->ksi_pass, setStringParam);
KSI_NET_OBJ_IMPLEMENT_SETTER(KSI_NetworkClient, AggregatorUser, const char *, aggregator->ksi_user, setStringParam);
KSI_NET_OBJ_IMPLEMENT_SETTER(KSI_NetworkClient, AggregatorPass, const char *, aggregator->ksi_pass, setStringParam);

KSI_IMPLEMENT_SETTER(KSI_NetworkClient, KSI_NetEndpoint *, aggregator, AggregatorEndpoint);
KSI_IMPLEMENT_SETTER(KSI_NetworkClient, KSI_NetEndpoint *, extender, ExtenderEndpoint);
KSI_IMPLEMENT_SETTER(KSI_NetworkClient, KSI_NetEndpoint *, publicationsFile, PublicationsFileEndpoint);

KSI_NET_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, extender->ksi_user, ExtenderUser);
KSI_NET_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, extender->ksi_pass, ExtenderPass);
KSI_NET_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, aggregator->ksi_user, AggregatorUser);
KSI_NET_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, aggregator->ksi_pass, AggregatorPass);

KSI_IMPLEMENT_GETTER(KSI_NetworkClient, KSI_NetEndpoint *, aggregator, AggregatorEndpoint);
KSI_IMPLEMENT_GETTER(KSI_NetworkClient, KSI_NetEndpoint *, extender, ExtenderEndpoint);
KSI_IMPLEMENT_GETTER(KSI_NetworkClient, KSI_NetEndpoint *, publicationsFile, PublicationsFileEndpoint);



KSI_IMPLEMENT_REF(KSI_RequestHandle);

int KSI_AsyncHandle_matchAggregationResp(const KSI_AsyncHandle handle, const KSI_AggregationResp *resp) {
	KSI_Integer *id = NULL;
	return (resp != NULL && KSI_AggregationResp_getRequestId(resp, &id) == KSI_OK &&
			id != NULL && KSI_Integer_getUInt64(id) == handle);
}

void KSI_AsyncPayload_free(KSI_AsyncPayload *o) {
	if (o != NULL && --o->ref == 0) {
		if (o->pldCtx_free) o->pldCtx_free(o->pldCtx);
		KSI_free(o->raw);
		KSI_free(o);
	}
}

int KSI_AsyncPayload_new(KSI_CTX *ctx, const unsigned char *payload, const size_t payload_len, KSI_AsyncPayload **o) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncPayload *tmp = NULL;

	if (ctx == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_malloc(sizeof(KSI_AsyncPayload));
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;

	tmp->id = 0;
	tmp->raw = NULL;
	tmp->len = 0;
	tmp->pldCtx = NULL;
	tmp->pldCtx_free = NULL;
	tmp->sendTime = 0;

	tmp->state = KSI_ASYNC_PLD_WAITING_FOR_DISPATCH;

	if (payload_len > 0) {
		tmp->raw = KSI_malloc(payload_len);
		if (tmp->raw == NULL) {
			KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		memcpy(tmp->raw, payload, payload_len);
		tmp->len = payload_len;
	}

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncPayload_free(tmp);
	return res;
}

KSI_IMPLEMENT_REF(KSI_AsyncPayload);
KSI_IMPLEMENT_SETTER(KSI_AsyncPayload, KSI_AsyncHandle, id, PayloadId);

int KSI_AsyncPayload_setPayloadCtx(KSI_AsyncPayload *o, void *pldCtx, void (*pldCtx_free)(void*)) {
	int res = KSI_UNKNOWN_ERROR;

	if (o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (o->pldCtx_free) o->pldCtx_free(o->pldCtx);

	o->pldCtx = pldCtx;
	o->pldCtx_free = pldCtx_free;

	res = KSI_OK;
cleanup:
	return res;
}

static int calculateRequestId(KSI_AsyncClient *c, KSI_uint64_t *id) {
	int res = KSI_UNKNOWN_ERROR;
	size_t last = 0;

	if (c == NULL || c->reqCache == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	last = c->requestCount;

	do {
		if ((++c->requestCount % c->maxParallelRequests) == 0) c->requestCount = 1;
		if (c->requestCount == last) {
			res = KSI_ASYNC_MAX_PARALLEL_COUNT_REACHED;
			goto cleanup;
		}
	} while (c->reqCache[c->requestCount] != NULL);

	*id = c->requestCount;
	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_addAggregationRequest(KSI_AsyncClient *c, KSI_AggregationReq *req, KSI_AsyncHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationReq *reqRef = NULL;
	KSI_AggregationPdu *pdu = NULL;
	unsigned char *raw = NULL;
	size_t len;
	KSI_AsyncPayload *tmp = NULL;
	KSI_AsyncPayload *pldRef = NULL;
	KSI_Integer *reqId = NULL;
	const char *user = NULL;
	const char *pass = NULL;
	KSI_uint64_t id = 0;
	void *impl = NULL;

	if (c == NULL || req == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (c->clientImpl == NULL || c->addRequest == NULL || c->getCredentials == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}
	impl = c->clientImpl;

	res = KSI_AggregationReq_getRequestId(req, &reqId);
	if (res != KSI_OK) goto cleanup;

	/* Clear the request id that was set  */
	if (reqId != NULL) {
		KSI_Integer_free(reqId);
		reqId = NULL;

		res = KSI_AggregationReq_setRequestId(req, reqId);
		if (res != KSI_OK) goto cleanup;
	}

	res = calculateRequestId(c, &id);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(c->ctx, id, &reqId);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AggregationReq_setRequestId(req, reqId);
	if (res != KSI_OK) goto cleanup;
	reqId = NULL;

	res = c->getCredentials(impl, &user, &pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AggregationReq_enclose((reqRef = KSI_AggregationReq_ref(req)), user, pass, &pdu);
	if (res != KSI_OK) {
		KSI_AggregationReq_free(reqRef);
		goto cleanup;
	}

	res = KSI_AggregationPdu_serialize(pdu, &raw, &len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AsyncPayload_new(c->ctx, raw, len, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AsyncPayload_setPayloadId(tmp, id);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AsyncPayload_setPayloadCtx(tmp, (void*)KSI_AggregationReq_ref(req), (void (*)(void*))KSI_AggregationReq_free);
	if (res != KSI_OK) goto cleanup;

	res = c->addRequest(impl, (pldRef = KSI_AsyncPayload_ref(tmp)));
	if (res != KSI_OK) {
		KSI_AsyncPayload_free(pldRef);
		goto cleanup;
	}
	c->reqCache[id] = tmp;
	tmp = NULL;
	c->pending++;

	*handle = id;

	res = KSI_OK;
cleanup:
	KSI_free(raw);
	KSI_Integer_free(reqId);
	KSI_AggregationPdu_free(pdu);
	KSI_AsyncPayload_free(tmp);

	return res;
}

static int asyncClient_handleAggregationResponse(KSI_AsyncClient *c) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationResp *tmp = NULL;
	KSI_ErrorPdu *error = NULL;
	KSI_Header *header = NULL;
	KSI_DataHash *respHmac = NULL;
	const char *user = NULL;
	const char *pass = NULL;
	KSI_OctetString *resp = NULL;
	const unsigned char *raw = NULL;
	size_t len = 0;
	KSI_AggregationPdu *pdu = NULL;
	KSI_Config *tmpConf = NULL;
	void *impl = NULL;

	if (c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(c->ctx);

	if (c->clientImpl == NULL || c->getResponse == NULL || c->getCredentials == NULL) {
		KSI_pushError(c->ctx, res = KSI_INVALID_STATE, "Async client is not properly initialized.");
		goto cleanup;
	}
	impl = c->clientImpl;

	for (;;) {

		res = c->getResponse(impl, &resp);
		if (res == KSI_ASYNC_QUEUE_EMPTY) {
			KSI_LOG_debug(c->ctx, "Async reaponse queue is empty.");
			goto cleanup;
		} else if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
		}

		res = KSI_OctetString_extract(resp, &raw, &len);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		KSI_LOG_logBlob(c->ctx, KSI_LOG_DEBUG, "Parsing aggregation response:", raw, len);

		/* Get PDU object. */
		res = KSI_AggregationPdu_parse(c->ctx, raw, len, &pdu);
		if(res != KSI_OK){
			KSI_pushError(c->ctx, res, "Unable to parse aggregation pdu.");
			goto cleanup;
		}

		res = KSI_AggregationPdu_getError(pdu, &error);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		if (error != NULL) {
			KSI_Utf8String *errorMsg = NULL;
			KSI_Integer *status = NULL;
			KSI_ErrorPdu_getErrorMessage(error, &errorMsg);
			KSI_ErrorPdu_getStatus(error, &status);
			KSI_ERR_push(c->ctx, res = KSI_convertAggregatorStatusCode(status), (long)KSI_Integer_getUInt64(status), __FILE__, __LINE__, KSI_Utf8String_cstr(errorMsg));
			goto cleanup;
		}

		res = KSI_AggregationPdu_getHeader(pdu, &header);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}
		if (header == NULL){
			KSI_pushError(c->ctx, res = KSI_INVALID_FORMAT, "A successful aggregation response must have a Header.");
			goto cleanup;
		}

		res = KSI_AggregationPdu_getHmac(pdu, &respHmac);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}
		if (respHmac == NULL){
			KSI_pushError(c->ctx, res = KSI_INVALID_FORMAT, "A successful aggregation response must have a HMAC.");
			goto cleanup;
		}

		res = c->getCredentials(impl, &user, &pass);
		if (res != KSI_OK) goto cleanup;

		res = pdu_verify_hmac(c->ctx, respHmac, pass,
				(KSI_HashAlgorithm)c->ctx->options[KSI_OPT_AGGR_HMAC_ALGORITHM],
				(int (*)(const void*, int, const char*, KSI_DataHash**))KSI_AggregationPdu_calculateHmac,
				(void*)pdu);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		/*Get response object*/
		res = KSI_AggregationPdu_getResponse(pdu, &tmp);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_AggregationPdu_setResponse(pdu, NULL);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_AggregationPdu_getConfResponse(pdu, &tmpConf);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		/* The push config is handled only via callback. */
		if (tmpConf != NULL) {
			KSI_Config_Callback confCallback = (KSI_Config_Callback)(c->ctx->options[KSI_OPT_AGGR_CONF_RECEIVED_CALLBACK]);
			/* It is push conf which was not explicitly requested. Invoke the user conf receive callback. */
			if (confCallback != NULL) {
				res = confCallback(c->ctx, tmpConf);
				if (res != KSI_OK) {
					KSI_pushError(c->ctx, res, NULL);
					goto cleanup;
				}
			}
		}

		if (tmp != NULL) {
			KSI_Integer *reqId = NULL;
			KSI_AsyncPayload *pld = NULL;

			res = KSI_AggregationResp_getRequestId(tmp, &reqId);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			if (c->maxParallelRequests < KSI_Integer_getUInt64(reqId) || c->reqCache[KSI_Integer_getUInt64(reqId)] == NULL) {
				KSI_LOG_warn(c->ctx, "Unexpected response received.");
			}

			pld = c->reqCache[KSI_Integer_getUInt64(reqId)];

			if (pld->state == KSI_ASYNC_PLD_WAITING_FOR_RESPONSE) {
				res = KSI_AsyncPayload_setPayloadCtx(pld, (void*)tmp, (void (*)(void*))KSI_AggregationResp_free);
				if (res != KSI_OK) {
					KSI_pushError(c->ctx, res, NULL);
					goto cleanup;
				}
				pld->state = KSI_ASYNC_PLD_RESPONSE_RECEIVED;
				tmp = NULL;
				c->pending--;
				c->received++;
			}
		}
		KSI_OctetString_free(resp);
		resp = NULL;
		KSI_AggregationPdu_free(pdu);
		pdu = NULL;
	}

cleanup:
	KSI_AggregationResp_free(tmp);
	KSI_Config_free(tmpConf);
	KSI_OctetString_free(resp);
	KSI_AggregationPdu_free(pdu);

	return res;
}

static int asyncClient_getResponse(KSI_AsyncClient *c, KSI_AsyncHandle handle, void **response) {
	int res = KSI_UNKNOWN_ERROR;

	if (c == NULL || response == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (c->reqCache[handle] != NULL && c->reqCache[handle]->state == KSI_ASYNC_PLD_RESPONSE_RECEIVED) {
		*response = c->reqCache[handle]->pldCtx;
		c->reqCache[handle]->pldCtx = NULL;
		c->reqCache[handle]->pldCtx_free = NULL;
		KSI_AsyncPayload_free(c->reqCache[handle]);
		c->reqCache[handle] = NULL;
		c->received--;
	} else if (c->reqCache[handle] != NULL && c->reqCache[handle]->state == KSI_ASYNC_PLD_WAITING_FOR_RESPONSE &&
			difftime(time(NULL), c->reqCache[handle]->sendTime) > c->rTimeout) {
		res = KSI_NETWORK_RECIEVE_TIMEOUT;
		goto cleanup;
	} else {
		*response = NULL;
	}
	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_getAggregationResponse(KSI_AsyncClient *c, KSI_AsyncHandle handle, KSI_AggregationResp **response) {
	int res = KSI_UNKNOWN_ERROR;

	if (c == NULL || response == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = asyncClient_getResponse(c, handle, (void**)response);
	if (res != KSI_OK) {
		KSI_pushError(c->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int asyncClient_findNextResponse(KSI_AsyncClient *c, KSI_AsyncHandle *handle) {
	int res;
	size_t last;

	if (c == NULL || c->reqCache == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	if ((c->pending + c->received) == 0) {
		*handle = KSI_ASYNC_HANDLE_INVALID;
		res = KSI_OK;
		goto cleanup;
	}

	last = c->tail;
	for (;;) {
		if (c->reqCache[c->tail] != NULL) {
			if (c->reqCache[c->tail]->state == KSI_ASYNC_PLD_WAITING_FOR_RESPONSE &&
					difftime(time(NULL), c->reqCache[c->tail]->sendTime) > c->rTimeout) {
				*handle = c->reqCache[c->tail]->id;
				res = KSI_NETWORK_RECIEVE_TIMEOUT;
				goto cleanup;
			}
			if (c->reqCache[c->tail]->state == KSI_ASYNC_PLD_RESPONSE_RECEIVED) {
				*handle = c->reqCache[c->tail]->id;
				res = KSI_OK;
				goto cleanup;
			}
		}
		if ((++c->tail % c->maxParallelRequests) == 0) c->tail = 1;
		if (c->tail == last) break;
	}
	*handle = KSI_ASYNC_HANDLE_INVALID;
	res = KSI_OK;
cleanup:
	return res;
}

int asyncClient_runAggr(KSI_AsyncClient *c, KSI_AsyncHandle *handle, size_t *waiting) {
	int res = KSI_UNKNOWN_ERROR;
	int sta = KSI_UNKNOWN_ERROR;

	if (c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(c->ctx);

	if (c->clientImpl == NULL || c->dispatch == NULL) {
		KSI_pushError(c->ctx, res = KSI_INVALID_STATE, "Async client is not properly initialized.");
		goto cleanup;
	}

	sta = c->dispatch(c->clientImpl);
	switch (sta) {
		case KSI_OK:
		case KSI_ASYNC_NOT_READY:
		case KSI_ASYNC_OUTPUT_BUFFER_FULL:
		case KSI_ASYNC_CONNECTION_CLOSED:
			/* Handle responses. */
			do {
				res = asyncClient_handleAggregationResponse(c);
			} while (res != KSI_ASYNC_QUEUE_EMPTY);
			if (res != KSI_OK && res != KSI_ASYNC_QUEUE_EMPTY) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}
			if (handle != NULL) {
				res = asyncClient_findNextResponse(c, handle);
				if (res != KSI_OK)  {
					KSI_pushError(c->ctx, res, NULL);
					goto cleanup;
				}
			}
			break;
		default:
			/* An unrecoverable error. */
			KSI_pushError(c->ctx, res = sta, NULL);
			goto cleanup;
	}
	if (waiting != NULL) *waiting = c->received;

	res = (sta != KSI_OK) ? sta :
			(c->pending + c->received) ? KSI_ASYNC_NOT_FINISHED : KSI_ASYNC_COMPLETED;
cleanup:
	return res;
}

static int asyncClient_getState(KSI_AsyncClient *c, KSI_AsyncHandle h, int *state) {
	int res = KSI_UNKNOWN_ERROR;

	if (c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (h >= c->maxParallelRequests || c->reqCache == NULL)  {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	*state = (c->reqCache[h] == NULL) ? KSI_ASYNC_PLD_UNDEFINED : c->reqCache[h]->state;

	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_recover(KSI_AsyncClient *c, KSI_AsyncHandle h, int policy) {
	int res = KSI_UNKNOWN_ERROR;
	int state;

	if (c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(c->ctx);

	if (c->clientImpl == NULL || c->dispatch == NULL) {
		KSI_pushError(c->ctx, res = KSI_INVALID_STATE, "Async client is not properly initialized.");
		goto cleanup;
	}

	res = asyncClient_getState(c, h, &state);
	if (res != KSI_OK)  {
		KSI_pushError(c->ctx, res, NULL);
		goto cleanup;
	}

	if (state != KSI_ASYNC_PLD_WAITING_FOR_RESPONSE) {
		KSI_pushError(c->ctx, res = KSI_INVALID_STATE, "Payload can not be recovered.");
		goto cleanup;
	}

	switch (policy) {
		case KSI_ASYNC_REC_REMOVE:
			KSI_AsyncPayload_free(c->reqCache[h]);
			c->reqCache[h] = NULL;
			c->pending--;
			break;

		case KSI_ASYNC_REC_RESEND:
			c->reqCache[h]->state = KSI_ASYNC_PLD_WAITING_FOR_DISPATCH;
			res = c->addRequest(c->clientImpl, c->reqCache[h]);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}
			break;

		default:
			KSI_pushError(c->ctx, res = KSI_INVALID_ARGUMENT, "Invalid recovery policy.");
			goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_setConnectTimeout(KSI_AsyncClient *c, size_t timeout) {
	if (c == NULL || c->clientImpl == NULL || c->setConnectTimeout == NULL) return KSI_INVALID_ARGUMENT;
	return c->setConnectTimeout(c->clientImpl, timeout);
}

static int asyncClient_setReceiveTimeout(KSI_AsyncClient *c, size_t timeout) {
	if (c == NULL) return KSI_INVALID_ARGUMENT;
	c->rTimeout = timeout;
	return KSI_OK;
}

void KSI_AsyncClient_free(KSI_AsyncClient *c) {
	if (c != NULL) {
		size_t i;

		if (c->clientImpl_free) c->clientImpl_free(c->clientImpl);

		for (i = 0; i < c->maxParallelRequests; i++) KSI_AsyncPayload_free(c->reqCache[i]);
		KSI_free(c->reqCache);

		KSI_free(c);
	}
}

static int KSI_AsyncService_addRequest(KSI_AsyncService *s, void *req, KSI_AsyncHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;

	if (s == NULL || req == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(s->ctx);

	if (s->impl == NULL || s->addRequest == NULL) {
		KSI_pushError(s->ctx, res = KSI_INVALID_STATE, "Async service client is not properly initialized.");
		goto cleanup;
	}

	res = s->addRequest(s->impl, req, handle);
	if (res != KSI_OK) {
		KSI_pushError(s->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncService_addAggregationReq(KSI_AsyncService *s, KSI_AggregationReq *req, KSI_AsyncHandle *handle) {
	return KSI_AsyncService_addRequest(s, (void *)req, handle);
}

static int KSI_AsyncService_getResponse(KSI_AsyncService *s, KSI_AsyncHandle handle, void **resp) {
	int res = KSI_UNKNOWN_ERROR;

	if (s == NULL || resp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(s->ctx);

	if (s->impl == NULL || s->getResponse == NULL) {
		KSI_pushError(s->ctx, res = KSI_INVALID_STATE, "Async service client is not properly initialized.");
		goto cleanup;
	}

	res = s->getResponse(s->impl, handle, resp);
	if (res != KSI_OK) {
		KSI_pushError(s->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncService_getAggregationResp(KSI_AsyncService *s, KSI_AsyncHandle handle, KSI_AggregationResp **resp) {
	return KSI_AsyncService_getResponse(s, handle, (void **)resp);
}

int KSI_AsyncService_run(KSI_AsyncService *s, KSI_AsyncHandle *handle, size_t *waiting) {
	int res = KSI_UNKNOWN_ERROR;

	if (s == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(s->ctx);

	if (s->impl == NULL || s->run == NULL) {
		KSI_pushError(s->ctx, res = KSI_INVALID_STATE, "Async service client is not properly initialized.");
		goto cleanup;
	}

	res = s->run(s->impl, handle, waiting);
	if (res != KSI_OK) {
		KSI_pushError(s->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncService_getRequestState(KSI_AsyncService *s, KSI_AsyncHandle h, int *state) {
	int res = KSI_UNKNOWN_ERROR;

	if (s == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(s->ctx);

	if (s->impl == NULL || s->getState == NULL) {
		KSI_pushError(s->ctx, res = KSI_INVALID_STATE, "Async service client is not properly initialized.");
		goto cleanup;
	}

	res = s->getState(s->impl, h, state);
	if (res != KSI_OK) {
		KSI_pushError(s->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncService_recover(KSI_AsyncService *service, KSI_AsyncHandle handle, int policy) {
	int res = KSI_UNKNOWN_ERROR;

	if (service == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	if (service->impl == NULL || service->recover == NULL) {
		KSI_pushError(service->ctx, res = KSI_INVALID_STATE, "Async service client is not properly initialized.");
		goto cleanup;
	}

	res = service->recover(service->impl, handle, policy);
	if (res != KSI_OK) {
		KSI_pushError(service->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

void KSI_AsyncService_free(KSI_AsyncService *s) {
	if (s != NULL) {
		if (s->impl_free) s->impl_free(s->impl);
		KSI_free(s);
	}
}

int KSI_AsyncService_new(KSI_CTX *ctx, KSI_AsyncService **s) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncService *tmp = NULL;

	if (ctx == NULL || s == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	tmp = KSI_malloc(sizeof(KSI_AsyncService));
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->impl = NULL;
	tmp->impl_free = NULL;

	tmp->addRequest = NULL;
	tmp->getResponse = NULL;
	tmp->run = NULL;

	tmp->recover = (int (*)(void *, KSI_AsyncHandle, int))asyncClient_recover;

	tmp->getState = (int (*)(void *, KSI_AsyncHandle, int *))asyncClient_getState;
	tmp->uriSplit = uriSplit;

	*s = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncService_free(tmp);
	return res;
}

int KSI_AsyncService_aggrInit(KSI_AsyncService *service) {
	if (service == NULL) return KSI_INVALID_ARGUMENT;

	service->addRequest = (int (*)(void *, void *, KSI_AsyncHandle *))asyncClient_addAggregationRequest;
	service->getResponse = (int (*)(void *, KSI_AsyncHandle, void **))asyncClient_getAggregationResponse;
	service->run = (int (*)(void *, KSI_AsyncHandle *, size_t *))asyncClient_runAggr;

	return KSI_OK;
}

int KSI_AsyncService_setMaxParallelRequests(KSI_AsyncService *service, size_t count){
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncPayload **tmp = NULL;
	KSI_AsyncClient *client = NULL;
	size_t i;

	if (service == NULL || service->impl == NULL || (client = service->impl)->maxParallelRequests > count) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_calloc(count, sizeof(KSI_AsyncPayload *));
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	for (i = 0; i < client->maxParallelRequests; i++) {
		tmp[i] = client->reqCache[i];
	}
	KSI_free(client->reqCache);
	client->reqCache = tmp;
	tmp = NULL;
	client->maxParallelRequests = count;

	res = KSI_OK;
cleanup:
	return res;
}

