/*
 * Copyright 2013-2017 Guardtime, Inc.
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
#include "tlv.h"
#include "net_async.h"
#include "impl/ctx_impl.h"
#include "impl/net_impl.h"

KSI_IMPLEMENT_GET_CTX(KSI_NetworkClient);
KSI_IMPLEMENT_GET_CTX(KSI_RequestHandle);

static int newStringFromExisting(char **string, const char *val, int val_len) {
	char *tmp = NULL;
	int res = KSI_UNKNOWN_ERROR;
	size_t new_len = (val_len < 0) ? (strlen(val) + 1) : ((size_t)val_len);

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
	/* scheme:[//[user:password@]host[:port]][/]path[?query][#fragment] */

	if ((user != NULL && pass == NULL) || (pass != NULL && user == NULL)) {
		return KSI_INVALID_ARGUMENT;
	}

	if (scheme != NULL) {
		count += KSI_snprintf(buf + count, len - count, "%s://", scheme);
	}

	if (user != NULL && pass != NULL) {
		count += KSI_snprintf(buf + count, len - count, "%s:%s@", user, pass);
	}

	if (host != NULL) {
		count += KSI_snprintf(buf + count, len - count, "%s", host);
	}

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

	/* Get response PDU. */
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

	res = KSI_ExtendPdu_verifyHmac(pdu, handle->client->extender->ksi_pass);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	/* Check if the the request context is initialized. This is needed for verifing and logging response inconsistencies. */
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
	KSI_Config *tmpConf = NULL;
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

	KSI_LOG_logBlob(handle->ctx, KSI_LOG_DEBUG, "Parsing aggregation response", raw, len);

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

	res = KSI_AggregationPdu_verify(pdu, handle->client->aggregator->ksi_pass);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	/* Check if the the request context is initialized. This is needed for verifing and logging response inconsistencies. */
	req = (KSI_AggregationReq*)handle->reqCtx;
	if (req == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_STATE, "Request context is not initialized.");
		goto cleanup;
	}

	/* Get response object. */
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
		KSI_LOG_logBlob(handle->ctx, KSI_LOG_WARN, "Response", raw, len);

		res = KSI_RequestHandle_getRequest(handle, &raw, &len);
		if (res != KSI_OK) {
			KSI_pushError(handle->ctx, res, NULL);
			goto cleanup;
		}
		KSI_LOG_logBlob(handle->ctx, KSI_LOG_WARN, "Request ", raw, len);
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

/* KSI_NetEndpoint. */
KSI_NET_OBJ_IMPLEMENT_SETTER(KSI_NetEndpoint, User, const char *, ksi_user, setStringParam);
KSI_NET_OBJ_IMPLEMENT_SETTER(KSI_NetEndpoint, Pass, const char *, ksi_pass, setStringParam);

KSI_IMPLEMENT_GETTER(KSI_NetEndpoint, const char *, ksi_user, User);
KSI_IMPLEMENT_GETTER(KSI_NetEndpoint, const char *, ksi_pass, Pass);


/* KSI_NetworkClient. */
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


int KSI_AbstractAsyncService_new(KSI_CTX *ctx, KSI_AsyncService **service) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncService *tmp = NULL;

	if (ctx == NULL || service == NULL) {
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
	tmp->responseHandler = NULL;
	tmp->run = NULL;
	tmp->getPendingCount = NULL;
	tmp->getReceivedCount = NULL;
	tmp->setOption = NULL;

	tmp->uriSplit = uriSplit;
	tmp->uriCompose = uriCompose;

	*service = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncService_free(tmp);
	return res;
}
