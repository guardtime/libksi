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

#include "http_parser.h"
#include "internal.h"
#include "net_impl.h"
#include "tlv.h"
#include "ctx_impl.h"

KSI_IMPLEMENT_GET_CTX(KSI_NetworkClient);
KSI_IMPLEMENT_GET_CTX(KSI_RequestHandle);

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

/**
 *
 */
int KSI_RequestHandle_new(KSI_CTX *ctx, const unsigned char *request, unsigned request_length, KSI_RequestHandle **handle) {
	KSI_ERR err;
	KSI_RequestHandle *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_RequestHandle);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->implCtx = NULL;
	tmp->implCtx_free = NULL;
	tmp->request = NULL;
	tmp->request_length = 0;
	if (request != NULL && request_length > 0) {
		tmp->request = KSI_calloc(request_length, 1);
		if (tmp->request == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}
		memcpy(tmp->request, request, request_length);
		tmp->request_length = request_length;
	}

	tmp->response = NULL;
	tmp->response_length = 0;

	tmp->client = NULL;

	*handle = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RequestHandle_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_RequestHandle_getNetContext(KSI_RequestHandle *handle, void **c) {
	KSI_ERR err;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, c != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	*c = handle->implCtx;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
void KSI_RequestHandle_free(KSI_RequestHandle *handle) {
	if (handle != NULL) {
		if (handle->implCtx_free != NULL) {
			handle->implCtx_free(handle->implCtx);
		}
		KSI_free(handle->request);
		KSI_free(handle->response);
		KSI_free(handle);
	}
}

int KSI_NetworkClient_sendSignRequest(KSI_NetworkClient *provider, KSI_AggregationReq *request, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;

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

	res = provider->sendSignRequest(provider, request, handle);
	if (res != KSI_OK) {
		KSI_pushError(provider->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_NetworkClient_sendExtendRequest(KSI_NetworkClient *provider, KSI_ExtendReq *request, KSI_RequestHandle **handle) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(provider->ctx, &err);

	if (provider->sendExtendRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Extend request sender not initialized.");
		goto cleanup;
	}

	res = provider->sendExtendRequest(provider, request, handle);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetworkClient_sendPublicationsFileRequest(KSI_NetworkClient *provider, KSI_RequestHandle **handle) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(provider->ctx, &err);

	if (provider->sendPublicationRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Publications file request sender not initialized.");
		goto cleanup;
	}

	res = provider->sendPublicationRequest(provider, handle);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

void KSI_NetworkClient_free(KSI_NetworkClient *provider) {
	if (provider != NULL) {
		KSI_free(provider->aggrPass);
		KSI_free(provider->aggrUser);
		KSI_free(provider->extPass);
		KSI_free(provider->extUser);
		if (provider->implFree != NULL) {
			provider->implFree(provider);
		} else {
			KSI_free(provider);
		}
	}
}

int KSI_RequestHandle_setResponse(KSI_RequestHandle *handle, const unsigned char *response, unsigned response_len) {
	KSI_ERR err;
	unsigned char *resp = NULL;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	if (response != NULL && response_len > 0) {
		resp = KSI_calloc(response_len, 1);
		if (resp == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}
		memcpy(resp, response, response_len);
	}

	handle->response = resp;
	handle->response_length = response_len;

	resp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(resp);

	return KSI_RETURN(&err);
}

int KSI_RequestHandle_setImplContext(KSI_RequestHandle *handle, void *netCtx, void (*netCtx_free)(void *)) {
	KSI_ERR err;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	if (handle->implCtx != netCtx && handle->implCtx != NULL && handle->implCtx_free != NULL) {
		handle->implCtx_free(handle->implCtx);
	}
	handle->implCtx = netCtx;
	handle->implCtx_free = netCtx_free;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_RequestHandle_setReadResponseFn(KSI_RequestHandle *handle, int (*fn)(KSI_RequestHandle *)) {
	KSI_ERR err;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	handle->readResponse = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_RequestHandle_getRequest(KSI_RequestHandle *handle, const unsigned char **request, unsigned *request_len) {
	KSI_ERR err;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	*request = handle->request;
	*request_len = handle->request_length;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int receiveResponse(KSI_RequestHandle *handle) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	if (handle->readResponse == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, NULL);
		goto cleanup;
	}

	res = handle->readResponse(handle);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_RequestHandle_getResponse(KSI_RequestHandle *handle, unsigned char **response, unsigned *response_len) {
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

	if (handle->response == NULL) {
		KSI_LOG_debug(handle->ctx, "Waiting for response.");
		res = receiveResponse(handle);
		if (res != KSI_OK) {
			KSI_pushError(handle->ctx, res, NULL);
			goto cleanup;
		}
	}

	*response = handle->response;
	*response_len = handle->response_length;

	res = KSI_OK;

cleanup:

	return res;
}

int pdu_verify_hmac(KSI_CTX *ctx, KSI_DataHash *hmac,const char *key, int (*calculateHmac)(void*, int, const char*, KSI_DataHash**) ,void *PDU){
	KSI_ERR err;
	int res;
	KSI_DataHash *actualHmac = NULL;
	int hashAlg;
	
	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, hmac != NULL) goto cleanup;
	KSI_PRE(&err, key != NULL) goto cleanup;
	KSI_PRE(&err, calculateHmac != NULL) goto cleanup;
	KSI_PRE(&err, PDU != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);
	
	/* Check HMAC. */
	res = KSI_DataHash_getHashAlg(hmac, &hashAlg);
	KSI_CATCH(&err, res);

	res = calculateHmac(PDU, hashAlg, key, &actualHmac);
	KSI_CATCH(&err, res);

	if (!KSI_DataHash_equals(hmac, actualHmac)){
		KSI_LOG_debug(ctx, "Verifying HMAC failed.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calculated HMAC", actualHmac);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "HMAC from response", hmac);
		KSI_FAIL(&err, KSI_HMAC_MISMATCH, NULL);
		goto cleanup;
	}

	KSI_SUCCESS(&err);
	
cleanup:
	
	KSI_DataHash_free(actualHmac);

	return KSI_RETURN(&err);
}

int KSI_RequestHandle_getExtendResponse(KSI_RequestHandle *handle, KSI_ExtendResp **resp) {
	KSI_ERR err;
	int res;
	KSI_ExtendPdu *pdu = NULL;
	KSI_ErrorPdu *error = NULL;
	KSI_DataHash *respHmac = NULL;
	KSI_Header *header = NULL;
	KSI_ExtendResp *tmp = NULL;
	unsigned char *raw = NULL;
	unsigned len = 0;
	
	
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, resp != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	res = KSI_RequestHandle_getResponse(handle, &raw, &len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(handle->ctx, KSI_LOG_DEBUG, "Parsing extend response from", raw, len);

	/*Get response PDU*/
	res = KSI_ExtendPdu_parse(handle->ctx, raw, len, &pdu);
	if(res != KSI_OK){
		int networkStatus = handle->client->getStausCode ? handle->client->getStausCode(handle->client) : 0; 
		
		if(networkStatus >= 400 && networkStatus < 600)
			KSI_FAIL_EXT(&err, KSI_HTTP_ERROR, networkStatus, "HTTP returned error. Unable to parse extend pdu.");
		else
			KSI_FAIL_EXT(&err, res, networkStatus, "Unable to parse extend pdu.");
		
		goto cleanup;
	}

	res = KSI_ExtendPdu_getError(pdu, &error);
	KSI_CATCH(&err, res) goto cleanup;
	
	if (error != NULL) {
		KSI_Utf8String *errorMsg = NULL;
		KSI_Integer *status = NULL;
		
		res = KSI_ErrorPdu_getErrorMessage(error, &errorMsg);
		KSI_CATCH(&err, res) goto cleanup;
		
		res = KSI_ErrorPdu_getStatus(error, &status);
		KSI_CATCH(&err, res) goto cleanup;
		
		KSI_FAIL_EXT(&err, KSI_convertExtenderStatusCode(status), (long)KSI_Integer_getUInt64(status), KSI_Utf8String_cstr(errorMsg));
		goto cleanup;
	}
		
	res = KSI_ExtendPdu_getHeader(pdu, &header);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendPdu_getHmac(pdu, &respHmac);
	KSI_CATCH(&err, res) goto cleanup;

	if (header == NULL){
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "A successful extension response must have a Header.");
		goto cleanup;
	}

	if (respHmac == NULL){
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "A successful extension response must have a HMAC.");
		goto cleanup;	
	}
	
	/*Get response object*/
	res = KSI_ExtendPdu_getResponse(pdu, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = pdu_verify_hmac(handle->ctx, respHmac, handle->client->extPass, 
			(int (*)(void*, int, const char*, KSI_DataHash**))KSI_ExtendPdu_calculateHmac,
			(void*)pdu);
	
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendPdu_setResponse(pdu, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	*resp = tmp;
	tmp = NULL;
	
	KSI_SUCCESS(&err);

cleanup:

	KSI_ExtendPdu_free(pdu);
	
	return KSI_RETURN(&err);
}

int KSI_RequestHandle_getAggregationResponse(KSI_RequestHandle *handle, KSI_AggregationResp **resp) {
	KSI_ERR err;
	int res;
	KSI_AggregationPdu *pdu = NULL;
	KSI_ErrorPdu *error = NULL;
	KSI_Header *header = NULL;
	KSI_DataHash *respHmac = NULL;
	KSI_DataHash *actualHmac = NULL;
	KSI_AggregationResp *tmp = NULL;
	unsigned char *raw = NULL;
	unsigned len;
	
	
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, handle->client != NULL) goto cleanup;
	KSI_PRE(&err, handle->client->aggrPass != NULL) goto cleanup;
	KSI_PRE(&err, resp != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	res = KSI_RequestHandle_getResponse(handle, &raw, &len);
	KSI_CATCH(&err, res) goto cleanup;
	
	KSI_LOG_logBlob(handle->ctx, KSI_LOG_DEBUG, "Parsing aggregation response from", raw, len);
	
	/*Get PDU object*/
	res = KSI_AggregationPdu_parse(handle->ctx, raw, len, &pdu);
	if(res != KSI_OK){
		int networkStatus = handle->client->getStausCode ? handle->client->getStausCode(handle->client) : 0; 
		
		if(networkStatus >= 400 && networkStatus < 600)
			KSI_FAIL_EXT(&err, KSI_HTTP_ERROR, networkStatus, "HTTP returned error. Unable to parse aggregation pdu.");
		else
			KSI_FAIL_EXT(&err, res, networkStatus, "Unable to parse aggregation pdu.");
		
		goto cleanup;
	}

	res = KSI_AggregationPdu_getError(pdu, &error);
	KSI_CATCH(&err, res) goto cleanup;
	
	if(error){
		KSI_Utf8String *errorMsg = NULL;
		KSI_Integer *status = NULL;
		KSI_ErrorPdu_getErrorMessage(error, &errorMsg);
		KSI_ErrorPdu_getStatus(error, &status);
		KSI_FAIL_EXT(&err, KSI_convertAggregatorStatusCode(status), (long)KSI_Integer_getUInt64(status), KSI_Utf8String_cstr(errorMsg));
		goto cleanup;
	}
	
	res = KSI_AggregationPdu_getHeader(pdu, &header);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_AggregationPdu_getHmac(pdu, &respHmac);
	KSI_CATCH(&err, res) goto cleanup;

	if (header == NULL){
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "A successful aggregation response must have a Header.");
		goto cleanup;
	}

	if (respHmac == NULL){
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "A successful aggregation response must have a HMAC.");
		goto cleanup;	
	}
	
	/* Check HMAC. */
	res = KSI_AggregationPdu_getHmac(pdu, &respHmac);
	KSI_CATCH(&err, res) goto cleanup;
	
	/*Get response object*/
	res = KSI_AggregationPdu_getResponse(pdu, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = pdu_verify_hmac(handle->ctx, respHmac, handle->client->aggrPass, 
			(int (*)(void*, int, const char*, KSI_DataHash**))KSI_AggregationPdu_calculateHmac,
			(void*)pdu);

	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_AggregationPdu_setResponse(pdu, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	*resp = tmp;
	tmp = NULL;
	
	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(actualHmac);
	KSI_AggregationPdu_free(pdu);
	return KSI_RETURN(&err);
}

int KSI_NetworkClient_setSendSignRequestFn(KSI_NetworkClient *client, int (*fn)(KSI_NetworkClient *, KSI_AggregationReq *, KSI_RequestHandle **)) {
	KSI_ERR err;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	client->sendSignRequest = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetworkClient_setSendExtendRequestFn(KSI_NetworkClient *client, int (*fn)(KSI_NetworkClient *, KSI_ExtendReq *, KSI_RequestHandle **)) {
	KSI_ERR err;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	client->sendExtendRequest = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetworkClient_setSendPublicationRequestFn(KSI_NetworkClient *client, int (*fn)(KSI_NetworkClient *, KSI_RequestHandle **)) {
	KSI_ERR err;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	client->sendPublicationRequest = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetworkClient_init(KSI_CTX *ctx, KSI_NetworkClient *client) {
	int res = KSI_UNKNOWN_ERROR;

	if (ctx == NULL || client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	client->ctx = ctx;
	client->aggrPass = NULL;
	client->aggrUser = NULL;
	client->extPass = NULL;
	client->extUser = NULL;
	client->implFree = NULL;
	client->sendExtendRequest = NULL;
	client->sendPublicationRequest = NULL;
	client->sendSignRequest = NULL;
	client->getStausCode = NULL;
	
	res = KSI_OK;

cleanup:

	return res;

}

int KSI_convertAggregatorStatusCode(KSI_Integer *statusCode) {
	if (statusCode == NULL) return KSI_OK;
	switch (KSI_Integer_getUInt64(statusCode)) {
		case 0x00: return KSI_OK;
		case 0x0101: return KSI_SERVICE_INVALID_REQUEST;
		case 0x0102: return KSI_SERVICE_AUTHENTICATION_FAILURE;
		case 0x0103: return KSI_SERVICE_INVALID_PAYLOAD;
		case 0x0104: return KSI_SERVICE_AGGR_REQUEST_TOO_LARGE;
		case 0x0105: return KSI_SERVICE_AGGR_REQUEST_OVER_QUOTA;
		case 0x0200: return KSI_SERVICE_INTERNAL_ERROR;
		case 0x0300: return KSI_SERVICE_UPSTREAM_ERROR;
		case 0x0301: return KSI_SERVICE_UPSTREAM_TIMEOUT;
		default: return KSI_SERVICE_UNKNOWN_ERROR;
	}
}

int KSI_convertExtenderStatusCode(KSI_Integer *statusCode) {
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
	int res = KSI_UNKNOWN_ERROR;
	struct http_parser_url parser;
	char *tmpHost = NULL;
	char *tmpSchema = NULL;
	char *tmpPath = NULL;

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

	if ((parser.field_set & (1 << UF_HOST)) && (host != NULL)) {
		/* Extract host. */
		int len = parser.field_data[UF_HOST].len + 1;
		tmpHost = KSI_malloc(len);
		if (tmpHost == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}
		KSI_snprintf(tmpHost, len, "%s", uri + parser.field_data[UF_HOST].off);
		tmpHost[len - 1] = '\0';
	}

	if ((parser.field_set & (1 << UF_SCHEMA)) && (scheme != NULL)) {
		/* Extract shcema. */
		int len = parser.field_data[UF_SCHEMA].len + 1;
		tmpSchema = KSI_malloc(len);
		if (tmpSchema == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}
		KSI_snprintf(tmpSchema, len, "%s", uri + parser.field_data[UF_SCHEMA].off);
		tmpSchema[len - 1] = '\0';
	}

	if ((parser.field_set & (1 << UF_PATH)) && (path != NULL)) {
		/* Extract path. */
		int len = parser.field_data[UF_PATH].len + 1;
		tmpPath = KSI_malloc(len);
		if (tmpPath == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}
		KSI_snprintf(tmpPath, len, "%s", uri + parser.field_data[UF_PATH].off);
		tmpPath[len - 1] = '\0';
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
	if (port != NULL) *port = parser.port;

	res = KSI_OK;

cleanup:

	KSI_free(tmpHost);
	KSI_free(tmpSchema);
	KSI_free(tmpPath);

	return res;
}

#define KSI_NET_IMPLEMENT_SETTER(name, type, var, fn) 														\
		int KSI_NetworkClient_set##name(KSI_NetworkClient *client, type val) {								\
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

KSI_NET_IMPLEMENT_SETTER(ExtenderUser, const char *, extUser, setStringParam);
KSI_NET_IMPLEMENT_SETTER(ExtenderPass, const char *, extPass, setStringParam);
KSI_NET_IMPLEMENT_SETTER(AggregatorUser, const char *, aggrUser, setStringParam);
KSI_NET_IMPLEMENT_SETTER(AggregatorPass, const char *, aggrPass, setStringParam);

KSI_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, extUser, ExtenderUser);
KSI_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, extPass, ExtenderPass);
KSI_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, aggrUser, AggregatorUser);
KSI_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, aggrPass, AggregatorPass);
