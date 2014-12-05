#include <string.h>

#include "internal.h"
#include "net_impl.h"
#include "tlv.h"

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
	KSI_ERR err;
	int res;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_PRE(&err, request != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(provider->ctx, &err);

	if (provider->sendSignRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Signed request sender not initialized.");
		goto cleanup;
	}

	res = provider->sendSignRequest(provider, request, handle);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
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

int KSI_NetworkClient_sendPublicationsFileRequest(KSI_NetworkClient *provider, KSI_RequestHandle *handle) {
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
		KSI_free(provider->agrPass);
		KSI_free(provider->agrUser);
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
	KSI_ERR err;
	int res;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, response != NULL) goto cleanup;
	KSI_PRE(&err, response_len != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	if (handle->response == NULL) {
		KSI_LOG_debug(handle->ctx, "Waiting for response.");
		res = receiveResponse(handle);
		KSI_CATCH(&err, res) goto cleanup;
	}

	*response = handle->response;
	*response_len = handle->response_length;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_RequestHandle_getExtendResponse(KSI_RequestHandle *handle, KSI_ExtendResp **resp) {
	KSI_ERR err;
	int res;
	KSI_ExtendPdu *pdu = NULL;
	KSI_DataHash *respHmac = NULL;
	KSI_DataHash *actualHmac = NULL;
	KSI_TLV *payloadTLV = NULL;
	KSI_ExtendResp *tmp = NULL;
	int hashAlg;
	unsigned char *raw = NULL;
	unsigned len;
	
	
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, resp != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	res = KSI_RequestHandle_getResponse(handle, &raw, &len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(handle->ctx, KSI_LOG_DEBUG, "Parsing extend response from", raw, len);

	/*Get response PDU*/
	res = KSI_ExtendPdu_parse(handle->ctx, raw, len, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	/*Control HMAC*/
	res = KSI_ExtendPdu_getHmac(pdu, &respHmac);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_DataHash_getHashAlg(respHmac, &hashAlg);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_ExtendPdu_calculateHmac(pdu, hashAlg, handle->client->extPass, &actualHmac);
	KSI_CATCH(&err, res) goto cleanup;
	
	if (!KSI_DataHash_equals(respHmac, actualHmac)){
		KSI_LOG_debug(handle->ctx, "Verifying HMAC failed.");
		KSI_LOG_logDataHash(handle->ctx, KSI_LOG_DEBUG, "Calculated HMAC", actualHmac);
		KSI_LOG_logDataHash(handle->ctx, KSI_LOG_DEBUG, "HMAC from response", respHmac);
		KSI_FAIL(&err, KSI_HMAC_MISMATCH, NULL);
		goto cleanup;
	}	
	
	/*Get response object and its TLV*/
	res = KSI_ExtendPdu_getResponse(pdu, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendPdu_setResponse(pdu, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendPdu_getPayloadTlv(pdu, &payloadTLV);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_ExtendPdu_setPayloadTlv(pdu, NULL);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_ExtendResp_setBaseTlv(tmp, payloadTLV);
	KSI_CATCH(&err, res) goto cleanup;
	payloadTLV = NULL;
	
	res = KSI_ExtendPdu_setResponse(pdu, NULL);
	KSI_CATCH(&err, res) goto cleanup;
	
	*resp = tmp;
	tmp = NULL;
	
	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(actualHmac);
	KSI_ExtendResp_free(tmp);
	KSI_ExtendPdu_free(pdu);
	KSI_TLV_free(payloadTLV);
	
	return KSI_RETURN(&err);
}

int KSI_RequestHandle_getAggregationResponse(KSI_RequestHandle *handle, KSI_AggregationResp **resp) {
	KSI_ERR err;
	int res;
	KSI_AggregationPdu *pdu = NULL;
	KSI_TLV *payloadTLV = NULL;
	KSI_DataHash *respHmac = NULL;
	KSI_DataHash *actualHmac = NULL;
	KSI_AggregationResp *tmp = NULL;
	int hashAlg;
	unsigned char *raw = NULL;
	unsigned len;
	
	
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, handle->client != NULL) goto cleanup;
	KSI_PRE(&err, handle->client->agrPass != NULL) goto cleanup;
	KSI_PRE(&err, resp != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	res = KSI_RequestHandle_getResponse(handle, &raw, &len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(handle->ctx, KSI_LOG_DEBUG, "Parsing aggregation response from", raw, len);
	
	/*Get PDU object*/
	res = KSI_AggregationPdu_parse(handle->ctx, raw, len, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	/*Control HMAC*/
	res = KSI_AggregationPdu_getHmac(pdu, &respHmac);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_DataHash_getHashAlg(respHmac, &hashAlg);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_AggregationPdu_calculateHmac(pdu, hashAlg, handle->client->agrPass, &actualHmac);
	KSI_CATCH(&err, res) goto cleanup;
	
	if (!KSI_DataHash_equals(respHmac, actualHmac)){
		KSI_LOG_debug(handle->ctx, "Verifying HMAC failed.");
		KSI_LOG_logDataHash(handle->ctx, KSI_LOG_DEBUG, "Calculated HMAC", actualHmac);
		KSI_LOG_logDataHash(handle->ctx, KSI_LOG_DEBUG, "HMAC from response", respHmac);
		KSI_FAIL(&err, KSI_HMAC_MISMATCH, NULL);
		goto cleanup;
	}	
	
	/*Get response object and its TLV*/
	res = KSI_AggregationPdu_getResponse(pdu, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_AggregationPdu_getPayloadTlv(pdu, &payloadTLV);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_AggregationPdu_setPayloadTlv(pdu, NULL);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_AggregationResp_setBaseTlv(tmp, payloadTLV);
	KSI_CATCH(&err, res) goto cleanup;
	payloadTLV = NULL;
	
	res = KSI_AggregationPdu_setResponse(pdu, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	*resp = tmp;
	tmp = NULL;
	
	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(actualHmac);
	KSI_AggregationResp_free(tmp);
	KSI_AggregationPdu_free(pdu);
	KSI_TLV_free(payloadTLV);
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

int KSI_NetworkClient_setSendPublicationRequestFn(KSI_NetworkClient *client, int (*fn)(KSI_NetworkClient *, KSI_RequestHandle *)) {
	KSI_ERR err;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	client->sendPublicationRequest = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
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
KSI_NET_IMPLEMENT_SETTER(AggregatorUser, const char *, agrUser, setStringParam);
KSI_NET_IMPLEMENT_SETTER(AggregatorPass, const char *, agrPass, setStringParam);

KSI_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, extUser, ExtenderUser);
KSI_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, extPass, ExtenderPass);
KSI_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, agrUser, AggregatorUser);
KSI_IMPLEMENT_GETTER(KSI_NetworkClient, const char *, agrPass, AggregatorPass);
