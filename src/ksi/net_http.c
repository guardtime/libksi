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

static int postProcessRequest(KSI_HttpClient *http, void *req, void* pdu, const char *user, int (*getHeader)(const void *, KSI_Header **), int (*setHeader)(void *, KSI_Header *), int (*getId)(void *, KSI_Integer **), int (*setId)(void *, KSI_Integer *)) {
	KSI_ERR err;
	int res;
	KSI_uint64_t reqId = 0;
	KSI_Header *headerp = NULL;
	KSI_Header *header = NULL;
	KSI_Integer *requestId = NULL;
	KSI_OctetString *client_id = NULL;
	
	KSI_PRE(&err, http != NULL) goto cleanup;
	KSI_PRE(&err, req != NULL) goto cleanup;
	KSI_PRE(&err, pdu != NULL) goto cleanup;
	KSI_PRE(&err, user != NULL) goto cleanup;
	KSI_BEGIN(http->parent.ctx, &err);
	
	reqId = ++http->requestId;
	
	res = getHeader(pdu, &headerp);
	KSI_CATCH(&err, res) goto cleanup;

	/*Add header*/
	if (headerp == NULL) {
		KSI_uint64_t user_len = strlen(user);
		if(user_len>0xFFFF){
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "User id too long.");
			goto cleanup;
		}
		
		res = KSI_Header_new(http->parent.ctx, &header);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_OctetString_new(http->parent.ctx, user, (unsigned)user_len, &client_id);
		KSI_CATCH(&err, res) goto cleanup;
		
		res = KSI_Header_setLoginId(header, client_id);
		KSI_CATCH(&err, res) goto cleanup;
		client_id = NULL;

		res = setHeader(pdu, header);
		KSI_CATCH(&err, res) goto cleanup;

		headerp = header;
		header = NULL;
	}
	
	/* Every request must have a header, and at this point, this should be quaranteed. */
	if (http->parent.ctx->requestHeaderCB != NULL) {
		res = http->parent.ctx->requestHeaderCB(headerp);
		KSI_CATCH(&err, res) goto cleanup;
	}

	res = getId(req, &requestId);
	KSI_CATCH(&err, res) goto cleanup;
	if (requestId == NULL) {
		res = KSI_Integer_new(http->parent.ctx, reqId, &requestId);
		KSI_CATCH(&err, res) goto cleanup;

		res = setId(req, requestId);
		KSI_CATCH(&err, res) goto cleanup;
		requestId = NULL;
	}
	
	KSI_SUCCESS(&err);

cleanup:

	KSI_Integer_free(requestId);
	KSI_Header_free(header);
	KSI_OctetString_free(client_id);
	
	return KSI_RETURN(&err);
}


static int prepareAggregationRequest(KSI_NetworkClient *client, KSI_AggregationReq *req, KSI_RequestHandle **handle) {
	KSI_ERR err;
	int res;
	KSI_HttpClient *http = (KSI_HttpClient *)client;
	KSI_RequestHandle *tmp = NULL;
	KSI_AggregationPdu *pdu = NULL;
	KSI_DataHash *hmac = NULL;
	unsigned char *raw = NULL;
	unsigned raw_len = 0;
	int hmacHashAlgo = KSI_getHashAlgorithmByName("default");

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_PRE(&err, req != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	if (http == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "KSI_HttpClient context not initialized.");
		goto cleanup;
	}
	res = KSI_AggregationPdu_new(client->ctx, &pdu);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = postProcessRequest(http, req, pdu, client->agrUser, (int (*)(const void *, KSI_Header **))KSI_AggregationPdu_getHeader, (int (*)(void *, KSI_Header *))KSI_AggregationPdu_setHeader, (int (*)(void*, KSI_Integer**))KSI_AggregationReq_getRequestId, (int (*)(void*, KSI_Integer*))KSI_AggregationReq_setRequestId);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_AggregationPdu_setRequest(pdu, req);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_AggregationPdu_getHmac(pdu, &hmac);
	KSI_CATCH(&err, res) goto cleanup;

	if (hmac != NULL) {
		res = KSI_AggregationPdu_setHmac(pdu, NULL);
		KSI_CATCH(&err, res) goto cleanup;

		KSI_DataHash_free(hmac);
	}

	res = KSI_AggregationPdu_calculateHmac(pdu, hmacHashAlgo, client->agrPass, &hmac);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_AggregationPdu_setHmac(pdu, hmac);
	KSI_CATCH(&err, res) goto cleanup;
	hmac = NULL;
	
	res = KSI_AggregationPdu_serialize(pdu, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(client->ctx, KSI_LOG_DEBUG, "Aggregation request", raw, raw_len);

	/* Create a new request handle */
	res = KSI_RequestHandle_new(client->ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	/* Evaluate the handle object. */
	if (http->sendRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}
	res = http->sendRequest(client, tmp, http->urlSigner);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	if(pdu){
		/* Detach request from the PDU, as it may not be freed in this function. */
		KSI_AggregationPdu_setRequest(pdu, NULL);
		KSI_AggregationPdu_free(pdu);
	}

	KSI_RequestHandle_free(tmp);
	KSI_DataHash_free(hmac);
	KSI_free(raw);

	return KSI_RETURN(&err);
}

static int prepareExtendRequest(KSI_NetworkClient *client, KSI_ExtendReq *req, KSI_RequestHandle **handle) {
	KSI_ERR err;
	int res;
	KSI_HttpClient *http = (KSI_HttpClient *)client;
	KSI_RequestHandle *tmp = NULL;
	KSI_ExtendPdu *pdu = NULL;
	KSI_DataHash *hmac = NULL;
	unsigned char *raw = NULL;
	unsigned raw_len = 0;
	int hmacHashAlgo = KSI_getHashAlgorithmByName("default");

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_PRE(&err, req != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	if (http == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "KSI_HttpClient context not initialized.");
		goto cleanup;
	}
	res = KSI_ExtendPdu_new(client->ctx, &pdu);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = postProcessRequest(http, req, pdu, client->extUser, (int (*)(const void *, KSI_Header **))KSI_ExtendPdu_getHeader, (int (*)(void *, KSI_Header *))KSI_ExtendPdu_setHeader, (int (*)(void*, KSI_Integer**))KSI_ExtendReq_getRequestId, (int (*)(void*, KSI_Integer*))KSI_ExtendReq_setRequestId);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_ExtendPdu_setRequest(pdu, req);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendPdu_getHmac(pdu, &hmac);
	KSI_CATCH(&err, res) goto cleanup;

	if (hmac != NULL) {
		res = KSI_ExtendPdu_setHmac(pdu, NULL);
		KSI_CATCH(&err, res) goto cleanup;

		KSI_DataHash_free(hmac);
	}

	res = KSI_ExtendPdu_calculateHmac(pdu, hmacHashAlgo, client->extPass, &hmac);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_ExtendPdu_setHmac(pdu, hmac);
	KSI_CATCH(&err, res) goto cleanup;
	hmac = NULL;
	
	res = KSI_ExtendPdu_serialize(pdu, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(client->ctx, KSI_LOG_DEBUG, "Extending request", raw, raw_len);

	/* Create a new request handle */
	res = KSI_RequestHandle_new(client->ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	if (http->sendRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}

	res = http->sendRequest(client, tmp, http->urlExtender);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	if(pdu){
		/* Detach request from the PDU, as it may not be freed in this function. */
		KSI_ExtendPdu_setRequest(pdu, NULL);
		KSI_ExtendPdu_free(pdu);
	}

	KSI_RequestHandle_free(tmp);
	KSI_DataHash_free(hmac);
	KSI_free(raw);

	return KSI_RETURN(&err);
}

static int preparePublicationsFileRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle) {
	KSI_ERR err;
	int res = KSI_UNKNOWN_ERROR;
	KSI_HttpClient *http = (KSI_HttpClient *) client;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	if (http->sendRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}

	res = http->sendRequest(client, handle, http->urlPublication);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

void KSI_HttpClient_free(KSI_HttpClient *http) {
	if (http != NULL) {
		KSI_free(http->urlSigner);
		KSI_free(http->urlExtender);
		KSI_free(http->urlPublication);
		KSI_free(http->agentName);

		if (http->implCtx_free != NULL) http->implCtx_free(http->implCtx);
		KSI_free(http);
	}
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

	tmp->parent = KSI_NETWORK_CLIENT_INIT(ctx);

	tmp->agentName = NULL;
	tmp->sendRequest = NULL;
	tmp->urlExtender = NULL;
	tmp->urlPublication = NULL;
	tmp->urlSigner = NULL;
	tmp->requestId = 0;

	tmp->parent.sendExtendRequest = prepareExtendRequest;
	tmp->parent.sendSignRequest = prepareAggregationRequest;
	tmp->parent.sendPublicationRequest = preparePublicationsFileRequest;
	tmp->parent.implFree = (void (*)(void *))KSI_HttpClient_free;

	setIntParam(&tmp->connectionTimeoutSeconds, 10);
	setIntParam(&tmp->readTimeoutSeconds, 10);
	setStringParam(&tmp->urlSigner, KSI_DEFAULT_URI_AGGREGATOR);
	setStringParam(&tmp->urlExtender, KSI_DEFAULT_URI_EXTENDER);
	setStringParam(&tmp->urlPublication, KSI_DEFAULT_URI_PUBLICATIONS_FILE);
	setStringParam(&tmp->agentName, "KSI HTTP Client");
	setStringParam(&tmp->parent.agrUser, "anon");
	setStringParam(&tmp->parent.agrPass, "anon");
	setStringParam(&tmp->parent.extUser, "anon");
	setStringParam(&tmp->parent.extPass, "anon");

	res = KSI_HttpClient_init(tmp);
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

KSI_NET_IMPLEMENT_SETTER(SignerUrl, const char *, urlSigner, setStringParam);
KSI_NET_IMPLEMENT_SETTER(ExtenderUrl, const char *, urlExtender, setStringParam);
KSI_NET_IMPLEMENT_SETTER(PublicationUrl, const char *, urlPublication, setStringParam);
KSI_NET_IMPLEMENT_SETTER(ConnectTimeoutSeconds, int, connectionTimeoutSeconds, setIntParam);
KSI_NET_IMPLEMENT_SETTER(ReadTimeoutSeconds, int, readTimeoutSeconds, setIntParam);

