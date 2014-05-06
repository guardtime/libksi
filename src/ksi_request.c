#include "ksi_internal.h"

#include "ksi_tlv_easy.h"

KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendPdu);


static int createPduTlv(KSI_CTX *ctx, int tag, KSI_TLV **pdu) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tag >= 0 && tag <= 0x1fff) goto cleanup;
	KSI_PRE(&err, pdu != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, tag, 0, 0, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*pdu = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

/***************
 * SIGN REQUEST
 ***************/
static int createSignRequest(KSI_CTX *ctx, const KSI_DataHash *hsh, unsigned char **raw, int *raw_len) {
	KSI_ERR err;
	int res;
	KSI_AggregationReq *req = NULL;
	KSI_AggregationPdu *pdu = NULL;

	KSI_DataHash *tmpHash = NULL;
	KSI_TLV *pduTlv = NULL;

	unsigned char *tmp = NULL;
	int tmp_len = 0;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, hsh != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);
	/* Create request object */
	res = KSI_AggregationReq_new(ctx, &req);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_AggregationPdu_new(ctx, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHash_clone(hsh, &tmpHash);
	KSI_CATCH(&err, res) goto cleanup;

	/* Add the hash to the request */
	res = KSI_AggregationReq_setRequestHash(req, tmpHash);
	KSI_CATCH(&err, res) goto cleanup;
	tmpHash = NULL;

	res = KSI_AggregationPdu_setRequest(pdu, req);
	KSI_CATCH(&err, res) goto cleanup;
	req = NULL;

	res = createPduTlv(ctx,  0x200, &pduTlv);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_construct(ctx, pduTlv, pdu, KSI_AggregationPdu_template);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Request PDU", pduTlv);

	/* Serialize the request TLV. */
	res = KSI_TLV_serialize(pduTlv, &tmp, &tmp_len);
	KSI_CATCH(&err, res) goto cleanup;

	*raw = tmp;
	*raw_len = tmp_len;

	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(pduTlv);

	KSI_DataHash_free(tmpHash);
	KSI_AggregationPdu_free(pdu);
	KSI_AggregationReq_free(req);

	KSI_free(tmp);
	KSI_nofree(imprint);

	return KSI_RETURN(&err);
}

/*****************
 * EXTEND REQUEST
 *****************/
static int createExtendRequest(KSI_CTX *ctx, const KSI_Integer *start, const KSI_Integer *end, unsigned char **raw, int *raw_len) {
	KSI_ERR err;
	int res;
	KSI_TLV *pduTLV = NULL;
	KSI_ExtendPdu *pdu = NULL;
	KSI_ExtendReq *req = NULL;

	unsigned char *tmp = NULL;
	int tmp_len = 0;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	/* Create PDU */
	res = createPduTlv(ctx, 0x300, &pduTLV);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create extend request object. */
	res = KSI_ExtendReq_new(ctx, &req);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendReq_setAggregationTime(req, KSI_Integer_clone(start));
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendReq_setPublicationTime(req, KSI_Integer_clone(end));
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendPdu_new(ctx, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendPdu_setRequest(pdu, req);
	KSI_CATCH(&err, res) goto cleanup;
	req = NULL;

	res = KSI_TlvTemplate_construct(ctx, pduTLV, pdu, KSI_TLV_TEMPLATE(KSI_ExtendPdu));
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Extend request PDU", pduTLV);

	/* Serialize the request TLV. */
	res = KSI_TLV_serialize(pduTLV, &tmp, &tmp_len);
	if (res != KSI_OK) goto cleanup;

	*raw = tmp;
	*raw_len = tmp_len;

	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_ExtendReq_free(req);
	KSI_ExtendPdu_free(pdu);
	KSI_free(tmp);
	KSI_nofree(imprint);
	KSI_TLV_free(pduTLV);

	return KSI_RETURN(&err);
}

int KSI_Signature_sign(const KSI_DataHash *hsh, KSI_Signature **signature) {
	KSI_ERR err;
	KSI_CTX *ctx;
	int res;
	KSI_NetHandle *handle = NULL;
	KSI_Signature *sign = NULL;

	unsigned char *req = NULL;
	int req_len = 0;

	unsigned char *resp = NULL;
	int resp_len = 0;

	KSI_PRE(&err, hsh != NULL) goto cleanup;
	KSI_BEGIN((ctx = KSI_DataHash_getCtx(hsh)), &err);

	res = createSignRequest(ctx, hsh, &req, &req_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Request", req, req_len);

	res = KSI_sendSignRequest(ctx, req, req_len, &handle);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NET_getResponse(handle, &resp, &resp_len, 0);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Response", resp, resp_len);

	res = KSI_parseAggregationResponse(ctx, resp, resp_len, &sign);
	KSI_CATCH(&err, res) goto cleanup;

	*signature = sign;
	sign = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Signature_free(sign);
	KSI_NetHandle_free(handle);
	KSI_free(req);

	return KSI_RETURN(&err);
}

int KSI_Signature_extend(KSI_Signature *signature, KSI_Integer *extentTo, KSI_Signature **extended) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	KSI_Signature *tmp = NULL;
	KSI_Integer *startTime;
	KSI_ExtendResp *response = NULL;
	KSI_CalendarHashChain *calHashChain = NULL;
	KSI_Integer *respStatus = NULL;

	unsigned char *rawReq = NULL;
	int rawReq_len = 0;

	unsigned char *rawResp = NULL;
	int rawResp_len = 0;

	KSI_TLV *respTlv = NULL;

	KSI_ExtendPdu *pdu = NULL;

	KSI_NetHandle *handle = NULL;

	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_PRE(&err, extended != NULL) goto cleanup;

	ctx = KSI_Signature_getCtx(signature);
	KSI_BEGIN(ctx, &err);

	/* Make a copy of the original signature */
	res = KSI_Signature_clone(signature, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	/* Request the calendar hash chain from this moment on. */
	res = KSI_Signature_getSigningTime(tmp, &startTime);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create request. */
	res = createExtendRequest(ctx, startTime, extentTo, &rawReq, &rawReq_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Extend request", rawReq, rawReq_len);

	/* Send the actual request. */
	res = KSI_sendExtendRequest(ctx, rawReq, rawReq_len, &handle);
	KSI_CATCH(&err, res) goto cleanup;

	/* Get the binary response */
	res = KSI_NET_getResponse(handle, &rawResp, &rawResp_len, 0);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Extend response", rawResp, rawResp_len);

	res = KSI_TLV_parseBlob(ctx, rawResp, rawResp_len, &respTlv);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create response PDU object. */
	res = KSI_ExtendPdu_new(ctx, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	/* Evaluate response PDU object. */
	res = KSI_TlvTemplate_extract(ctx, pdu, respTlv, KSI_ExtendPdu_template, NULL);
	KSI_CATCH(&err, res) goto cleanup;


	/* Extract the response */
	res = KSI_ExtendPdu_getResponse(pdu, &response);
	KSI_CATCH(&err, res) goto cleanup;

	/* Verify the response is ok. */
	res = KSI_ExtendResp_getStatus(response, &respStatus);
	KSI_CATCH(&err, res) goto cleanup;

	/* Fail if status is presend and does not equal to success (0) */
	if (respStatus != NULL && !KSI_Integer_equalsUInt(respStatus, 0)) {
		KSI_Utf8String *error = NULL;
		res = KSI_ExtendResp_getErrorMsg(response, &error);

		KSI_FAIL(&err, KSI_EXTENDER_ERROR, (char *)error);
		KSI_nofree(error);
		goto cleanup;
	}

	/* Extract the calendar hash chain */
	res = KSI_ExtendResp_getCalendarHashChain(response, &calHashChain);
	KSI_CATCH(&err, res) goto cleanup;

	/* Remove the chain from the structure, as it will be freed when this function finishes. */
	res = KSI_ExtendResp_setCalendarHashChain(response, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	/* Add the hash chain to the signature. */
	res = KSI_Signature_replaceCalendarChain(tmp, calHashChain);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Parsed part of the response", respTlv);

	*extended = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_ExtendPdu_free(pdu);
	KSI_NetHandle_free(handle);
	KSI_TLV_free(respTlv);
	KSI_free(rawReq);
	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);
}
