#include "ksi_internal.h"

#include "ksi_tlv_easy.h"

/***************
 *
 * SIGN REQUEST
 *
 ***************/

static int createSignRequestTlv(KSI_CTX *ctx, const unsigned char *imprint, int imprint_len, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tmp = NULL;

	KSI_TLV_BEGIN(ctx, KSI_TLV_TAG_PDU_AGGREGATION, 0, 0)
		KSI_TLV_NESTED_BEGIN(KSI_TLV_TAG_AGGR_REQUEST, 0, 0)
			KSI_TLV_NESTED_RAW(KSI_TLV_TAG_AGGR_REQUEST_HASH, 0, 0, imprint, imprint_len)
		KSI_TLV_NESTED_END
	KSI_TLV_END(res, tmp);

	if (res != KSI_OK) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

cleanup:

	KSI_TLV_free(tmp);

	return res;
}

static int createSignRequest(KSI_CTX *ctx, KSI_DataHash *hsh, unsigned char **outReq, int *outReq_len) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tlv = NULL;

	const unsigned char *imprint = NULL;
	int imprint_len = 0;

	unsigned char *req = NULL;
	int req_len = 0;

	/* Extract imprint. */
	res = KSI_DataHash_getImprint(hsh,  &imprint, &imprint_len);
	if (res != KSI_OK) goto cleanup;

	/* Create request TLV. */
	res = createSignRequestTlv(ctx, imprint, imprint_len, &tlv);
	if (res != KSI_OK) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Request TLV", tlv);

	/* Serialize the request TLV. */
	res = KSI_TLV_serialize(tlv, &req, &req_len);
	if (res != KSI_OK) goto cleanup;

	*outReq = req;
	*outReq_len = req_len;

	req = NULL;

cleanup:

	KSI_free(req);
	KSI_nofree(imprint);
	KSI_TLV_free(tlv);

	return res;
}

/*****************
 *
 * EXTEND REQUEST
 *
 *****************/

static int createExtendRequestTlv(KSI_CTX *ctx, KSI_uint64_t start, KSI_uint64_t end, KSI_TLV **tlv) {
	int res;
	KSI_TLV *tmp = NULL;

	KSI_TLV_BEGIN(ctx, 0x0300, 0, 0)
		KSI_TLV_NESTED_BEGIN(0x301, 0, 0)
			KSI_TLV_NESTED_UINT(0x02, 0, 0, start)
			KSI_TLV_NESTED_UINT(0x03, 0, 0, end)
		KSI_TLV_NESTED_END
	KSI_TLV_END(res, tmp);

	if (res != KSI_OK) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

cleanup:

	return res;
}

static int createExtendRequest(KSI_CTX *ctx, KSI_uint64_t start, KSI_uint64_t end, unsigned char **outReq, int *outReq_len) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tlv = NULL;

	const unsigned char *imprint = NULL;
	int imprint_len = 0;

	unsigned char *req = NULL;
	int req_len = 0;

	/* Create request TLV. */
	res = createExtendRequestTlv(ctx, start, end, &tlv);
	if (res != KSI_OK) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Extend request TLV", tlv);

	/* Serialize the request TLV. */
	res = KSI_TLV_serialize(tlv, &req, &req_len);
	if (res != KSI_OK) goto cleanup;

	*outReq = req;
	*outReq_len = req_len;

	req = NULL;

cleanup:

	KSI_free(req);
	KSI_nofree(imprint);
	KSI_TLV_free(tlv);

	return res;
}

int KSI_sign(KSI_DataHash *hsh, KSI_Signature **signature) {
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

	res = KSI_NET_sendSignRequest(ctx->netProvider, req, req_len, &handle);
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
