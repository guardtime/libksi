#include "ksi_internal.h"
#include "ksi_hash.h"

#include "ksi_tlv_easy.h"

static int createRequestTlv(KSI_CTX *ctx, unsigned char *imprint, int imprint_len, KSI_TLV **outTlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tlv = NULL;

	KSI_TLV_BEGIN(ctx, KSI_TLV_TAG_PDU_AGGREGATION, 0, 0)
		KSI_TLV_NESTED_BEGIN(KSI_TLV_TAG_AGGR_REQUEST, 0, 0)
			KSI_TLV_NESTED_RAW(KSI_TLV_TAG_AGGR_REQUEST_HASH, 0, 0, imprint, imprint_len)
		KSI_TLV_NESTED_END
	KSI_TLV_END(res, tlv);

	if (res != KSI_OK) goto cleanup;

	*outTlv = tlv;
	tlv = NULL;

cleanup:

	KSI_TLV_free(tlv);

	return res;
}

static int createRequest (KSI_DataHash *hsh, unsigned char **outReq, int *outReq_len) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tlv = NULL;

	unsigned char *imprint = NULL;
	int imprint_len = 0;

	unsigned char *req = NULL;
	int req_len = 0;

	/* Extract imprint. */
	res = KSI_DataHash_getImprint(hsh,  &imprint, &imprint_len);
	if (res != KSI_OK) goto cleanup;

	/* Create request TLV. */
	res = createRequestTlv(hsh->ctx, imprint, imprint_len, &tlv);
	if (res != KSI_OK) goto cleanup;

	KSI_LOG_logTlv(hsh->ctx, KSI_LOG_DEBUG, "Request TLV", tlv);

	/* Serialize the request TLV. */
	res = KSI_TLV_serialize(tlv, &req, &req_len);
	if (res != KSI_OK) goto cleanup;

	*outReq = req;
	*outReq_len = req_len;

	req = NULL;

cleanup:

	KSI_free(req);
	KSI_free(imprint);
	KSI_TLV_free(tlv);

	return res;
}

int KSI_sign(KSI_DataHash *hsh, KSI_Signature **signature) {
	KSI_ERR err;
	int res;
	KSI_NetHandle *handle = NULL;
	KSI_Signature *sign = NULL;

	unsigned char *req = NULL;
	int req_len = 0;

	unsigned char *resp = NULL;
	int resp_len = 0;


	KSI_PRE(&err, hsh != NULL) goto cleanup;

	KSI_BEGIN(hsh->ctx, &err);

	res = createRequest(hsh, &req, &req_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(hsh->ctx, KSI_LOG_DEBUG, "Request", req, req_len);

	res = KSI_NET_sendSignRequest(hsh->ctx->netProvider, req, req_len, &handle);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NET_getResponse(handle, &resp, &resp_len, 0);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(hsh->ctx, KSI_LOG_DEBUG, "Response", resp, resp_len);

	res = KSI_parseSignature(hsh->ctx, resp, resp_len, &sign);
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
