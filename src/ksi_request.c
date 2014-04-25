#include "ksi_internal.h"

#include "ksi_tlv_easy.h"

typedef struct KSI_TlvTemplate_st KSI_TlvTemplate;

struct KSI_TlvTemplate_st {
	int type;
	int tag;
	int isNonCritical;
	int isForward;
	int (*getValue)(const void *, const void **);

	KSI_TlvTemplate *subTemplate;
};

#define KSI_TLV_TEMPLATE_INTEGER 				1
#define KSI_TLV_TEMPLATE_OCTET_STRING 			2
#define KSI_TLV_TEMPLATE_UTF8_STRING 			3
#define KSI_TLV_TEMPLATE_IMPRINT 				4
#define KSI_TLV_TEMPLATE_COMPOSITE				5

#define DEFINE_TLV_TEMPLATE(name)	static KSI_TlvTemplate name##_template[] = {
#define TLV_INTEGER(tag, isNonCritical, isForward, fn) {KSI_TLV_TEMPLATE_INTEGER, tag, isNonCritical, isForward, (int (*)(const void *, const void **))fn, NULL },
#define TLV_OCTET_STRING(tag, isNonCritical, isForward, fn) {KSI_TLV_TEMPLATE_OCTET_STRING, tag, isNonCritical, isForward, (int (*)(const void *, const void **))fn, NULL},
#define TLV_UTF8_STRING(tag, isNonCritical, isForward, fn) {KSI_TLV_TEMPLATE_UTF8_STRING, tag, isNonCritical, isForward, (int (*)(const void *, const void **))fn, NULL},
#define TLV_IMPRINT(tag, isNonCritical, isForward, fn) {KSI_TLV_TEMPLATE_IMPRINT, tag, isNonCritical, isForward, (int (*)(const void *, const void **))fn, NULL},
#define TLV_COMPOSITE(tag, isNonCritical, isForward, fn, sub) {KSI_TLV_TEMPLATE_COMPOSITE, tag, isNonCritical, isForward, (int (*)(const void *, const void **))fn, sub##_template},
#define END_TLV_TEMPLATE { -1, 0, 0, 0, NULL, NULL}};

DEFINE_TLV_TEMPLATE(KSI_Header)
	TLV_INTEGER(0x05, 0, 0, KSI_Header_getInstanceId)
	TLV_INTEGER(0x06, 0, 0, KSI_Header_getMessageId)
	TLV_INTEGER(0x07, 0, 0, KSI_Header_getClientId)
END_TLV_TEMPLATE

DEFINE_TLV_TEMPLATE(KSI_Config)
	TLV_INTEGER(0x02, 0, 0, KSI_Config_getMaxLevel)
	TLV_INTEGER(0x03, 0, 0, KSI_Config_getAggrAlgo)
	TLV_INTEGER(0x04, 0, 0, KSI_Config_getAggrPeriod)
	TLV_UTF8_STRING(0x05, 0, 0, KSI_Config_getParentUri)
END_TLV_TEMPLATE

DEFINE_TLV_TEMPLATE(KSI_AggregationReq)
	TLV_COMPOSITE(0x01, 0, 0, KSI_AggregationReq_getHeader, KSI_Header)
	TLV_INTEGER(0x02, 0, 0, KSI_AggregationReq_getRequestId)
	TLV_IMPRINT(0x03, 0, 0, KSI_AggregationReq_getRequestHash)
	TLV_INTEGER(0x04, 0, 0, KSI_AggregationReq_getRequestLevel)
	TLV_COMPOSITE(0x04, 0, 0, KSI_AggregationReq_getConfig, KSI_Config)
END_TLV_TEMPLATE

DEFINE_TLV_TEMPLATE(KSI_ExtendReq)
	TLV_COMPOSITE(0x01, 0, 0, KSI_ExtendReq_getHeader, KSI_Header)
	TLV_INTEGER(0x04, 0, 0, KSI_ExtendReq_getRequestId)
	TLV_INTEGER(0x02, 0, 0, KSI_ExtendReq_getAggregationTime)
	TLV_INTEGER(0x03, 0, 0, KSI_ExtendReq_getPublicationTime)
END_TLV_TEMPLATE

static int createPdu(KSI_CTX *ctx, int tag, KSI_TLV **pdu) {
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

static int pduAdd(KSI_TLV *pdu, int tag, const void *payload, KSI_TlvTemplate *template) {
	KSI_ERR err;
	int res;
	const unsigned char *raw;
	int raw_len;
	KSI_TLV *tlv = NULL;
	KSI_TLV *tmp = NULL;
	KSI_CTX *ctx = NULL;
	const void *ptr = NULL;

	KSI_PRE(&err, pdu != NULL) goto cleanup;
	KSI_PRE(&err, payload != NULL) goto cleanup;
	KSI_PRE(&err, template != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(pdu);

	KSI_BEGIN(ctx, &err);

	/* Create a new TLV for the payload. */
	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, tag, 0, 0, &tlv);
	KSI_CATCH(&err, res) goto cleanup;


	while (template->type > 0) {
		ptr = NULL;
		res = template->getValue(payload, &ptr);
		KSI_CATCH(&err, res) goto cleanup;
		if (ptr != NULL) {
			res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, template->tag, template->isNonCritical, template->isForward, &tmp);
			KSI_CATCH(&err, res) goto cleanup;

			switch (template->type) {
				case KSI_TLV_TEMPLATE_INTEGER:
					res = KSI_TLV_cast(tmp, KSI_TLV_PAYLOAD_INT);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_setUintValue(tmp, KSI_Integer_getUInt64((KSI_Integer *) ptr));
					KSI_CATCH(&err, res) goto cleanup;

					break;
				case KSI_TLV_TEMPLATE_IMPRINT:
					res = KSI_DataHash_getImprint((const KSI_DataHash *)ptr, &raw, &raw_len);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_setRawValue(tmp, raw, raw_len);
					KSI_CATCH(&err, res) goto cleanup;

					break;
				case KSI_TLV_TEMPLATE_COMPOSITE:
					printf("Entering composite\n");
					res = pduAdd(tmp, template->tag, ptr, template->subTemplate);
					KSI_CATCH(&err, res) goto cleanup;

					break;
			}

			res = KSI_TLV_appendNestedTlv(tlv, NULL, tmp);
			KSI_CATCH(&err, res) goto cleanup;

			tmp = NULL;
		}
		template++;
	}

	res = KSI_TLV_appendNestedTlv(pdu, NULL, tlv);
	KSI_CATCH(&err, res) goto cleanup;

	tlv = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(ptr);

	KSI_TLV_free(tlv);
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
	KSI_DataHash *tmpHash = NULL;
	KSI_TLV *pdu = NULL;

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

	res = KSI_DataHash_clone(hsh, &tmpHash);
	KSI_CATCH(&err, res) goto cleanup;

	/* Add the hash to the request */
	res = KSI_AggregationReq_setRequestHash(req, tmpHash);
	KSI_CATCH(&err, res) goto cleanup;

	/* The hash value will be freed with the request. */
	tmpHash = NULL;

	res = createPdu(ctx,  0x200, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	res = pduAdd(pdu, 0x201, req, KSI_AggregationReq_template);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Request PDU", pdu);

	/* Serialize the request TLV. */
	res = KSI_TLV_serialize(pdu, &tmp, &tmp_len);
	KSI_CATCH(&err, res) goto cleanup;

	*raw = tmp;
	*raw_len = tmp_len;

	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(pdu);

	KSI_DataHash_free(tmpHash);
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
	KSI_TLV *pdu = NULL;
	KSI_ExtendReq *req = NULL;

	unsigned char *tmp = NULL;
	int tmp_len = 0;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	/* Create PDU */
	res = createPdu(ctx, 0x300, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create extend request object. */
	res = KSI_ExtendReq_new(ctx, &req);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendReq_setAggregationTime(req, KSI_Integer_clone(start));
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendReq_setPublicationTime(req, KSI_Integer_clone(end));
	KSI_CATCH(&err, res) goto cleanup;

	res = pduAdd(pdu, 0x301, req, KSI_ExtendReq_template);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Extend request PDU", pdu);

	/* Serialize the request TLV. */
	res = KSI_TLV_serialize(pdu, &tmp, &tmp_len);
	if (res != KSI_OK) goto cleanup;

	*raw = tmp;
	*raw_len = tmp_len;

	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp);
	KSI_nofree(imprint);
	KSI_TLV_free(pdu);

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

int KSI_Signature_extend(KSI_Signature *signature, KSI_Signature **extended) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	KSI_Signature *tmp = NULL;
	const KSI_Integer *startTime;

	unsigned char *req = NULL;
	int req_len = 0;

	unsigned char *resp = NULL;
	int resp_len = 0;

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
	res = createExtendRequest(ctx, startTime, NULL, &req, &req_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Extend request", req, req_len);

	/* Send the actual request. */
	res = KSI_sendExtendRequest(ctx, req, req_len, &handle);
	KSI_CATCH(&err, res) goto cleanup;

	/* Get the binary response */
	res = KSI_NET_getResponse(handle, &resp, &resp_len, 0);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Extend response", resp, resp_len);


	*extended = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(req);
	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);
}
