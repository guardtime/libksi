#include "ksi_internal.h"

#include "ksi_tlv_easy.h"

typedef struct KSI_TlvTemplate_st KSI_TlvTemplate;

typedef int (*getter_t)(const void *, const void **);
typedef int (*setter_t)(void *, void *);
struct KSI_TlvTemplate_st {
	int type;
	int tag;
	int isNonCritical;
	int isForward;
	/* Getter and setter for the internal value. */
	getter_t getValue;
	setter_t setValue;

	/* Constructor and destructor for the internal value. */
	int (*construct)(KSI_CTX *, void **);
	void (*destruct)(void *);



	KSI_TlvTemplate *subTemplate;
	/* List functions */
	int (*elementAppend)(void *, void *);
	/* Can this element be added multiple times (usefull with collections). */
	int multiple;
	int (*elementConstruct)(KSI_CTX *, void **);
	void (*elementDestruct)(void *);

	/* Callbacks */
	int (*callbackEncode)(void *, KSI_TLV *);
	int (*callbackDecode)(KSI_CTX *ctx, KSI_TLV *, void *, getter_t, setter_t);
};

#define KSI_TLV_TEMPLATE_INTEGER 				1
#define KSI_TLV_TEMPLATE_OCTET_STRING 			2
#define KSI_TLV_TEMPLATE_UTF8_STRING 			3
#define KSI_TLV_TEMPLATE_IMPRINT 				4
#define KSI_TLV_TEMPLATE_COMPOSITE				5
#define KSI_TLV_TEMPLATE_LIST					6
#define KSI_TLV_TEMPLATE_CALLBACK				7

#define TLV_FULL_TEMPLATE_DEF(typ, tg, nc, fw, gttr, sttr, constr, destr, subTmpl, appnd, mul, elConstr, elDestr, cbEnc, cbDec) { typ, tg, nc, fw, (getter_t)gttr, (setter_t)sttr, (int (*)(KSI_CTX *, void **)) constr, (void (*)(void *)) destr, subTmpl, (int (*)(void *, void *))appnd, mul, (int (*)(KSI_CTX *, void **)) elConstr, (void (*)(void *)) elDestr, (int (*)(void *, KSI_TLV *))cbEnc, (int (*)(KSI_CTX *ctx, KSI_TLV *, void *))cbDec},
#define TLV_PRIMITIVE_TEMPLATE_DEF(type, tag, isNonCritical, isForward, getter, setter) TLV_FULL_TEMPLATE_DEF(type, tag, isNonCritical, isForward, getter, setter, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL)

#define DEFINE_TLV_TEMPLATE(name)	static KSI_TlvTemplate name##_template[] = {
#define TLV_INTEGER(tag, isNonCritical, isForward, getter, setter) 			TLV_PRIMITIVE_TEMPLATE_DEF(KSI_TLV_TEMPLATE_INTEGER, tag, isNonCritical, isForward, getter, setter)
#define TLV_OCTET_STRING(tag, isNonCritical, isForward, getter, setter) 	TLV_PRIMITIVE_TEMPLATE_DEF(KSI_TLV_TEMPLATE_OCTET_STRING, tag, isNonCritical, isForward, getter, setter)
#define TLV_UTF8_STRING(tag, isNonCritical, isForward, getter, setter) 		TLV_PRIMITIVE_TEMPLATE_DEF(KSI_TLV_TEMPLATE_UTF8_STRING, tag, isNonCritical, isForward, getter, setter)
#define TLV_IMPRINT(tag, isNonCritical, isForward, getter, setter) 			TLV_PRIMITIVE_TEMPLATE_DEF(KSI_TLV_TEMPLATE_IMPRINT, tag, isNonCritical, isForward, getter, setter)
#define TLV_COMPOSITE(tag, isNonCritical, isForward, getter, setter, sub) {KSI_TLV_TEMPLATE_COMPOSITE, tag, isNonCritical, isForward, (int (*)(const void *, const void **))getter, (int(*)(void *, void*))setter, (int (*)(KSI_CTX *, void **))sub##_new, (void(*)(void *)) sub##_free, sub##_template, NULL, 0, NULL, NULL, NULL, NULL},
#define TLV_LIST(tag, isNonCritical, isForward, getter, setter, type, sub) {KSI_TLV_TEMPLATE_LIST, tag, isNonCritical, isForward, (int (*)(const void *, const void **))getter, (int(*)(void *, void*))setter, type##List_new, type##List_free, sub##_template, (int(*)(void *, void *))sub##_append, 1, (int (*)(KSI_CTX *, void **))sub##_new, (void (*)(void *))sub##_free, NULL, NULL}
#define TLV_CALLBACK(tag, isNonCritical, isForward, getter, setter, encode, decode) TLV_FULL_TEMPLATE_DEF(KSI_TLV_TEMPLATE_CALLBACK, tag, isNonCritical, isForward, getter, setter, NULL, NULL, NULL, NULL, 1, NULL, NULL, encode, decode)
#define END_TLV_TEMPLATE { -1, 0, 0, 0, NULL, NULL}};

static int decodeCalendarHashChainLink(KSI_CTX *ctx, KSI_TLV *tlv, KSI_CalendarHashChain *calHashChain, getter_t valueGetter, setter_t valueSetter) {
	KSI_ERR err;
	int res;
	int isLeft = 0;
	int tag;
	const unsigned char *raw;
	int raw_len = 0;
	KSI_LIST(KSI_HashChainLink) *listp = NULL;
	KSI_LIST(KSI_HashChainLink) *list = NULL;
	KSI_HashChainLink *link = NULL;
	KSI_DataHash *hsh = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, calHashChain != NULL) goto cleanup;
	KSI_PRE(&err, valueGetter != NULL) goto cleanup;
	KSI_PRE(&err, valueSetter != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	/* Verify the tag */
	tag = KSI_TLV_getTag(tlv);
	switch(tag) {
		case 0x07:
			isLeft = 1;
			break;
		case 0x08:
			isLeft = 0;
			break;
		default:
			KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
			goto cleanup;
	}


	/* Get the imprint as raw value */
	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create datahash object */
	res = KSI_DataHash_fromImprint(ctx, raw, raw_len, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	/* Initialize the current link. */
	res = KSI_HashChainLink_new(ctx, &link);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChainLink_setIsLeft(link, isLeft);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChainLink_setImprint(link, hsh);
	KSI_CATCH(&err, res) goto cleanup;
	hsh = NULL;

	/* Get the whole hash chain. */
	res = valueGetter(calHashChain, &listp);
	KSI_CATCH(&err, res) goto cleanup;

	/* Initialize list if it does not exist */
	if (listp == NULL) {
		res = KSI_HashChainLinkList_new(ctx, &list);
		KSI_CATCH(&err, res) goto cleanup;

		listp = list;
	}

	/* Append the current link to the list */
	res = KSI_HashChainLinkList_append(listp, link);
	link = NULL;

	if (list != NULL) {
		/* The list was just created - set it in the object */
		res = KSI_CalendarHashChain_setHashChain(calHashChain, list);
		KSI_CATCH(&err, res) goto cleanup;

		list = NULL;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_HashChainLinkList_free(list);
	KSI_HashChainLink_free(link);
	KSI_DataHash_free(hsh);
	KSI_nofree(raw);
	KSI_nofree(listp);
	return KSI_RETURN(&err);
}

DEFINE_TLV_TEMPLATE(KSI_Header)
	TLV_INTEGER(0x05, 0, 0, KSI_Header_getInstanceId, KSI_Header_setInstanceId)
	TLV_INTEGER(0x06, 0, 0, KSI_Header_getMessageId, KSI_Header_setMessageId)
	TLV_INTEGER(0x07, 0, 0, KSI_Header_getClientId, KSI_Header_setClientId)
END_TLV_TEMPLATE

DEFINE_TLV_TEMPLATE(KSI_Config)
	TLV_INTEGER(0x02, 0, 0, KSI_Config_getMaxLevel, KSI_Config_setMaxLevel)
	TLV_INTEGER(0x03, 0, 0, KSI_Config_getAggrAlgo, KSI_Config_setAggrAlgo)
	TLV_INTEGER(0x04, 0, 0, KSI_Config_getAggrPeriod, KSI_Config_setAggrPeriod)
	TLV_UTF8_STRING(0x05, 0, 0, KSI_Config_getParentUri, KSI_Config_setParentUri)
END_TLV_TEMPLATE

DEFINE_TLV_TEMPLATE(KSI_AggregationReq)
	TLV_COMPOSITE(0x01, 0, 0, KSI_AggregationReq_getHeader, KSI_AggregationReq_setHeader, KSI_Header)
	TLV_INTEGER(0x02, 0, 0, KSI_AggregationReq_getRequestId, KSI_AggregationReq_setRequestId)
	TLV_IMPRINT(0x03, 0, 0, KSI_AggregationReq_getRequestHash, KSI_AggregationReq_setRequestHash)
	TLV_INTEGER(0x04, 0, 0, KSI_AggregationReq_getRequestLevel, KSI_AggregationReq_setRequestLevel)
	TLV_COMPOSITE(0x04, 0, 0, KSI_AggregationReq_getConfig, KSI_AggregationReq_setConfig, KSI_Config)
END_TLV_TEMPLATE

DEFINE_TLV_TEMPLATE(KSI_AggregationPdu)
	TLV_COMPOSITE(0x201, 0, 0, KSI_AggregationPdu_getRequest, KSI_AggregationPdu_setRequest, KSI_AggregationReq)
//	TLV_COMPOSITE(0x202, 0, 0, KSI_AggregationPdu_getResponse, KSI_AggregationPdu_setResponse, KSI_AggregationResp)
END_TLV_TEMPLATE

DEFINE_TLV_TEMPLATE(KSI_CalendarHashChain)
	TLV_INTEGER(0x01, 0, 0, KSI_CalendarHashChain_getPublicationTime, KSI_CalendarHashChain_setPublicationTime)
	TLV_INTEGER(0x02, 0, 0, KSI_CalendarHashChain_getAggregationTime, KSI_CalendarHashChain_setAggregationTime)
	TLV_IMPRINT(0x05, 0, 0, KSI_CalendarHashChain_getInputHash, KSI_CalendarHashChain_setInputHash)
	TLV_CALLBACK(0x07, 0, 0, KSI_CalendarHashChain_getHashChain, KSI_CalendarHashChain_setHashChain, NULL, decodeCalendarHashChainLink)
	TLV_CALLBACK(0x08, 0, 0, KSI_CalendarHashChain_getHashChain, KSI_CalendarHashChain_setHashChain, NULL, NULL)
END_TLV_TEMPLATE

DEFINE_TLV_TEMPLATE(KSI_ExtendReq)
	TLV_COMPOSITE(0x01, 0, 0, KSI_ExtendReq_getHeader, KSI_ExtendReq_setHeader, KSI_Header)
	TLV_INTEGER(0x04, 0, 0, KSI_ExtendReq_getRequestId, KSI_ExtendReq_setRequestId)
	TLV_INTEGER(0x02, 0, 0, KSI_ExtendReq_getAggregationTime, KSI_ExtendReq_setAggregationTime)
	TLV_INTEGER(0x03, 0, 0, KSI_ExtendReq_getPublicationTime, KSI_ExtendReq_setPublicationTime)
END_TLV_TEMPLATE

DEFINE_TLV_TEMPLATE(KSI_ExtendResp)
	TLV_COMPOSITE(0x01, 0, 0, KSI_ExtendResp_getHeader, KSI_ExtendResp_setHeader, KSI_Header)
	TLV_INTEGER(0x02, 0, 0, KSI_ExtendResp_getRequestId, KSI_ExtendResp_setRequestId)
	TLV_INTEGER(0x05, 0, 0, KSI_ExtendResp_getStatus, KSI_ExtendResp_setStatus)
	TLV_UTF8_STRING(0x06, 0, 0, KSI_ExtendResp_getErrorMsg, KSI_ExtendResp_setErrorMsg)
	TLV_INTEGER(0x07, 0, 0, KSI_ExtendResp_getLastTime, KSI_ExtendResp_getLastTime)
	TLV_COMPOSITE(0x802, 0, 0, KSI_ExtendResp_getCalendarHashChain, KSI_ExtendResp_setCalendarHashChain, KSI_CalendarHashChain)
END_TLV_TEMPLATE

DEFINE_TLV_TEMPLATE(KSI_ExtendPdu)
	TLV_COMPOSITE(0x301, 0, 0, KSI_ExtendPdu_getRequest, KSI_ExtendPdu_setRequest, KSI_ExtendReq)
	TLV_COMPOSITE(0x302, 0, 0, KSI_ExtendPdu_getResponse, KSI_ExtendPdu_setResponse, KSI_ExtendResp)
END_TLV_TEMPLATE

static int extract(KSI_CTX *ctx, void *payload, KSI_TLV *tlv, KSI_TlvTemplate *template, KSI_LIST(KSI_TLV) *reminder) {
	KSI_ERR err;
	KSI_TLV *tmp = NULL;
	int res;
	KSI_TlvTemplate *t = NULL;
	const unsigned char *raw = NULL;
	int raw_len = 0;

	KSI_Integer *integerVal = NULL;
	KSI_DataHash *hashVal = NULL;
	KSI_OctetString *octetStringVal = NULL;
	KSI_Utf8String *stringVal = NULL;
	void *listVal = NULL;
	void *compositeVal = NULL;
	void *valuep = NULL;
	void *listp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_TLV);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_iterNested(tlv);
	KSI_CATCH(&err, res) goto cleanup;

	while (1) {
		res = KSI_TLV_getNextNestedTLV(tlv, &tmp);
		KSI_CATCH(&err, res) goto cleanup;

		if (tmp == NULL) break;

		t = template;
		while(t->type > 0 && t->tag != KSI_TLV_getTag(tmp)) {
			++t;
		}

		if (t->type > 0) {
			/* Validate the value has not been set */
			res = t->getValue(payload, (const void **)&valuep);
			KSI_CATCH(&err, res) goto cleanup;

			if (valuep != NULL && !t->multiple) {
				compositeVal = NULL;
				KSI_FAIL(&err, KSI_INVALID_FORMAT, "To avoid memory leaks, a value may not be set more than once while parsing.");
				goto cleanup;
			}

			/* Parse the current TLV */
			switch (t->type) {
				case KSI_TLV_TEMPLATE_INTEGER:
					res = KSI_TLV_cast(tmp, KSI_TLV_PAYLOAD_INT);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_getInteger(tmp, &integerVal);
					KSI_CATCH(&err, res) goto cleanup;

					res = t->setValue(payload, (void *)integerVal);
					KSI_CATCH(&err, res) goto cleanup;

					integerVal = NULL;
					break;

				case KSI_TLV_TEMPLATE_IMPRINT:
					res = KSI_TLV_cast(tmp, KSI_TLV_PAYLOAD_RAW);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_getRawValue(tmp, &raw, &raw_len);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_DataHash_fromImprint(ctx, raw, raw_len, &hashVal);
					KSI_CATCH(&err, res) goto cleanup;

					hashVal = NULL;

					res = t->setValue(payload, (void *)hashVal);
					KSI_CATCH(&err, res) goto cleanup;

					hashVal = NULL;
					break;

				case KSI_TLV_TEMPLATE_OCTET_STRING:
					res = KSI_TLV_cast(tmp, KSI_TLV_PAYLOAD_RAW);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_getRawValue(tmp, &raw, &raw_len);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_OctetString_new(ctx, raw, raw_len, &octetStringVal);
					KSI_CATCH(&err, res) goto cleanup;

					res = t->setValue(tmp, (void *)octetStringVal);
					octetStringVal = NULL;
					break;

				case KSI_TLV_TEMPLATE_UTF8_STRING:
					res = KSI_TLV_cast(tmp, KSI_TLV_PAYLOAD_STR);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_getStringValue(tmp, (const char **)&raw);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_Utf8String_new(ctx, (const char *)raw, &stringVal);
					KSI_CATCH(&err, res) goto cleanup;

					res = t->setValue(payload, (void *)stringVal);
					KSI_CATCH(&err, res) goto cleanup;

					stringVal = NULL;
					break;

				case KSI_TLV_TEMPLATE_COMPOSITE:
					res = t->construct(ctx, &compositeVal);
					KSI_CATCH(&err, res) goto cleanup;

					res = extract(ctx, compositeVal, tmp, t->subTemplate, NULL);
					KSI_CATCH(&err, res) {
						t->destruct(compositeVal);
						goto cleanup;
					}

					break;
				case KSI_TLV_TEMPLATE_CALLBACK:
					break;
				case KSI_TLV_TEMPLATE_LIST:
					if (valuep == NULL) {
						/* Create new list */
						res = t->construct(ctx, &listp);
						KSI_CATCH(&err, res) goto cleanup;

						res = t->setValue(payload, listp);
						KSI_CATCH(&err, res) {
							t->destruct(listp);
							goto cleanup;
						}
					}

					res = t->getValue(payload, &listp);
					KSI_CATCH(&err, res) goto cleanup;

					res = t->elementConstruct(ctx, &listVal);
					KSI_CATCH(&err, res) goto cleanup;

					res = extract(ctx, listVal, tmp, t->subTemplate, reminder);
					KSI_CATCH(&err, res) {
						t->elementDestruct(listVal);
						goto cleanup;
					}

					res = t->elementAppend(listp, listVal);
					KSI_CATCH(&err, res) {
						t->elementDestruct(listVal);
						goto cleanup;
					}

					break;
				default:
					/* Should not happen, but just in case. */
					KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Undefined template type");
					goto cleanup;
			}

		} else {
			if (reminder != NULL) {
				/* The TLV tag is not in the template, move it to the reminder. */
				res = KSI_TLVList_append(reminder, tmp);
				KSI_CATCH(&err, res) goto cleanup;

				/* Detele the TLV from the original list. */
				res = KSI_TLV_removeNestedTlv(tlv, tmp);
				KSI_CATCH(&err, res) goto cleanup;
			} else {
				if (!KSI_TLV_isLenient(tlv)) {
					KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
					goto cleanup;
				}
			}
		}
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_OctetString_free(octetStringVal);
	KSI_DataHash_free(hashVal);
	KSI_Utf8String_free(stringVal);
	KSI_Integer_free(integerVal);

	return KSI_RETURN(&err);
}

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

static int constructTlv(KSI_CTX *ctx, KSI_TLV *tlv, const void *payload, KSI_TlvTemplate *template) {
	KSI_ERR err;
	int res;
	const unsigned char *raw;
	int raw_len;
	KSI_TLV *tmp = NULL;
	const void *payloadp = NULL;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, template != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	while (template->type > 0) {
		payloadp = NULL;
		res = template->getValue(payload, &payloadp);
		KSI_CATCH(&err, res) goto cleanup;
		if (payloadp != NULL) {
			res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, template->tag, template->isNonCritical, template->isForward, &tmp);
			KSI_CATCH(&err, res) goto cleanup;

			switch (template->type) {
				case KSI_TLV_TEMPLATE_INTEGER:
					res = KSI_TLV_cast(tmp, KSI_TLV_PAYLOAD_INT);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_setUintValue(tmp, KSI_Integer_getUInt64((KSI_Integer *) payloadp));
					KSI_CATCH(&err, res) goto cleanup;

					break;
				case KSI_TLV_TEMPLATE_OCTET_STRING:
					res = KSI_OctetString_extract((const KSI_OctetString *)payloadp, &raw, &raw_len);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_setRawValue(tmp, raw, raw_len);
					KSI_CATCH(&err, res) goto cleanup;

					break;
				case KSI_TLV_TEMPLATE_IMPRINT:
					res = KSI_DataHash_getImprint((const KSI_DataHash *)payloadp, &raw, &raw_len);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_setRawValue(tmp, raw, raw_len);
					KSI_CATCH(&err, res) goto cleanup;

					break;
				case KSI_TLV_TEMPLATE_COMPOSITE:
					res = KSI_TLV_cast(tmp, KSI_TLV_PAYLOAD_TLV);
					KSI_CATCH(&err, res) goto cleanup;

					res = constructTlv(ctx, tmp, payloadp, template->subTemplate);
					KSI_CATCH(&err, res) goto cleanup;

					break;

				case KSI_TLV_TEMPLATE_LIST:
					// TODO!
				default:
					KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Unimplemented template type.");
					goto cleanup;
			}

			res = KSI_TLV_appendNestedTlv(tlv, NULL, tmp);
			KSI_CATCH(&err, res) goto cleanup;

			tmp = NULL;
		}
		template++;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(payloadp);

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

	res = constructTlv(ctx, pduTlv, pdu, KSI_AggregationPdu_template);
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

	// FIXME!
	KSI_Integer *tmpStart = NULL;
	res = KSI_Integer_new(ctx, KSI_Integer_getUInt64(start) - 3600*24*14, &tmpStart);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendReq_setAggregationTime(req, tmpStart);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendReq_setPublicationTime(req, KSI_Integer_clone(end));
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendPdu_new(ctx, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_ExtendPdu_setRequest(pdu, req);
	KSI_CATCH(&err, res) goto cleanup;
	req = NULL;

	res = constructTlv(ctx, pduTLV, pdu, KSI_ExtendPdu_template);
//	res = pduAdd(pduTLV, 0x301, req, KSI_ExtendReq_template);
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

int KSI_Signature_extend(KSI_Signature *signature, KSI_Signature **extended) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	KSI_Signature *tmp = NULL;
	const KSI_Integer *startTime;

	unsigned char *rawReq = NULL;
	int rawReq_len = 0;

	unsigned char *rawResp = NULL;
	int rawResp_len = 0;

	KSI_TLV *respTlv = NULL;
	KSI_LIST(KSI_TLV) *reminder = NULL;

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
	res = createExtendRequest(ctx, startTime, NULL, &rawReq, &rawReq_len);
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

	res = KSI_ExtendPdu_new(ctx, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	res = extract(ctx, pdu, respTlv, KSI_ExtendPdu_template, reminder);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Parsed part of the response", respTlv);

	*extended = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(rawReq);
	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);
}
