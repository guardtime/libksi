#include "ksi_internal.h"

static int encodeCalendarHashChainLink(KSI_CTX *ctx, KSI_TLV *tlv, const KSI_CalendarHashChain *calHashChain, const KSI_TlvTemplate *template);
static int decodeCalendarHashChainLeftLink(KSI_CTX *ctx, KSI_TLV *tlv, KSI_CalendarHashChain *calHashChain, const KSI_TlvTemplate *template);
static int decodeCalendarHashChainRightLink(KSI_CTX *ctx, KSI_TLV *tlv, KSI_CalendarHashChain *calHashChain, KSI_TlvTemplate *template);

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationsHeader)
	KSI_TLV_INTEGER(0x01, 0, 0, KSI_PublicationsHeader_getVersion, KSI_PublicationsHeader_setVersion)
	KSI_TLV_INTEGER(0x02, 0, 0, KSI_PublicationsHeader_getTimeCreated, KSI_PublicationsHeader_setTimeCreated)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_CertificateRecord)
	KSI_TLV_OCTET_STRING(0x01, 0, 0, KSI_CertificateRecord_getCertId, KSI_CertificateRecord_setCertId)
	KSI_TLV_OBJECT(0x02, 0, 0, KSI_CertificateRecord_getCert, KSI_CertificateRecord_setCert, KSI_PKICertificate_fromTlv, KSI_PKICertificate_toTlv)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationData)
	KSI_TLV_INTEGER(0x02, 0, 0, KSI_PublicationData_getTime, KSI_PublicationData_setTime)
	KSI_TLV_IMPRINT(0x04, 0, 0, KSI_PublicationData_getImprint, KSI_PublicationData_setImprint)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationRecord)
	KSI_TLV_COMPOSITE(0x10, 0, 0, KSI_PublicationRecord_getPublishedData, KSI_PublicationRecord_setPublishedData, KSI_PublicationData)
	KSI_TLV_UTF8_STRING_LIST(0x09, 0, 0, KSI_PublicationRecord_getPublicationRef, KSI_PublicationRecord_setPublicationRef)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_MetaData)
	KSI_TLV_UTF8_STRING(0x01, 0, 0, KSI_MetaData_getClientId, KSI_MetaData_setClientId)
	KSI_TLV_INTEGER(0x02, 0, 0, KSI_MetaData_getMachineId, KSI_MetaData_setMachineId)
	KSI_TLV_INTEGER(0x03, 0, 0, KSI_MetaData_getSequenceNr, KSI_MetaData_setSequenceNr)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_HashChainLink)
	KSI_TLV_NATIVE_INT(0x01, 0, 0, KSI_HashChainLink_getLevelCorrection, KSI_HashChainLink_setLevelCorrection)
	KSI_TLV_IMPRINT(0x02, 0, 0, KSI_HashChainLink_getImprint, KSI_HashChainLink_setImprint)
	KSI_TLV_IMPRINT(0x03, 0, 0, KSI_HashChainLink_getMetaHash, KSI_HashChainLink_setMetaHash)
	KSI_TLV_COMPOSITE(0x04, 0, 0, KSI_HashChainLink_getMetaData, KSI_HashChainLink_setMetaData, KSI_MetaData)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_Header)
	KSI_TLV_INTEGER(0x05, 0, 0, KSI_Header_getInstanceId, KSI_Header_setInstanceId)
	KSI_TLV_INTEGER(0x06, 0, 0, KSI_Header_getMessageId, KSI_Header_setMessageId)
	KSI_TLV_INTEGER(0x07, 0, 0, KSI_Header_getClientId, KSI_Header_setClientId)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_Config)
	KSI_TLV_INTEGER(0x02, 0, 0, KSI_Config_getMaxLevel, KSI_Config_setMaxLevel)
	KSI_TLV_INTEGER(0x03, 0, 0, KSI_Config_getAggrAlgo, KSI_Config_setAggrAlgo)
	KSI_TLV_INTEGER(0x04, 0, 0, KSI_Config_getAggrPeriod, KSI_Config_setAggrPeriod)
	KSI_TLV_UTF8_STRING(0x05, 0, 0, KSI_Config_getParentUri, KSI_Config_setParentUri)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationReq)
	KSI_TLV_COMPOSITE(0x01, 0, 0, KSI_AggregationReq_getHeader, KSI_AggregationReq_setHeader, KSI_Header)
	KSI_TLV_INTEGER(0x02, 0, 0, KSI_AggregationReq_getRequestId, KSI_AggregationReq_setRequestId)
	KSI_TLV_IMPRINT(0x03, 0, 0, KSI_AggregationReq_getRequestHash, KSI_AggregationReq_setRequestHash)
	KSI_TLV_INTEGER(0x04, 0, 0, KSI_AggregationReq_getRequestLevel, KSI_AggregationReq_setRequestLevel)
	KSI_TLV_COMPOSITE(0x04, 0, 0, KSI_AggregationReq_getConfig, KSI_AggregationReq_setConfig, KSI_Config)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationPdu)
	KSI_TLV_COMPOSITE(0x201, 0, 0, KSI_AggregationPdu_getRequest, KSI_AggregationPdu_setRequest, KSI_AggregationReq)
//	TLV_COMPOSITE(0x202, 0, 0, KSI_AggregationPdu_getResponse, KSI_AggregationPdu_setResponse, KSI_AggregationResp)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_CalendarHashChain)
	KSI_TLV_INTEGER(0x01, 0, 0, KSI_CalendarHashChain_getPublicationTime, KSI_CalendarHashChain_setPublicationTime)
	KSI_TLV_INTEGER(0x02, 0, 0, KSI_CalendarHashChain_getAggregationTime, KSI_CalendarHashChain_setAggregationTime)
	KSI_TLV_IMPRINT(0x05, 0, 0, KSI_CalendarHashChain_getInputHash, KSI_CalendarHashChain_setInputHash)
	KSI_TLV_CALLBACK(0x07, 0, 0, KSI_CalendarHashChain_getHashChain, KSI_CalendarHashChain_setHashChain, encodeCalendarHashChainLink, decodeCalendarHashChainLeftLink)
	KSI_TLV_CALLBACK(0x08, 0, 0, KSI_CalendarHashChain_getHashChain, KSI_CalendarHashChain_setHashChain, NULL, decodeCalendarHashChainRightLink)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_ExtendReq)
	KSI_TLV_COMPOSITE(0x01, 0, 0, KSI_ExtendReq_getHeader, KSI_ExtendReq_setHeader, KSI_Header)
	KSI_TLV_INTEGER(0x04, 0, 0, KSI_ExtendReq_getRequestId, KSI_ExtendReq_setRequestId)
	KSI_TLV_INTEGER(0x02, 0, 0, KSI_ExtendReq_getAggregationTime, KSI_ExtendReq_setAggregationTime)
	KSI_TLV_INTEGER(0x03, 0, 0, KSI_ExtendReq_getPublicationTime, KSI_ExtendReq_setPublicationTime)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_ExtendResp)
	KSI_TLV_COMPOSITE(0x01, 0, 0, KSI_ExtendResp_getHeader, KSI_ExtendResp_setHeader, KSI_Header)
	KSI_TLV_INTEGER(0x02, 0, 0, KSI_ExtendResp_getRequestId, KSI_ExtendResp_setRequestId)
	KSI_TLV_INTEGER(0x05, 0, 0, KSI_ExtendResp_getStatus, KSI_ExtendResp_setStatus)
	KSI_TLV_UTF8_STRING(0x06, 0, 0, KSI_ExtendResp_getErrorMsg, KSI_ExtendResp_setErrorMsg)
	KSI_TLV_INTEGER(0x07, 0, 0, KSI_ExtendResp_getLastTime, KSI_ExtendResp_setLastTime)
	KSI_TLV_COMPOSITE(0x802, 0, 0, KSI_ExtendResp_getCalendarHashChain, KSI_ExtendResp_setCalendarHashChain, KSI_CalendarHashChain)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_ExtendPdu)
	KSI_TLV_COMPOSITE(0x301, 0, 0, KSI_ExtendPdu_getRequest, KSI_ExtendPdu_setRequest, KSI_ExtendReq)
	KSI_TLV_COMPOSITE(0x302, 0, 0, KSI_ExtendPdu_getResponse, KSI_ExtendPdu_setResponse, KSI_ExtendResp)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_PKISignedData)
	KSI_TLV_OCTET_STRING(0x01, 0, 0, KSI_PKISignedData_getSignatureValue, KSI_PKISignedData_setSignatureValue)
	KSI_TLV_OBJECT(0x02, 0, 0, KSI_PKISignedData_getCert, KSI_PKISignedData_setCert, KSI_PKICertificate_fromTlv, KSI_PKICertificate_toTlv)
	KSI_TLV_OCTET_STRING(0x03, 0, 0, KSI_PKISignedData_getCertId, KSI_PKISignedData_setCertId)
KSI_END_TLV_TEMPLATE

static int encodeCalendarHashChainLink(KSI_CTX *ctx, KSI_TLV *tlv, const KSI_CalendarHashChain *calHashChain, const KSI_TlvTemplate *template) {
	KSI_ERR err;
	int res;
	int i;

	KSI_LIST(KSI_HashChainLink) *chain = NULL;

	KSI_TLV *tmp = NULL;
	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, calHashChain != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, template != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_TLV);
	KSI_CATCH(&err, res) goto cleanup;

	res = template->getValue((void *)calHashChain, (void **)&chain);
	KSI_CATCH(&err, res) goto cleanup;

	if (chain == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	for (i = 0; i < KSI_HashChainLinkList_length(chain); i++) {
		KSI_HashChainLink *link = NULL;
		KSI_DataHash *hsh = NULL;
		const unsigned char *imprint = NULL;
		int imprint_len = 0;
		int isLeft;

		/* Get the chain element. */
		res = KSI_HashChainLinkList_elementAt(chain, i, &link);
		KSI_CATCH(&err, res) goto cleanup;

		/* Extract data hash value */
		res = KSI_HashChainLink_getImprint(link, &hsh);
		KSI_CATCH(&err, res) goto cleanup;

		/* Extract raw imprint */
		res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_len);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_HashChainLink_getIsLeft(link, &isLeft);
		KSI_CATCH(&err, res) goto cleanup;

		/* Create new TLV object. */
		res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, isLeft ? 0x07 : 0x08, 0, 0, &tmp );
		KSI_CATCH(&err, res) goto cleanup;

		/* Set the imprint as payload. */
		res = KSI_TLV_setRawValue(tmp, imprint, imprint_len);
		KSI_CATCH(&err, res) goto cleanup;

		/* Append the payload to the parent TLV */
		res = KSI_TLV_appendNestedTlv(tlv, NULL, tmp);
		KSI_CATCH(&err, res) goto cleanup;

		tmp = NULL;

		KSI_nofree(link);
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(aggrTime);
	KSI_nofree(publTime);
	KSI_nofree(inputHash);
	KSI_nofree(chain);

	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

static int decodeCalendarHashChainLink(KSI_CTX *ctx, KSI_TLV *tlv, KSI_CalendarHashChain *calHashChain, getter_t valueGetter, setter_t valueSetter, int isLeft) {
	KSI_ERR err;
	int res;
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
	res = valueGetter((void *)calHashChain, (void **)&listp);
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
		res = valueSetter((void *)calHashChain, (void *)list);
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

static int decodeCalendarHashChainLeftLink(KSI_CTX *ctx, KSI_TLV *tlv, KSI_CalendarHashChain *calHashChain, const KSI_TlvTemplate *template) {
	return decodeCalendarHashChainLink(ctx, tlv, calHashChain, template->getValue, template->setValue, 1);
}
static int decodeCalendarHashChainRightLink(KSI_CTX *ctx, KSI_TLV *tlv, KSI_CalendarHashChain *calHashChain, KSI_TlvTemplate *template) {
	return decodeCalendarHashChainLink(ctx, tlv, calHashChain, template->getValue, template->setValue, 0);
}


static int storeObjectValue(KSI_CTX *ctx, const KSI_TlvTemplate *template, void *payload, void *val) {
	KSI_ERR err;
	int res;
	void *list = NULL;
	void *listp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, template != NULL) goto cleanup;
	KSI_PRE(&err, payload != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (template->listAppend != NULL) {
		/* If the list append function pointer is set, the value is added to a list. */
		void *list = NULL;


		res = template->getValue(payload, &listp);
		if (res != KSI_OK) goto cleanup;
		
		if (listp == NULL) {
			/* Make sure we have required function pointers. */
			if (template->listNew == NULL || template->listFree == NULL) {
				KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Template does not have list constructor or destructor, but list itself does not exist.");
				goto cleanup;
			}
			res = template->listNew(ctx, &list);
			KSI_CATCH(&err, res) goto cleanup;

			listp = list;
		}
		
		res = template->listAppend(listp, (void *) val);
		KSI_CATCH(&err, res) goto cleanup;
		
		res = template->setValue(payload, listp);
		KSI_CATCH(&err, res) goto cleanup;

	} else {
		/* Regular value - store with the setter. */
		res = template->setValue(payload, (void *) val);
		KSI_CATCH(&err, res) goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(listp);
	if (template->listFree != NULL) template->listFree(list);

	return KSI_RETURN(&err);
}

int KSI_TlvTemplate_extract(KSI_CTX *ctx, void *payload, KSI_TLV *tlv, const KSI_TlvTemplate *template, KSI_LIST(KSI_TLV) *reminder) {
	KSI_ERR err;
	int res;
	int i;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_TLV);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_iterNested(tlv);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_extractGenerator(ctx, payload, (void *)tlv, template, reminder, (int (*)(void *, KSI_TLV **))KSI_TLV_getNextNestedTLV);
	KSI_CATCH(&err, res) goto cleanup;

	if (reminder != NULL) {
		/* Remove the elements in the reminder from the base tlv. */
		for (i = 0; i < KSI_TLVList_length(reminder); i++) {
			KSI_TLV *tmp = NULL;
			/* Delete the TLV from the original list. */
			res = KSI_TLV_removeNestedTlv(tlv, tmp);
			KSI_CATCH(&err, res) goto cleanup;

			KSI_nofree(tmp);
		}
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);

}

int KSI_TlvTemplate_extractGenerator(KSI_CTX *ctx, void *payload, void *generatorCtx, const KSI_TlvTemplate *template, KSI_LIST(KSI_TLV) *reminder, int (*generator)(void *, KSI_TLV **)) {
	KSI_ERR err;
	KSI_TLV *tlv = NULL;
	int res;
	const KSI_TlvTemplate *t = NULL;

	KSI_Integer *integerVal = NULL;
	KSI_DataHash *hashVal = NULL;
	KSI_OctetString *octetStringVal = NULL;
	KSI_Utf8String *stringVal = NULL;
	KSI_uint64_t uint64Val = 0;
	void *voidVal = NULL;
	int intVal = 0;
	void *compositeVal = NULL;
	void *valuep = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	while (1) {
		int matchCount = 0;
		res = generator(generatorCtx, &tlv);
		KSI_CATCH(&err, res) goto cleanup;

		if (tlv == NULL) break;

		KSI_LOG_trace(ctx, "Starting to parse TLV(0x%02x)", KSI_TLV_getTag(tlv));

		t = template;

		while (t->type > 0) {
			if (t->tag != KSI_TLV_getTag(tlv)) {
				t++;
				continue;
			}
			matchCount++;

			valuep = NULL;
			if (t->getValue != NULL) {
				/* Validate the value has not been set */
				res = t->getValue(payload, (void **)&valuep);
				KSI_CATCH(&err, res) goto cleanup;
			}

			if (valuep != NULL && !t->multiple) {
				compositeVal = NULL;
				KSI_FAIL(&err, KSI_INVALID_FORMAT, "To avoid memory leaks, a value may not be set more than once while parsing.");
				goto cleanup;
			}
			/* Parse the current TLV */
			switch (t->type) {
				case KSI_TLV_TEMPLATE_NATIVE_INT:
					KSI_LOG_trace(ctx, "Detected native int template for TLV value extraction.");
					res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_INT);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_getUInt64Value(tlv, &uint64Val);
					KSI_CATCH(&err, res) goto cleanup;

					intVal = (int)uint64Val;
					if (intVal != uint64Val) {
						KSI_FAIL(&err, KSI_INVALID_FORMAT, "Value too big for internal int value.");
						goto cleanup;
					}

					res = ((int (*)(void *, int))t->setValue)(payload, intVal);
					KSI_CATCH(&err, res) goto cleanup;

					break;
				case KSI_TLV_TEMPLATE_SEEK_POS:
					intVal = KSI_TLV_getAbsoluteOffset(tlv);

					res = ((int (*)(void *, int))t->setValue)(payload, intVal);
					KSI_CATCH(&err, res) goto cleanup;

					break;
				case KSI_TLV_TEMPLATE_OBJECT:
					if (t->fromTlv == NULL) {
						KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Invalid template: fromTlv not set.");
						goto cleanup;
					}

					res = t->fromTlv(tlv, &voidVal);
					KSI_CATCH(&err, res) goto cleanup;

					res = storeObjectValue(ctx, t, payload, voidVal);
					KSI_CATCH(&err, res) goto cleanup;

					break;
				case KSI_TLV_TEMPLATE_COMPOSITE:
					KSI_LOG_trace(ctx, "Detected composite template for TLV value extraction.");

					res = t->construct(ctx, &compositeVal);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TlvTemplate_extract(ctx, compositeVal, tlv, t->subTemplate, NULL);
					KSI_CATCH(&err, res) {
						t->destruct(compositeVal);
						goto cleanup;
					}

					res = storeObjectValue(ctx, t, payload, (void *)compositeVal);
					KSI_CATCH(&err, res) goto cleanup;

					KSI_LOG_trace(ctx, "Composite value extracted.");
					break;
				case KSI_TLV_TEMPLATE_CALLBACK:
					KSI_LOG_trace(ctx, "Detected callback template for TLV value extraction.");

					if (t->callbackDecode != NULL) {
						res = t->callbackDecode(ctx, tlv, payload, t);
						KSI_CATCH(&err, res) goto cleanup;
					}
					break;
				default:
					KSI_LOG_warn(ctx, "No template found.");
					/* Should not happen, but just in case. */
					KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Undefined template type");
					goto cleanup;
			}

			t++;
		}

		if(matchCount == 0) {
			if (reminder != NULL) {
				/* The TLV tag is not in the template, move it to the reminder. */
				res = KSI_TLVList_append(reminder, tlv);
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

int KSI_TlvTemplate_construct(KSI_CTX *ctx, KSI_TLV *tlv, const void *payload, const KSI_TlvTemplate *template) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;
	void *payloadp = NULL;
	int intVal;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, template != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	while (template->type > 0) {
		payloadp = NULL;
		res = template->getValue(payload, &payloadp);
		KSI_CATCH(&err, res) goto cleanup;
		if (payloadp != NULL) {
			switch (template->type) {
				case KSI_TLV_TEMPLATE_SEEK_POS:
					/* As this is a read-only template in the extraction process, there is
					 * no logical construction action performed. */
					break;
				case KSI_TLV_TEMPLATE_NATIVE_INT:
					res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, template->tag, template->isNonCritical, template->isForward, &tmp);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_cast(tmp, KSI_TLV_PAYLOAD_INT);
					KSI_CATCH(&err, res) goto cleanup;

					res = ((int (*)(const void *, int *))template->getValue)(payload, &intVal);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_setUintValue(tmp, (KSI_uint64_t)intVal);
					KSI_CATCH(&err, res) goto cleanup;

					break;
				case KSI_TLV_TEMPLATE_OBJECT:
					if (template->toTlv == NULL) {
						KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Invalid template: toTlv not set.");
						goto cleanup;
					}

					if (template->listLength != NULL) {
						int i;
						for (i = 0; i < template->listLength(payloadp); i++) {
							void *listElement = 0;
							res = template->listElementAt(payloadp, i, &listElement);
							KSI_CATCH(&err, res) goto cleanup;

							res = template->toTlv(listElement, template->tag, template->isNonCritical, template->isForward, &tmp);
							KSI_CATCH(&err, res) goto cleanup;

							res = KSI_TLV_appendNestedTlv(tlv, NULL, tmp);
							KSI_CATCH(&err, res) goto cleanup;
							tmp = NULL;
						}


					} else {
						res = template->toTlv(payloadp, template->tag, template->isNonCritical, template->isForward, &tmp);
						KSI_CATCH(&err, res) goto cleanup;
					}

					break;
				case KSI_TLV_TEMPLATE_COMPOSITE:
					res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, template->tag, template->isNonCritical, template->isForward, &tmp);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TLV_cast(tmp, KSI_TLV_PAYLOAD_TLV);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TlvTemplate_construct(ctx, tmp, payloadp, template->subTemplate);
					KSI_CATCH(&err, res) goto cleanup;

					break;
				case KSI_TLV_TEMPLATE_CALLBACK:
					if (template->callbackEncode != NULL) {
						res = template->callbackEncode(ctx, tlv, payload, template);
						KSI_CATCH(&err, res) goto cleanup;
					}
					break;
				default:
					KSI_LOG_error(ctx, "Unimplemented template type: %d", template->type);
					KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Unimplemented template type.");
					goto cleanup;
			}

			if (tmp != NULL) {
				res = KSI_TLV_appendNestedTlv(tlv, NULL, tmp);
				KSI_CATCH(&err, res) goto cleanup;
			}
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

int KSI_TlvTemplate_deepCopy(KSI_CTX *ctx, const void *from, const KSI_TlvTemplate *baseTemplate, void *to) {
	KSI_ERR err;
	KSI_TLV *tmpTlv = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, from != NULL) goto cleanup;
	KSI_PRE(&err, baseTemplate != NULL) goto cleanup;
	KSI_PRE(&err, to != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	/* Create a dummy TLV */
	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, 0x0, 0, 0, &tmpTlv);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create a TLV object */
	res = KSI_TlvTemplate_construct(ctx, tmpTlv, from, baseTemplate);
	KSI_CATCH(&err, res) goto cleanup;

	/* Evaluate the cloned object */
	res = KSI_TlvTemplate_extract(ctx, to, tmpTlv, baseTemplate, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmpTlv);

	return KSI_RETURN(&err);
}
