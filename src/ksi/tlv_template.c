#include <limits.h>
#include "internal.h"


#define KSI_CalAuthRecPKISignedData_new KSI_PKISignedData_new
#define KSI_CalAuthRecPKISignedData_free KSI_PKISignedData_free

#define KSI_AggrAuthRecPKISignedData_new KSI_PKISignedData_new
#define KSI_AggrAuthRecPKISignedData_free KSI_PKISignedData_free

#define FLAGSET(tmpl, flg) (((tmpl).flags & flg) != 0)

KSI_DEFINE_TLV_TEMPLATE(KSI_CalAuthRecPKISignedData)
	KSI_TLV_OCTET_STRING(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PKISignedData_getSignatureValue, KSI_PKISignedData_setSignatureValue)
	KSI_TLV_OCTET_STRING(0x03, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PKISignedData_getCertId, KSI_PKISignedData_setCertId)
	KSI_TLV_UTF8_STRING(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_PKISignedData_getCertRepositoryUri, KSI_PKISignedData_setCertRepositoryUri)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggrAuthRecPKISignedData)
	KSI_TLV_OCTET_STRING(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PKISignedData_getSignatureValue, KSI_PKISignedData_setSignatureValue)
	KSI_TLV_OBJECT(0x02, KSI_TLV_TMPL_FLG_NONE, KSI_PKISignedData_setCertificate, KSI_PKISignedData_getCertificate, KSI_PKICertificate_fromTlv, KSI_PKICertificate_toTlv, KSI_PKISignature_free)
	KSI_TLV_OCTET_STRING(0x03, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PKISignedData_getCertId, KSI_PKISignedData_setCertId)
	KSI_TLV_UTF8_STRING(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_PKISignedData_getCertRepositoryUri, KSI_PKISignedData_setCertRepositoryUri)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationsHeader)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationsHeader_getVersion, KSI_PublicationsHeader_setVersion)
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationsHeader_getTimeCreated, KSI_PublicationsHeader_setTimeCreated)
	KSI_TLV_UTF8_STRING(0x03, KSI_TLV_TMPL_FLG_NONE, KSI_PublicationsHeader_getRepositoryUri, KSI_PublicationsHeader_setRepositoryUri)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_CertificateRecord)
	KSI_TLV_OCTET_STRING(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_CertificateRecord_getCertId, KSI_CertificateRecord_setCertId)
	KSI_TLV_OBJECT(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_CertificateRecord_getCert, KSI_CertificateRecord_setCert, KSI_PKICertificate_fromTlv, KSI_PKICertificate_toTlv, KSI_PKICertificate_free)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationData)
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationData_getTime, KSI_PublicationData_setTime)
	KSI_TLV_IMPRINT(0x04, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationData_getImprint, KSI_PublicationData_setImprint)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationRecord)
	KSI_TLV_COMPOSITE(0x10, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationRecord_getPublishedData, KSI_PublicationRecord_setPublishedData, KSI_PublicationData)
	KSI_TLV_UTF8_STRING_LIST(0x09, KSI_TLV_TMPL_FLG_NONE, KSI_PublicationRecord_getPublicationRefList, KSI_PublicationRecord_setPublicationRefList)
	KSI_TLV_UTF8_STRING_LIST(0x0a, KSI_TLV_TMPL_FLG_NONE, KSI_PublicationRecord_getRepositoryUriList, KSI_PublicationRecord_setRepositoryUriList)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_MetaData)
	KSI_TLV_UTF8_STRING(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_MetaData_getClientId, KSI_MetaData_setClientId)
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_MetaData_getMachineId, KSI_MetaData_setMachineId)
	KSI_TLV_INTEGER(0x03, KSI_TLV_TMPL_FLG_NONE, KSI_MetaData_getSequenceNr, KSI_MetaData_setSequenceNr)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_HashChainLink)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_NONE, KSI_HashChainLink_getLevelCorrection, KSI_HashChainLink_setLevelCorrection)
	KSI_TLV_IMPRINT(0x02, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_HashChainLink_getImprint, KSI_HashChainLink_setImprint)
	KSI_TLV_META_IMPRINT(0x03, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_HashChainLink_getMetaHash, KSI_HashChainLink_setMetaHash)
	KSI_TLV_COMPOSITE(0x04, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_HashChainLink_getMetaData, KSI_HashChainLink_setMetaData, KSI_MetaData)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_Header)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_NONE, KSI_Header_getInstanceId, KSI_Header_setInstanceId)
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_NONE, KSI_Header_getMessageId, KSI_Header_setMessageId) /* Should be mandatory. */
	KSI_TLV_OCTET_STRING(0x03, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Header_getClientId, KSI_Header_setClientId)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_Config)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Config_getMaxLevel, KSI_Config_setMaxLevel)
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Config_getAggrAlgo, KSI_Config_setAggrAlgo)
	KSI_TLV_INTEGER(0x03, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Config_getAggrPeriod, KSI_Config_setAggrPeriod)
	KSI_TLV_UTF8_STRING_LIST(0x04, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Config_getParentUri, KSI_Config_setParentUri)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationHashChain)
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationHashChain_getAggregationTime, KSI_AggregationHashChain_setAggregationTime)
	KSI_TLV_INTEGER_LIST(0x03, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationHashChain_getChainIndex, KSI_AggregationHashChain_setChainIndex)
	KSI_TLV_OCTET_STRING(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationHashChain_getInputData, KSI_AggregationHashChain_setInputData)
	KSI_TLV_IMPRINT(0x05, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationHashChain_getInputHash, KSI_AggregationHashChain_setInputHash)
	KSI_TLV_INTEGER(0x06, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationHashChain_getAggrHashId, KSI_AggregationHashChain_setAggrHashId)
	KSI_TLV_OBJECT_LIST(0x07, KSI_TLV_TMPL_FLG_LEAST_ONE_G0, KSI_AggregationHashChain_getChain, KSI_AggregationHashChain_setChain, KSI_HashChainLink)
	KSI_TLV_OBJECT_LIST(0x08, KSI_TLV_TMPL_FLG_LEAST_ONE_G0 | KSI_TLV_TMPL_FLG_NO_SERIALIZE, KSI_AggregationHashChain_getChain, KSI_AggregationHashChain_setChain, KSI_HashChainLink)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationAuthRec)
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationAuthRec_getAggregationTime, KSI_AggregationAuthRec_setAggregationTime)
	KSI_TLV_INTEGER_LIST(0x04, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationAuthRec_getChainIndex, KSI_AggregationAuthRec_setChainIndex)
	KSI_TLV_IMPRINT(0x05, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationAuthRec_getInputHash, KSI_AggregationAuthRec_setInputHash)
	KSI_TLV_UTF8_STRING(0x0b, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationAuthRec_getSigAlgo, KSI_AggregationAuthRec_setSigAlgo)
	KSI_TLV_COMPOSITE(0x0c, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationAuthRec_getSigData, KSI_AggregationAuthRec_setSigData, KSI_AggrAuthRecPKISignedData)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_CalendarAuthRec)
	KSI_TLV_COMPOSITE(0x10, KSI_TLV_TMPL_FLG_FORWARD | KSI_TLV_TMPL_FLG_MANDATORY | KSI_TLV_TMPL_FLG_MORE_DEFS, KSI_CalendarAuthRec_getPublishedData, KSI_CalendarAuthRec_setPublishedData, KSI_PublicationData)
	KSI_TLV_UNPROCESSED(0x10, KSI_CalendarAuthRec_setSignedData)
	KSI_TLV_UTF8_STRING(0x0b, KSI_TLV_TMPL_FLG_MANDATORY, KSI_CalendarAuthRec_getSignatureAlgo, KSI_CalendarAuthRec_setSignatureAlgo)
	KSI_TLV_COMPOSITE(0x0c, KSI_TLV_TMPL_FLG_MANDATORY, KSI_CalendarAuthRec_getSignatureData, KSI_CalendarAuthRec_setSignatureData, KSI_CalAuthRecPKISignedData)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationReq)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationReq_getRequestId, KSI_AggregationReq_setRequestId)
	KSI_TLV_IMPRINT(0x02, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationReq_getRequestHash, KSI_AggregationReq_setRequestHash)
	KSI_TLV_INTEGER(0x03, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationReq_getRequestLevel, KSI_AggregationReq_setRequestLevel)
	KSI_TLV_COMPOSITE(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationReq_getConfig, KSI_AggregationReq_setConfig, KSI_Config)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_RequestAck)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RequestAck_getAggregationPeriod, KSI_RequestAck_setAggregationPeriod)
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RequestAck_getAggregationDelay, KSI_RequestAck_setAggregationDelay)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_CalendarHashChain)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_CalendarHashChain_getPublicationTime, KSI_CalendarHashChain_setPublicationTime)
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_NONE, KSI_CalendarHashChain_getAggregationTime, KSI_CalendarHashChain_setAggregationTime)
	KSI_TLV_IMPRINT(0x05, KSI_TLV_TMPL_FLG_MANDATORY, KSI_CalendarHashChain_getInputHash, KSI_CalendarHashChain_setInputHash)
	KSI_TLV_OBJECT_LIST(0x07, KSI_TLV_TMPL_FLG_LEAST_ONE_G0, KSI_CalendarHashChain_getHashChain, KSI_CalendarHashChain_setHashChain, KSI_CalendarHashChainLink)
	KSI_TLV_OBJECT_LIST(0x08, KSI_TLV_TMPL_FLG_LEAST_ONE_G0 | KSI_TLV_TMPL_FLG_NO_SERIALIZE, KSI_CalendarHashChain_getHashChain, KSI_CalendarHashChain_setHashChain, KSI_CalendarHashChainLink)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationResp)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getRequestId, KSI_AggregationResp_setRequestId)
	KSI_TLV_INTEGER(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getStatus, KSI_AggregationResp_setStatus)
	KSI_TLV_UTF8_STRING(0x05, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getErrorMsg, KSI_AggregationResp_setErrorMsg)
	KSI_TLV_COMPOSITE(0x10, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getConfig, KSI_AggregationResp_setConfig, KSI_Config)
	KSI_TLV_COMPOSITE(0x11, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getRequestAck, KSI_AggregationResp_setRequestAck, KSI_RequestAck)
	KSI_TLV_COMPOSITE_LIST(0x0801, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getAggregationChainList, KSI_AggregationResp_setAggregationChainList, KSI_AggregationHashChain)
	KSI_TLV_COMPOSITE(0x0802, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getCalendarChain, KSI_AggregationResp_setCalendarChain, KSI_CalendarHashChain)
	KSI_TLV_COMPOSITE(0x0804, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getAggregationAuthRec, KSI_AggregationResp_setAggregationAuthRec, KSI_AggregationAuthRec) /* TODO! Future work. */
	KSI_TLV_COMPOSITE(0x0805, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getCalendarAuthRec, KSI_AggregationResp_setCalendarAuthRec, KSI_CalendarAuthRec)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationPdu)
	KSI_TLV_COMPOSITE(0x01, KSI_TLV_TMPL_FLG_MANDATORY | KSI_TLV_TMPL_FLG_MORE_DEFS, KSI_AggregationPdu_getHeader, KSI_AggregationPdu_setHeader, KSI_Header)
	KSI_TLV_UNPROCESSED(0x1, KSI_AggregationPdu_setHeaderTlv)
	KSI_TLV_COMPOSITE(0x201, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0 | KSI_TLV_TMPL_FLG_MORE_DEFS, KSI_AggregationPdu_getRequest, KSI_AggregationPdu_setRequest, KSI_AggregationReq)
	KSI_TLV_UNPROCESSED(0x201, KSI_AggregationPdu_setPayloadTlv)
	KSI_TLV_COMPOSITE(0x202, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0 | KSI_TLV_TMPL_FLG_MORE_DEFS, KSI_AggregationPdu_getResponse, KSI_AggregationPdu_setResponse, KSI_AggregationResp)
	KSI_TLV_UNPROCESSED(0x202, KSI_AggregationPdu_setPayloadTlv)
	KSI_TLV_IMPRINT(0x1F, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationPdu_getHmac, KSI_AggregationPdu_setHmac)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_ExtendReq)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_ExtendReq_getRequestId, KSI_ExtendReq_setRequestId)
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendReq_getAggregationTime, KSI_ExtendReq_setAggregationTime)
	KSI_TLV_INTEGER(0x03, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendReq_getPublicationTime, KSI_ExtendReq_setPublicationTime)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_ExtendResp)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendResp_getRequestId, KSI_ExtendResp_setRequestId)
	KSI_TLV_INTEGER(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendResp_getStatus, KSI_ExtendResp_setStatus)
	KSI_TLV_UTF8_STRING(0x05, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendResp_getErrorMsg, KSI_ExtendResp_setErrorMsg)
	KSI_TLV_INTEGER(0x10, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendResp_getLastTime, KSI_ExtendResp_setLastTime)
	KSI_TLV_COMPOSITE(0x802, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendResp_getCalendarHashChain, KSI_ExtendResp_setCalendarHashChain, KSI_CalendarHashChain)
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_ExtendPdu)
	KSI_TLV_COMPOSITE(0x01, KSI_TLV_TMPL_FLG_MANDATORY | KSI_TLV_TMPL_FLG_MORE_DEFS, KSI_ExtendPdu_getHeader, KSI_ExtendPdu_setHeader, KSI_Header)
	KSI_TLV_UNPROCESSED(0x1, KSI_ExtendPdu_setHeaderTlv)
	KSI_TLV_COMPOSITE(0x301, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0 | KSI_TLV_TMPL_FLG_MORE_DEFS, KSI_ExtendPdu_getRequest, KSI_ExtendPdu_setRequest, KSI_ExtendReq)
	KSI_TLV_UNPROCESSED(0x301, KSI_ExtendPdu_setPayloadTlv)
	KSI_TLV_COMPOSITE(0x302, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0 | KSI_TLV_TMPL_FLG_MORE_DEFS, KSI_ExtendPdu_getResponse, KSI_ExtendPdu_setResponse, KSI_ExtendResp)
	KSI_TLV_UNPROCESSED(0x302, KSI_ExtendPdu_setPayloadTlv)
	KSI_TLV_IMPRINT(0x1F, KSI_TLV_TMPL_FLG_MANDATORY, KSI_ExtendPdu_getHmac, KSI_ExtendPdu_setHmac)
KSI_END_TLV_TEMPLATE

static int storeObjectValue(KSI_CTX *ctx, const KSI_TlvTemplate *tmpl, void *payload, void *val) {
	KSI_ERR err;
	int res;
	void *list = NULL;
	void *listp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tmpl != NULL) goto cleanup;
	KSI_PRE(&err, payload != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (tmpl->listAppend != NULL) {
		res = tmpl->getValue(payload, &listp);
		if (res != KSI_OK) goto cleanup;
		
		if (listp == NULL) {
			/* Make sure we have required function pointers. */
			if (tmpl->listNew == NULL || tmpl->listFree == NULL) {
				KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Template does not have list constructor or destructor, but list itself does not exist.");
				goto cleanup;
			}
			res = tmpl->listNew(ctx, &list);
			KSI_CATCH(&err, res) goto cleanup;

			listp = list;
		}
		
		res = tmpl->listAppend(listp, (void *) val);
		KSI_CATCH(&err, res) goto cleanup;
		
		res = tmpl->setValue(payload, listp);
		KSI_CATCH(&err, res) goto cleanup;

		list = NULL;

	} else {
		/* Regular value - store with the setter. */
		res = tmpl->setValue(payload, (void *) val);
		KSI_CATCH(&err, res) goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(listp);
	if (tmpl->listFree != NULL) tmpl->listFree(list);

	return KSI_RETURN(&err);
}

typedef struct TLVListIterator_st {
	KSI_LIST(KSI_TLV) *list;
	size_t idx;
} TLVListIterator;

static int TLVListIterator_next(TLVListIterator *iter, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *next = NULL;

	if (iter == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (iter->idx < KSI_TLVList_length(iter->list)) {
		res = KSI_TLVList_elementAt(iter->list, iter->idx, &next);
		if (res != KSI_OK) goto cleanup;

		iter->idx++;
	}

	*tlv = next;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_TlvTemplate_extract(KSI_CTX *ctx, void *payload, KSI_TLV *tlv, const KSI_TlvTemplate *tmpl) {
	KSI_ERR err;
	int res;
	TLVListIterator iter;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_TLV);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_getNestedList(tlv, &iter.list);
	KSI_CATCH(&err, res) goto cleanup;

	iter.idx = 0;

	res = KSI_TlvTemplate_extractGenerator(ctx, payload, (void *)&iter, tmpl, (int (*)(void *, KSI_TLV **))TLVListIterator_next);
	KSI_CATCH(&err, res) {
		KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Parsed tlv before failure", tlv);
		goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);

}

int KSI_TlvTemplate_parse(KSI_CTX *ctx, unsigned char *raw, unsigned raw_len, const KSI_TlvTemplate *tmpl, void *payload) {
	KSI_ERR err;
	int res;
	KSI_TLV *tlv = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len > 0) goto cleanup;
	KSI_PRE(&err, tmpl != NULL) goto cleanup;
	KSI_PRE(&err, payload != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_parseBlob2(ctx, raw, raw_len, 0, &tlv);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_extract(ctx, payload, tlv, tmpl);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Parsed TLV", tlv);

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tlv);

	return KSI_RETURN(&err);
}

static size_t getTemplateLength(const KSI_TlvTemplate *tmpl) {
	const KSI_TlvTemplate *tmp = NULL;
	size_t len = 0;

	/* Count the number of templates. */
	tmp = tmpl;
	while (tmp != NULL && tmp++->tag) ++len;

	return len;
}

int KSI_TlvTemplate_extractGenerator(KSI_CTX *ctx, void *payload, void *generatorCtx, const KSI_TlvTemplate *tmpl, int (*generator)(void *, KSI_TLV **)) {
	KSI_ERR err;
	KSI_TLV *tlv = NULL;
	int res;

	KSI_uint64_t uint64Val = 0;
	void *voidVal = NULL;
	int intVal = 0;
	void *compositeVal = NULL;
	void *valuep = NULL;
	KSI_TLV *tlvVal = NULL;

	size_t template_len = 0;
	bool *templateHit = NULL;
	bool groupHit[2] = {false, false};
	bool oneOf[2] = {false, false};
	size_t i;
	size_t tmplStart = 0;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	template_len = getTemplateLength(tmpl);

	/* Create the hit buffer with all values set to zero. */
	if (template_len > 0) {
		templateHit = KSI_calloc(template_len, sizeof(bool));
	}

	while (1) {
		int matchCount = 0;
		res = generator(generatorCtx, &tlv);
		KSI_CATCH(&err, res) goto cleanup;

		if (tlv == NULL) break;

		KSI_LOG_trace(ctx, "Starting to parse TLV(0x%02x)", KSI_TLV_getTag(tlv));

		for (i = tmplStart; i < template_len; i++) {
			if (tmpl[i].tag != KSI_TLV_getTag(tlv)) continue;
			if (i == tmplStart && !tmpl[i].multiple) tmplStart++;
			matchCount++;
			templateHit[i] = true;
			if ((tmpl[i].flags & KSI_TLV_TMPL_FLG_LEAST_ONE_G0) != 0) groupHit[0] = true;
			if ((tmpl[i].flags & KSI_TLV_TMPL_FLG_LEAST_ONE_G1) != 0) groupHit[1] = true;

			if (FLAGSET(tmpl[i], KSI_TLV_TMPL_FLG_MOST_ONE_G0)) {
				if (oneOf[0]) {
					KSI_FAIL(&err, KSI_INVALID_FORMAT, "Mutually exclusive elements present within group 0.");
					goto cleanup;
				}
				oneOf[0] = true;
			}

			if (FLAGSET(tmpl[i], KSI_TLV_TMPL_FLG_MOST_ONE_G1)) {
				if (oneOf[1]) {
					KSI_FAIL(&err, KSI_INVALID_FORMAT, "Mutually exclusive elements present within group 0.");
					goto cleanup;
				}
				oneOf[1] = true;
			}

			valuep = NULL;
			if (tmpl[i].getValue != NULL) {
				/* Validate the value has not been set */
				res = tmpl[i].getValue(payload, (void **)&valuep);
				KSI_CATCH(&err, res) goto cleanup;
			}

			if (valuep != NULL && !tmpl[i].multiple) {
				compositeVal = NULL;
				KSI_LOG_error(ctx, "Multiple occurrances of a unique tag 0x%02x", tmpl[i].tag);
				KSI_FAIL(&err, KSI_INVALID_FORMAT, "To avoid memory leaks, a value may not be set more than once while parsing.");
				goto cleanup;
			}
			/* Parse the current TLV */
			switch (tmpl[i].type) {
				case KSI_TLV_TEMPLATE_SEEK_POS:
					uint64Val = (KSI_uint64_t)KSI_TLV_getAbsoluteOffset(tlv);

					res = ((int (*)(void *, KSI_uint64_t))tmpl[i].setValue)(payload, uint64Val);
					KSI_CATCH(&err, res) goto cleanup;

					break;
				case KSI_TLV_TEMPLATE_UNPROCESSED:
					res = KSI_TLV_clone(tlv, &tlvVal);
					KSI_CATCH(&err, res) goto cleanup;

					res = storeObjectValue(ctx, &tmpl[i], payload, tlvVal);
					KSI_CATCH(&err, res) goto cleanup;

					tlvVal = NULL;

					break;
				case KSI_TLV_TEMPLATE_OBJECT:
					if (tmpl[i].fromTlv == NULL) {
						KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Invalid template: fromTlv not set.");
						goto cleanup;
					}

					res = tmpl[i].fromTlv(tlv, &voidVal);
					KSI_CATCH(&err, res) goto cleanup;

					res = storeObjectValue(ctx, &tmpl[i], payload, voidVal);
					KSI_CATCH(&err, res) {
						tmpl[i].destruct(voidVal);
						goto cleanup;
					}

					break;
				case KSI_TLV_TEMPLATE_COMPOSITE:
					KSI_LOG_trace(ctx, "Detected composite template for TLV value extraction.");

					res = tmpl[i].construct(ctx, &compositeVal);
					KSI_CATCH(&err, res) goto cleanup;

					res = KSI_TlvTemplate_extract(ctx, compositeVal, tlv, tmpl[i].subTemplate);
					KSI_CATCH(&err, res) {
						KSI_LOG_error(ctx, "Unable to parse composite TLV: 0x%02x", KSI_TLV_getTag(tlv));
						tmpl[i].destruct(compositeVal);
						goto cleanup;
					}

					res = storeObjectValue(ctx, &tmpl[i], payload, (void *)compositeVal);
					KSI_CATCH(&err, res) goto cleanup;

					KSI_LOG_trace(ctx, "Composite value extracted.");
					break;
				default:
					KSI_LOG_warn(ctx, "No template found.");
					/* Should not happen, but just in case. */
					KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Undefined template type");
					goto cleanup;
			}

			if ((tmpl[i].flags & KSI_TLV_TMPL_FLG_MORE_DEFS) == 0) break;
		}

		/* Check if a match was found, an raise an error if the TLV is marked as critical. */
		if(matchCount == 0 && !KSI_TLV_isNonCritical(tlv)) {
			KSI_LOG_error(ctx, "Unknown critical tag: 0x%02x", KSI_TLV_getTag(tlv));
			KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
			goto cleanup;
		}
	}

	/* Check that every mandatory component was present. */
	for (i = 0; i < template_len; i++) {
		char errm[100];
		if ((tmpl[i].flags & KSI_TLV_TMPL_FLG_MANDATORY) != 0 && !templateHit[i]) {
			snprintf(errm, sizeof(errm), "Mandatory element missing: tag=0x%x", tmpl[i].tag);
			KSI_FAIL(&err, KSI_INVALID_FORMAT, errm);
			goto cleanup;
		}
		if (((tmpl[i].flags & KSI_TLV_TMPL_FLG_LEAST_ONE_G0) != 0 && !groupHit[0]) ||
				((tmpl[i].flags & KSI_TLV_TMPL_FLG_LEAST_ONE_G1) != 0 && !groupHit[1])) {
			snprintf(errm, sizeof(errm), "Mandatory group missing: tag=0x%x", tmpl[i].tag);
			KSI_FAIL(&err, KSI_INVALID_FORMAT, errm);
			goto cleanup;
		}

	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(templateHit);
	KSI_TLV_free(tlvVal);

	return KSI_RETURN(&err);
}

int KSI_TlvTemplate_construct(KSI_CTX *ctx, KSI_TLV *tlv, const void *payload, const KSI_TlvTemplate *tmpl) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;
	void *payloadp = NULL;
	int isNonCritical = 0;
	int isForward = 0;

	size_t template_len = 0;
	bool *templateHit = NULL;
	bool groupHit[2] = {false, false};
	bool oneOf[2] = {false, false};

	int i;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, tmpl != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	template_len = getTemplateLength(tmpl);

	if (template_len > 0) {
		templateHit = KSI_calloc(template_len, sizeof(bool));
	}

	for(i = 0; i < template_len; i++) {
		if ((tmpl[i].flags & KSI_TLV_TMPL_FLG_NO_SERIALIZE) != 0) continue;
		payloadp = NULL;
		res = tmpl[i].getValue(payload, &payloadp);
		KSI_CATCH(&err, res) goto cleanup;
		if (payloadp != NULL) {
			templateHit[i] = true;

			if ((tmpl[i].flags & KSI_TLV_TMPL_FLG_LEAST_ONE_G0) != 0) groupHit[0] = true;
			if ((tmpl[i].flags & KSI_TLV_TMPL_FLG_LEAST_ONE_G1) != 0) groupHit[1] = true;
			if (FLAGSET(tmpl[i], KSI_TLV_TMPL_FLG_MOST_ONE_G0)) {
				if (oneOf[0]) {
					KSI_FAIL(&err, KSI_INVALID_FORMAT, "Mutually exclusive elements present within group 0.");
				}
				oneOf[0] = true;
			}
			if (FLAGSET(tmpl[i], KSI_TLV_TMPL_FLG_MOST_ONE_G1)) {
				if (oneOf[1]) {
					KSI_FAIL(&err, KSI_INVALID_FORMAT, "Mutually exclusive elements present within group 0.");
				}
				oneOf[1] = true;
			}

			isNonCritical = (tmpl[i].flags & KSI_TLV_TMPL_FLG_NONCRITICAL) != 0;
			isForward = (tmpl[i].flags & KSI_TLV_TMPL_FLG_FORWARD) != 0;

			switch (tmpl[i].type) {
				case KSI_TLV_TEMPLATE_OBJECT:
					if (tmpl[i].toTlv == NULL) {
						KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Invalid template: toTlv not set.");
						goto cleanup;
					}

					if (tmpl[i].listLength != NULL) {
						int j;
						for (j = 0; j < tmpl[i].listLength(payloadp); j++) {
							void *listElement = NULL;
							res = tmpl[i].listElementAt(payloadp, j, &listElement);
							KSI_CATCH(&err, res) goto cleanup;

							res = tmpl[i].toTlv(ctx, listElement, tmpl[i].tag, isNonCritical, isForward != 0, &tmp);
							KSI_CATCH(&err, res) goto cleanup;

							res = KSI_TLV_appendNestedTlv(tlv, NULL, tmp);
							KSI_CATCH(&err, res) goto cleanup;
							tmp = NULL;
						}


					} else {
						res = tmpl[i].toTlv(ctx, payloadp, tmpl[i].tag, isNonCritical, isForward, &tmp);
						KSI_CATCH(&err, res) goto cleanup;

						res = KSI_TLV_appendNestedTlv(tlv, NULL, tmp);
						KSI_CATCH(&err, res) goto cleanup;
						tmp = NULL;
					}

					break;
				case KSI_TLV_TEMPLATE_COMPOSITE:
					if (tmpl[i].listLength != NULL) {
						int j;
						for (j = 0; j < tmpl[i].listLength(payloadp); j++) {
							void *listElement = NULL;

							res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, tmpl[i].tag, isNonCritical, isForward, &tmp);
							KSI_CATCH(&err, res) goto cleanup;

							res = tmpl[i].listElementAt(payloadp, j, &listElement);
							KSI_CATCH(&err, res) goto cleanup;

							res = KSI_TlvTemplate_construct(ctx, tmp, listElement, tmpl[i].subTemplate);
							KSI_CATCH(&err, res) goto cleanup;

							res = KSI_TLV_appendNestedTlv(tlv, NULL, tmp);
							KSI_CATCH(&err, res) goto cleanup;
							tmp = NULL;
						}
					} else {
						res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, tmpl[i].tag, isNonCritical, isForward, &tmp);
						KSI_CATCH(&err, res) goto cleanup;

						res = KSI_TlvTemplate_construct(ctx, tmp, payloadp, tmpl[i].subTemplate);
						KSI_CATCH(&err, res) goto cleanup;

						res = KSI_TLV_appendNestedTlv(tlv, NULL, tmp);
						KSI_CATCH(&err, res) goto cleanup;
						tmp = NULL;
					}
					break;
				default:
					KSI_LOG_error(ctx, "Unimplemented template type: %d", tmpl[i].type);
					KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Unimplemented template type.");
					goto cleanup;
			}
		}
	}

	/* Check that every mandatory component was present. */
	for (i = 0; i < template_len; i++) {
		char errm[100];
		if ((tmpl[i].flags & KSI_TLV_TMPL_FLG_MANDATORY) != 0 && !templateHit[i]) {
			snprintf(errm, sizeof(errm), "Mandatory element missing: tag=0x%x", tmpl[i].tag);
			KSI_FAIL(&err, KSI_INVALID_FORMAT, errm);
			goto cleanup;
		}
		if (((tmpl[i].flags & KSI_TLV_TMPL_FLG_LEAST_ONE_G0) != 0 && !groupHit[0]) ||
				((tmpl[i].flags & KSI_TLV_TMPL_FLG_LEAST_ONE_G1) != 0 && !groupHit[1])) {
			snprintf(errm, sizeof(errm), "Mandatory group missing: tag=0x%x", tmpl[i].tag);
			KSI_FAIL(&err, KSI_INVALID_FORMAT, errm);
			goto cleanup;
		}
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(payloadp);

	KSI_free(templateHit);
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
	res = KSI_TlvTemplate_extract(ctx, to, tmpTlv, baseTemplate);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmpTlv);

	return KSI_RETURN(&err);
}

int KSI_TlvTemplate_serializeObject(KSI_CTX *ctx, const void *obj, unsigned tag, int isNc, int isFwd, const KSI_TlvTemplate *tmpl, unsigned char **raw, unsigned *raw_len) {
	KSI_ERR err;
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char *tmp = NULL;
	unsigned tmp_len = 0;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, obj != NULL) goto cleanup;
	KSI_PRE(&err, tmpl != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	/* Create TLV for the PDU object. */
	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, tag, isFwd, isNc, &tlv);
	KSI_CATCH(&err, res) goto cleanup;

	/* Evaluate the TLV. */
	res = KSI_TlvTemplate_construct(ctx, tlv, obj, tmpl);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Serializing object", tlv);

	/* Serialize the TLV. */
	res = KSI_TLV_serialize(tlv, &tmp, &tmp_len);
	KSI_CATCH(&err, res) goto cleanup;

	*raw = tmp;
	tmp = NULL;
	*raw_len = tmp_len;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp);
	KSI_TLV_free(tlv);

	return KSI_RETURN(&err);
}
