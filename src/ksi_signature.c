#include <string.h>

#include "ksi_internal.h"
#include "ksi_tlv_easy.h"

typedef struct aggrChainRec_st AggrChainRec;
typedef struct headerRec_st HeaderRec;
typedef struct calAuthRec_st CalAuthRec;
typedef struct aggrAuthRec_st AggrAuthRec;
typedef struct pubDataRec_st PubDataRec;

KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarHashChain);
KSI_IMPORT_TLV_TEMPLATE(KSI_HashChainLink);
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_PKISignedData);

KSI_DEFINE_LIST(AggrChainRec);

struct calAuthRec_st {
	KSI_CTX *ctx;

	PubDataRec *pubData;
	char *sigAlgo;
	KSI_PKISignedData *sigData;
};

struct aggrAuthRec_st {
	KSI_CTX *ctx;
	KSI_Integer *aggregationTime;
	KSI_LIST(KSI_Integer) *chainIndexesList;
	KSI_DataHash *intputHash;

	char *sigAlgo;

	KSI_PKISignedData *sigData;
};

struct pubDataRec_st {
	KSI_CTX *ctx;
	unsigned char *raw;
	int raw_len;
	KSI_Integer *pubTime;
	KSI_DataHash *pubHash;
};

struct sigDataRec_st {
	KSI_CTX *ctx;

	unsigned char *sigValue;
	int sigValue_len;

	unsigned char *cert;
	int cert_len;

	KSI_OctetString *certId;

	char *certRepUri;
};

struct aggrChainRec_st {
	KSI_CTX *ctx;
	KSI_Integer *aggregationTime;
	KSI_LIST(KSI_Integer) *chainIndex;
	unsigned char *inputData;
	int inputData_len;
	KSI_DataHash *inputHash;
	int aggrHashId;
	KSI_LIST(KSI_HashChainLink) *chain;
};

struct calChainRec_st {
	KSI_Integer *publicationTime;
	KSI_Integer *aggregationTime;
	KSI_DataHash *inputHash;
	KSI_LIST(KSI_HashChainLink) *chain;
};

struct headerRec_st {
	KSI_CTX *ctx;
	KSI_Integer *instanceId;
	KSI_Integer *messageId;
	unsigned char *clientId;
	int clientId_length;
};

/**
 * KSI Signature object
 */
struct KSI_Signature_st {
	KSI_CTX *ctx;

	/* Base TLV - when serialized, this value will be used. */
	KSI_TLV *baseTlv;

	KSI_CalendarHashChain *calendarChain;

	KSI_LIST(AggrChainRec) *aggregationChainList;

	CalAuthRec *calAuth;
	AggrAuthRec *aggrAuth;
	KSI_PublicationRecord *publication;

};

static void PubDataRec_free (PubDataRec *pdc) {
	if (pdc != NULL) {
		KSI_free(pdc->raw);
		KSI_Integer_free(pdc->pubTime);
		KSI_DataHash_free(pdc->pubHash);
		KSI_free(pdc);
	}
}

static void AggrAuthRec_free(AggrAuthRec *aar) {
	if (aar != NULL) {
		KSI_Integer_free(aar->aggregationTime);
		KSI_IntegerList_free(aar->chainIndexesList);
		KSI_DataHash_free(aar->intputHash);
		KSI_free(aar->sigAlgo);
		KSI_PKISignedData_free(aar->sigData);
		KSI_free(aar);
	}
}

static void CalAuthRec_free(CalAuthRec *calAuth) {
	if (calAuth != NULL) {
		PubDataRec_free(calAuth->pubData);
		KSI_free(calAuth->sigAlgo);
		KSI_PKISignedData_free(calAuth->sigData);

		KSI_free(calAuth);
	}
}

static void HeaderRec_free(HeaderRec *hdr) {
	if (hdr != NULL) {
		KSI_Integer_free(hdr->instanceId);
		KSI_Integer_free(hdr->messageId);
		KSI_free(hdr->clientId);
		KSI_free(hdr);
	}
}

static void AggrChainRec_free(AggrChainRec *aggr) {
	if (aggr != NULL) {
		KSI_Integer_free(aggr->aggregationTime);
		KSI_IntegerList_free(aggr->chainIndex);
		KSI_free(aggr->inputData);
		KSI_DataHash_free(aggr->inputHash);
		KSI_HashChainLinkList_free(aggr->chain);
		KSI_free(aggr);
	}
}

KSI_IMPLEMENT_LIST(AggrChainRec, AggrChainRec_free);

static int KSI_Signature_new(KSI_CTX *ctx, KSI_Signature **sig) {
	KSI_ERR err;
	int res;
	KSI_Signature *tmp = NULL;
	KSI_LIST(AggrChainRec) *list = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_Signature);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->calendarChain = NULL;
	tmp->baseTlv = NULL;
	tmp->publication = NULL;
	tmp->aggregationChainList = NULL;

	res = AggrChainRecList_new(ctx, &list);
	KSI_CATCH(&err, res) goto cleanup;

	tmp->aggregationChainList = list;

	*sig = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);

}

static int CalAuthRec_validate(KSI_CTX *ctx, CalAuthRec *calAuth) {
	KSI_ERR err;
	int res;
	KSI_PKICertificate *cert = NULL;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_OctetString *certId = NULL;
	KSI_OctetString *signatureValue = NULL;
	const unsigned char *raw = NULL;
	int raw_len = 0;

	KSI_PRE(&err, calAuth != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_PKISignedData_getCertId(calAuth->sigData, &certId);
	KSI_CATCH(&err, res) goto cleanup;

	if (certId == NULL) {
		res = KSI_PKISignedData_getCert(calAuth->sigData, &cert);
		KSI_CATCH(&err, res) goto cleanup;
	} else {
		res = KSI_receivePublicationsFile(ctx, &pubFile);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_PublicationsFile_getPKICertificateById(pubFile, certId, &cert);
		KSI_CATCH(&err, res) goto cleanup;
	}

	if (cert == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Unable to validate calendar auth record.");
		goto cleanup;
	}

	res = KSI_PKISignedData_getSignatureValue(calAuth->sigData, &signatureValue);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_OctetString_extract(signatureValue, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKITruststore_validateRawSignature(ctx, calAuth->pubData->raw, calAuth->pubData->raw_len, calAuth->sigAlgo, raw, raw_len, cert);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(cert);
	KSI_nofree(pubFile);
	KSI_nofree(certId);
	KSI_nofree(signatureValue);
	KSI_nofree(raw);

	return KSI_RETURN(&err);
}

static int HeaderRec_new(KSI_CTX *ctx, HeaderRec **hdr) {
	KSI_ERR err;
	HeaderRec *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(HeaderRec);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->clientId = NULL;
	tmp->clientId_length = 0;
	tmp->instanceId = NULL;
	tmp->messageId = NULL;

	*hdr = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	HeaderRec_free(tmp);

	return KSI_RETURN(&err);

}

static int AggChainRec_new(KSI_CTX *ctx, AggrChainRec **out) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	AggrChainRec *tmp = NULL;
	tmp = KSI_new(AggrChainRec);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->aggrHashId = 0;
	tmp->aggregationTime = NULL;
	tmp->chain = NULL;
	tmp->chainIndex = NULL;
	tmp->inputData = NULL;
	tmp->inputData_len = 0;
	tmp->inputHash = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	AggrChainRec_free(tmp);

	return KSI_RETURN(&err);
}

static int PubDataRed_new(KSI_CTX *ctx, PubDataRec **out) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	PubDataRec *tmp = NULL;
	tmp = KSI_new(PubDataRec);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->raw = NULL;
	tmp->pubHash = NULL;
	tmp->pubTime = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	PubDataRec_free(tmp);

	return KSI_RETURN(&err);

}

static int CalAuthRec_new(KSI_CTX *ctx, CalAuthRec **out) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	CalAuthRec *tmp = NULL;
	tmp = KSI_new(CalAuthRec);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->pubData = NULL;
	tmp->sigAlgo = NULL;
	tmp->sigData = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	CalAuthRec_free(tmp);

	return KSI_RETURN(&err);

}

static int AggrAuthRec_new(KSI_CTX *ctx, AggrAuthRec **out) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, out != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	AggrAuthRec *tmp = NULL;
	tmp = KSI_new(AggrAuthRec);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = KSI_IntegerList_new(ctx, &tmp->chainIndexesList);
	KSI_CATCH(&err, res) goto cleanup;

	tmp->intputHash = NULL;
	tmp->ctx = ctx;
	tmp->sigAlgo = NULL;
	tmp->sigData = NULL;
	tmp->aggregationTime = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	AggrAuthRec_free(tmp);

	return KSI_RETURN(&err);
}

static int AggrChainRec_addIndex(KSI_CTX *ctx, KSI_TLV *tlv, AggrChainRec *aggr) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *item = NULL;
	KSI_LIST(KSI_Integer) *list = NULL;

	if (aggr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	list = aggr->chainIndex;

	if (list == NULL) {
		res = KSI_IntegerList_new(ctx, &list);
	}

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_INT);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TLV_getInteger(tlv, &item);
	if (res != KSI_OK) goto cleanup;

	res = KSI_IntegerList_append(list, item);
	if (res != KSI_OK) goto cleanup;
	item = NULL;

	aggr->chainIndex = list;
	list = NULL;



cleanup:
	if (list != aggr->chainIndex) KSI_IntegerList_free(list);
	KSI_Integer_free(item);

	return res;
}

static int AggrChainRec_addLink(KSI_CTX *ctx, KSI_TLV *tlv, AggrChainRec *aggr) {
	KSI_ERR err;
	int res = KSI_UNKNOWN_ERROR;
	int isLeft;

	KSI_HashChainLink *link = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, aggr != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	switch (KSI_TLV_getTag(tlv)) {
		case 0x07:
			isLeft = 1;
			break;
		case 0x08:
			isLeft = 0;
			break;
		default:
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
			goto cleanup;
	}

	res = KSI_HashChainLink_new(ctx, &link);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChainLink_setIsLeft(link, isLeft);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_extract(ctx, link, tlv, KSI_TLV_TEMPLATE(KSI_HashChainLink), NULL);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create a new list of links if this is the first link. */
	if (aggr->chain == NULL) {
		res = KSI_HashChainLinkList_new(ctx, &aggr->chain);
		KSI_CATCH(&err, res) goto cleanup;
	}

	/* Append the link to the chain */
	res = KSI_HashChainLinkList_append(aggr->chain, link);
	KSI_CATCH(&err, res) goto cleanup;
	link = NULL;

	res = KSI_OK;

cleanup:

	KSI_HashChainLink_free(link);

	return res;
}

static int CalChainRec_addLink(KSI_CTX *ctx, KSI_TLV *tlv, KSI_CalendarHashChain *cal) {
	int res;
	KSI_DataHash *hsh = NULL;
	const unsigned char *imprint = NULL;
	int imprint_len = 0;
	int isLeft;
	KSI_LIST(KSI_HashChainLink) *chain = NULL;

	/* Validate arguments. */
	switch (KSI_TLV_getTag(tlv)) {
		case 0x07:
			isLeft = 1;
			break;
		case 0x08:
			isLeft = 0;
			break;
		default:
			res = KSI_INVALID_ARGUMENT;
			goto cleanup;
	}

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_RAW);
	if (res != KSI_OK) goto cleanup;

	/* Extract the raw value from the tlv */
	res = KSI_TLV_getRawValue(tlv, &imprint, &imprint_len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHash_fromImprint(ctx, imprint, imprint_len, &hsh);
	if (res != KSI_OK) goto cleanup;

	res = KSI_CalendarHashChain_getHashChain(cal, &chain);
	if (res != KSI_OK) goto cleanup;

	res = KSI_HashChain_appendLink(ctx, hsh, NULL, NULL, isLeft, 0, &chain);
	if (res != KSI_OK) goto cleanup;

	res = KSI_CalendarHashChain_setHashChain(cal, chain);
	if (res != KSI_OK) goto cleanup;

	hsh = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(imprint);
	KSI_DataHash_free(hsh);

	return res;
}

static int parseAggregationChainRec(KSI_CTX *ctx, KSI_TLV *tlv, KSI_Signature *sig) {
	KSI_ERR err;
	int res;

	AggrChainRec *aggr = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);


	if (KSI_TLV_getTag(tlv) != 0x0801) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = AggChainRec_new(ctx, &aggr);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_TLV_PARSE_BEGIN(ctx, tlv)
		KSI_PARSE_TLV_ELEMENT_INTEGER	(0x02, &aggr->aggregationTime)
		KSI_PARSE_TLV_ELEMENT_CB		(0x03, AggrChainRec_addIndex, aggr)
		KSI_PARSE_TLV_ELEMENT_RAW		(0x04, &aggr->inputData, &aggr->inputData_len)
		KSI_PARSE_TLV_ELEMENT_IMPRINT	(0x05, &aggr->inputHash)
		KSI_PARSE_TLV_ELEMENT_UINT8		(0x06, &aggr->aggrHashId)
		KSI_PARSE_TLV_ELEMENT_CB		(0x07, AggrChainRec_addLink, aggr)
		KSI_PARSE_TLV_ELEMENT_CB		(0x08, AggrChainRec_addLink, aggr)
		KSI_PARSE_TLV_ELEMENT_UNKNONW_NON_CRITICAL_IGNORE
	KSI_TLV_PARSE_END(res);
	KSI_CATCH(&err, res) goto cleanup;

	res = AggrChainRecList_append(sig->aggregationChainList, aggr);
	KSI_CATCH(&err, res) goto cleanup;

	aggr = NULL;

	KSI_SUCCESS(&err);

cleanup:

	AggrChainRec_free(aggr);

	return KSI_RETURN(&err);
}

static int parsePublDataRecord(KSI_CTX *ctx, KSI_TLV *tlv, PubDataRec **pdr) {
	KSI_ERR err;
	int res;
	PubDataRec *tmp = NULL;
	unsigned char *raw;
	int raw_len;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, pdr != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	res = PubDataRed_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;
	if (*pdr != NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Multiple publication data records.");
		goto cleanup;
	}

	/* Keep the serialized value. */
	res = KSI_TLV_serialize(tlv, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_TLV_PARSE_BEGIN(ctx, tlv)
		KSI_PARSE_TLV_ELEMENT_INTEGER(0x02, &tmp->pubTime)
		KSI_PARSE_TLV_ELEMENT_IMPRINT(0x04, &tmp->pubHash)
		KSI_PARSE_TLV_ELEMENT_UNKNONW_NON_CRITICAL_IGNORE
	KSI_TLV_PARSE_END(res);
	KSI_CATCH(&err, res) goto cleanup;;

	if (tmp->pubTime == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Published Data: Missing publication time.");
		goto cleanup;

	}

	if (tmp->pubHash == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Published Data: Missing publication hash.");
		goto cleanup;

	}

	tmp->raw = raw;
	tmp->raw_len = raw_len;
	raw = NULL;

	*pdr = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(raw);
	PubDataRec_free(tmp);

	return KSI_RETURN(&err);
}

static int parseSigDataRecord(KSI_CTX *ctx, KSI_TLV *tlv, KSI_PKISignedData **sdr) {
	KSI_ERR err;
	int res;
	KSI_PKISignedData *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, sdr != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	if (*sdr != NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Multiple signature data records.");
		goto cleanup;
	}

	res = KSI_PKISignedData_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_extract(ctx, tmp, tlv, KSI_TLV_TEMPLATE(KSI_PKISignedData), NULL);
	KSI_CATCH(&err, res) goto cleanup;

	*sdr = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_PKISignedData_free(tmp);

	return KSI_RETURN(&err);

}

static int parseAggrAuthRecChainIndex(KSI_CTX *ctx, KSI_TLV *tlv, AggrAuthRec **aar) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, aar != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	if (KSI_TLV_getTag(tlv) != 0x03)

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int parsePublication(KSI_CTX *ctx, KSI_TLV *tlv, KSI_PublicationRecord **pubRec) {
	KSI_ERR err;
	int res;
	KSI_PublicationRecord *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, pubRec != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_PublicationRecord_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_extract(ctx, tmp, tlv, KSI_TLV_TEMPLATE(KSI_PublicationRecord), NULL);
	KSI_CATCH(&err, res) goto cleanup;

	*pubRec = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_PublicationRecord_free(tmp);

	return KSI_RETURN(&err);

}

static int parseAggrAuthRec(KSI_CTX *ctx, KSI_TLV *tlv, AggrAuthRec **aar) {
	KSI_ERR err;
	int res;
	AggrAuthRec *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, aar != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = AggrAuthRec_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_TLV_PARSE_BEGIN(ctx, tlv)
		KSI_PARSE_TLV_ELEMENT_INTEGER(0x02, &tmp->aggregationTime)
		KSI_PARSE_TLV_ELEMENT_CB(0x03, parseAggrAuthRecChainIndex, &tmp)
		KSI_PARSE_TLV_ELEMENT_IMPRINT(0x05, &tmp->intputHash)

		KSI_PARSE_TLV_ELEMENT_UTF8STR(0x0b, &tmp->sigAlgo)

		KSI_PARSE_TLV_ELEMENT_CB(0x0c, parseSigDataRecord, &tmp->sigData)

		KSI_PARSE_TLV_ELEMENT_UNKNONW_NON_CRITICAL_IGNORE
	KSI_TLV_PARSE_END(res);

	*aar = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	AggrAuthRec_free(tmp);

	return KSI_RETURN(&err);
}

static int parseCalAuthRec(KSI_CTX *ctx, KSI_TLV *tlv, CalAuthRec **car) {
	KSI_ERR err;
	int res;
	CalAuthRec *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, car != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	if (*car != NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Multiple calendar auth records.");
		goto cleanup;
	}

	res = CalAuthRec_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_TLV_PARSE_BEGIN(ctx, tlv)
		KSI_PARSE_TLV_ELEMENT_CB(0x10, parsePublDataRecord, &tmp->pubData)
		KSI_PARSE_TLV_ELEMENT_UTF8STR(0x0b, &tmp->sigAlgo)
		KSI_PARSE_TLV_ELEMENT_CB(0x0c, parseSigDataRecord, &tmp->sigData)
		KSI_PARSE_TLV_ELEMENT_UNKNONW_NON_CRITICAL_IGNORE
	KSI_TLV_PARSE_END(res);
	KSI_CATCH(&err, res) goto cleanup;

	/* Check mandatory parameters. */
	if (tmp->pubData == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Calendar Auth Record: Missing publication data.");
		goto cleanup;
	}

	if (tmp->sigAlgo == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Calendar Auth Record: Missing algorithm.");
		goto cleanup;
	}

	if (tmp->sigData == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Calendar Auth Record: Missing signed data.");
		goto cleanup;
	}

	*car = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	CalAuthRec_free(tmp);

	return KSI_RETURN(&err);
}

static int validateSignatureWithPublication(KSI_CTX *ctx, KSI_Signature *sig) {
	KSI_ERR err;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationData *pubData = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *pubHash = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_DataHash *inputHash = NULL;
	KSI_LIST(KSI_HashChainLink) *chain = NULL;
	int res;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	/* Get the calendar hash chain input hash. */
	res = KSI_CalendarHashChain_getInputHash(sig->calendarChain, &inputHash);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_CalendarHashChain_getHashChain(sig->calendarChain, &chain);
	KSI_CATCH(&err, res) goto cleanup;

	/* Calculate calendar hash chain root hash. */
	res = KSI_HashChain_aggregateCalendar(chain, inputHash, &rootHash);
	KSI_CATCH(&err, res) goto cleanup;

	/* Get the publications file. */
	res = KSI_receivePublicationsFile(ctx, &pubFile);
	KSI_CATCH(&err, res) goto cleanup;

	/* Get the publication */
	res = KSI_PublicationsFile_getPublicationDataByTime(pubFile, pubTime, &pubRec);
	KSI_CATCH(&err, res) goto cleanup;

	if (pubRec == NULL) {
		KSI_FAIL(&err, KSI_VERIFY_PUBLICATION_NOT_FOUND, NULL);
		goto cleanup;
	}

	/* Extract the publication data. */
	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubData);
	KSI_CATCH(&err, res) goto cleanup;

	/* Extract the imprint from the published data object. */
	res = KSI_PublicationData_getImprint(pubData, &pubHash);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calendar chain root hash", rootHash);
	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Publication imprint     ", pubHash);

	/* Verify the hashes are correct. */
	if (!KSI_DataHash_equals(rootHash, pubHash)) {
		KSI_FAIL(&err, KSI_VERIFY_PUBLICATION_MISMATCH, NULL);
		goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(chain);
	KSI_nofree(pubFile);
	KSI_nofree(pubData);
	KSI_nofree(pubTime);
	KSI_nofree(pubHash);
	KSI_nofree(inputHash);

	KSI_DataHash_free(rootHash);

	return KSI_RETURN(&err);
}

static int validateSignature_internal(KSI_Signature *sig) {
	KSI_ERR err;
	KSI_DataHash *hsh = NULL;
	uint32_t utc_time;
	int res;
	int level;
	int i;
	KSI_Integer *aggregationTime = NULL;
	KSI_Integer *publicationTime = NULL;
	KSI_LIST(KSI_HashChainLink) *chain = NULL;
	KSI_DataHash *inputHash = NULL;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	if (sig->aggregationChainList == NULL || AggrChainRecList_length(sig->aggregationChainList) == 0) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signature does not contain any aggregation chains.");
		goto cleanup;
	}

	if (sig->calendarChain == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signature does not contain a calendar chain.");
		goto cleanup;
	}

	if (sig->calAuth == NULL && sig->publication == NULL) { // TODO! Should this list contain also aggr auth record?
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signature does not contain any authentication record.");
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getHashChain(sig->calendarChain, &chain);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &publicationTime);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &aggregationTime);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_CalendarHashChain_getInputHash(sig->calendarChain, &inputHash);
	KSI_CATCH(&err, res) goto cleanup;

	/* Validate aggregation time */
	res = KSI_HashChain_getCalendarAggregationTime(chain, publicationTime, &utc_time);
	KSI_CATCH(&err, res) goto cleanup;

	if (aggregationTime == NULL) aggregationTime = publicationTime;


	if (!KSI_Integer_equalsUInt(aggregationTime, utc_time)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Aggregation time mismatch.");
		goto cleanup;
	}

	/* Aggregate aggregation chains. */
	hsh = NULL;
	level = 0;

	for (i = 0; i < AggrChainRecList_length(sig->aggregationChainList); i++) {
		const AggrChainRec* aggregationChain = NULL;
		KSI_DataHash *tmpHash = NULL;

		res = AggrChainRecList_elementAt(sig->aggregationChainList, i, (AggrChainRec **)&aggregationChain);
		KSI_CATCH(&err, res) goto cleanup;

		if (aggregationChain == NULL) break;

		if (hsh != NULL) {
			/* Validate input hash */
			if (!KSI_DataHash_equals(hsh, aggregationChain->inputHash)) {
				KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Aggregation chain mismatch,");
			}
		}

		res = KSI_HashChain_aggregate(aggregationChain->chain, aggregationChain->inputHash, level, aggregationChain->aggrHashId, &level, &tmpHash);
		KSI_CATCH(&err, res) {
			KSI_FAIL(&err, res, "Failed to calculate aggregation chain.");
			goto cleanup;
		}

		if (hsh != NULL) {
			KSI_DataHash_free(hsh);
		}
		hsh = tmpHash;
	}

	/* Validate calendar input hash */
	if (!KSI_DataHash_equals(hsh, inputHash)) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Calendar chain input hash mismatch.");
		goto cleanup;
	}

	KSI_DataHash_free(hsh);
	hsh = NULL;

	/* Aggregate calendar chain */
	res = KSI_HashChain_aggregateCalendar(chain, inputHash, &hsh);
	KSI_CATCH(&err, res) goto cleanup;


	if (sig->calAuth != NULL) {
		/* Validate calendar root hash */
		if (!KSI_DataHash_equals(hsh, sig->calAuth->pubData->pubHash)) {
			KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Calendar chain root hash mismatch.");
			goto cleanup;
		}
	}

	if (sig->aggrAuth != NULL) {
		/* TODO! */
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Validation using aggregation auth record not implemented.");
		goto cleanup;
	}


	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(hsh);

	return KSI_RETURN(&err);
}


static int validateSignature(KSI_CTX *ctx, KSI_Signature *sig) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = validateSignature_internal(sig);
	KSI_CATCH(&err, res) goto cleanup;

	if (sig->calAuth != NULL) {
		res = CalAuthRec_validate(ctx, sig->calAuth);
		KSI_CATCH(&err, res) goto cleanup;
	}

	if (sig->publication != NULL) {
		res = validateSignatureWithPublication(ctx, sig);
		KSI_CATCH(&err, res) goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}


static int extractSignature(KSI_CTX *ctx, KSI_TLV *tlv, KSI_Signature **signature) {
	KSI_ERR err;
	int res;

	KSI_Signature *sig = NULL;
	KSI_CalendarHashChain *cal = NULL;
	KSI_Integer *aggregationTime = NULL;
	KSI_Integer *publicationTime = NULL;
	KSI_DataHash *inputHash = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	if (KSI_TLV_getTag(tlv) != 0x800) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_Signature_new(ctx, &sig);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_CalendarHashChain_new(ctx, &cal);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_debug(ctx, "Starting to parse signature.");

	// FIXME: Replace using templates instead.
	KSI_TLV_PARSE_BEGIN(ctx, tlv)
		KSI_PARSE_TLV_ELEMENT_CB(0x801, parseAggregationChainRec, sig) // Aggregation hash chain

		KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x802) // Calendar hash chain
			KSI_PARSE_TLV_ELEMENT_INTEGER(0x01, &publicationTime)
			KSI_PARSE_TLV_ELEMENT_INTEGER(0x02, &aggregationTime)
			KSI_PARSE_TLV_ELEMENT_IMPRINT(0x05, &inputHash)
			KSI_PARSE_TLV_ELEMENT_CB(0x07, CalChainRec_addLink, cal)
			KSI_PARSE_TLV_ELEMENT_CB(0x08, CalChainRec_addLink, cal)
			KSI_PARSE_TLV_ELEMENT_UNKNONW_NON_CRITICAL_REMOVE
		KSI_PARSE_TLV_NESTED_ELEMENT_END

		KSI_PARSE_TLV_ELEMENT_CB(0x0803, parsePublication, &sig->publication);
		KSI_PARSE_TLV_ELEMENT_CB(0x0804, parseAggrAuthRec, &sig->aggrAuth);
		KSI_PARSE_TLV_ELEMENT_CB(0x0805, parseCalAuthRec, &sig->calAuth)

		KSI_PARSE_TLV_ELEMENT_UNKNONW_NON_CRITICAL_REMOVE
	KSI_TLV_PARSE_END(res);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_CalendarHashChain_setAggregationTime(cal, aggregationTime);
	KSI_CATCH(&err, res) goto cleanup;
	aggregationTime = NULL;

	res = KSI_CalendarHashChain_setPublicationTime(cal, publicationTime);
	KSI_CATCH(&err, res) goto cleanup;
	publicationTime = NULL;

	res = KSI_CalendarHashChain_setInputHash(cal, inputHash);
	KSI_CATCH(&err, res) goto cleanup;
	inputHash = NULL;
	sig->calendarChain = cal;
	cal = NULL;

	res = validateSignature(ctx, sig);
	KSI_CATCH(&err, res) goto cleanup;


	*signature = sig;
	sig = NULL;

	KSI_LOG_debug(ctx, "Finished parsing successfully.");
	KSI_SUCCESS(&err);

cleanup:

	KSI_Integer_free(aggregationTime);
	KSI_Integer_free(publicationTime);
	KSI_DataHash_free(inputHash);

	KSI_CalendarHashChain_free(cal);
	KSI_Signature_free(sig);

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

static int replaceCalendarChain(KSI_Signature *sig, KSI_CalendarHashChain *calendarHashChain) {
	KSI_ERR err;
	int res;
	KSI_DataHash *newInputHash = NULL;
	KSI_DataHash *oldInputHash = NULL;
	KSI_TLV *oldCalChainTlv = NULL;
	KSI_TLV *newCalChainTlv = NULL;

	KSI_PRE(&err, calendarHashChain != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;

	KSI_BEGIN(sig->ctx, &err);

	if (sig->calendarChain == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Signature does not contain a hash chain.");
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getInputHash(calendarHashChain, &newInputHash);
	KSI_CATCH(&err, res) goto cleanup;


	if (newInputHash == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Given calendar hash chain does not contain an input hash.");
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getInputHash(sig->calendarChain, &oldInputHash);
	KSI_CATCH(&err, res) goto cleanup;

	/* The output hash and input hash have to be equal */
	if (!KSI_DataHash_equals(newInputHash, oldInputHash)) {
		KSI_FAIL(&err, KSI_EXTEND_WRONG_CAL_CHAIN, NULL);
		goto cleanup;
	}

	res = KSI_TLV_iterNested(sig->baseTlv);
	KSI_CATCH(&err, res) goto cleanup;

	while (1) {
		res = KSI_TLV_getNextNestedTLV(sig->baseTlv, &oldCalChainTlv);
		KSI_CATCH(&err, res) goto cleanup;

		if (oldCalChainTlv == NULL) {
			KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signature does not contain calendar chain.");
			goto cleanup;
		}

		if (KSI_TLV_getTag(oldCalChainTlv) == KSI_TAG_CALENDAR_CHAIN) break;
	}

	res = KSI_TLV_new(sig->ctx, KSI_TLV_PAYLOAD_TLV, KSI_TAG_CALENDAR_CHAIN, 0, 0, &newCalChainTlv);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_construct(sig->ctx, newCalChainTlv, calendarHashChain, KSI_TLV_TEMPLATE(KSI_CalendarHashChain));
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_replaceNestedTlv(sig->baseTlv, oldCalChainTlv, newCalChainTlv);
	KSI_CATCH(&err, res) goto cleanup;
	newCalChainTlv = NULL;

	/* Free only the memory, if everything else was OK.*/
	KSI_TLV_free(oldCalChainTlv);

	KSI_CalendarHashChain_free(sig->calendarChain);
	sig->calendarChain = calendarHashChain;


	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(oldInputHash);
	KSI_nofree(newInputHash);

	KSI_TLV_free(newCalChainTlv);

	KSI_nofree(newInputHash);

	return KSI_RETURN(&err);
}

static int removeWeakAuthRecords(KSI_Signature *sig) {
	KSI_ERR err;
	KSI_LIST(KSI_TLV) *nested = NULL;
	KSI_TLV *tlv = NULL;
	int res;
	int i;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	res = KSI_TLV_getNestedList(sig->baseTlv, &nested);
	KSI_CATCH(&err, res) goto cleanup;

	/* By looping in reverse order, we can safely remove elements
	 * and continue. */
	for (i = KSI_TLVList_length(nested) - 1; i >= 0; i--) {
		int tag;

		res = KSI_TLVList_elementAt(nested, i, &tlv);
		KSI_CATCH(&err, res) goto cleanup;

		tag = KSI_TLV_getTag(tlv);

		if (tag == 0x0804 || tag == 0x0805) {
			res = KSI_TLVList_remove(nested, i);
			KSI_CATCH(&err, res) goto cleanup;

			KSI_TLV_free(tlv);
			tlv = NULL;
		}
	}

	if (sig->calAuth != NULL) {
		CalAuthRec_free(sig->calAuth);
		sig->calAuth = NULL;
	}

	if (sig->aggrAuth != NULL) {
		AggrAuthRec_free(sig->aggrAuth);
		sig->aggrAuth = NULL;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(nested);
	KSI_nofree(tlv);

	return KSI_RETURN(&err);
}

static int setPublicationRecord(KSI_Signature *sig, KSI_PublicationRecord *pubRec) {
	KSI_ERR err;
	KSI_TLV *newPubTlv = NULL;
	int oldPubTlvPos = -1;
	KSI_LIST(KSI_TLV) *nestedList = NULL;
	int res;
	int i;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, pubRec != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	/* Create a new TLV object */
	res = KSI_TLV_new(sig->ctx, KSI_TLV_PAYLOAD_TLV, 0x0803, 0, 0, &newPubTlv);
	KSI_CATCH(&err, res) goto cleanup;

	/* Evaluate the TLV object */
	res = KSI_TlvTemplate_construct(sig->ctx, newPubTlv, pubRec, KSI_TLV_TEMPLATE(KSI_PublicationRecord));
	KSI_CATCH(&err, res) goto cleanup;

	/* Find previous publication */
	res = KSI_TLV_getNestedList(sig->baseTlv, &nestedList);
	KSI_CATCH(&err, res) goto cleanup;

	for (i = 0; i < KSI_TLVList_length(nestedList); i++) {
		KSI_TLV *tmp = NULL;
		res = KSI_TLVList_elementAt(nestedList, i, &tmp);
		KSI_CATCH(&err, res) goto cleanup;

		if (KSI_TLV_getTag(tmp) == 0x0803) {
			oldPubTlvPos = i;
			break;
		}

		KSI_nofree(tmp);
	}

	if (oldPubTlvPos != -1) {
		res = KSI_TLVList_replaceAt(nestedList, oldPubTlvPos, newPubTlv);
		KSI_CATCH(&err, res) goto cleanup;
	} else {
		res = KSI_TLVList_append(nestedList, newPubTlv);
		KSI_CATCH(&err, res) goto cleanup;
	}

	if (sig->publication != NULL) {
		KSI_PublicationRecord_free(sig->publication);
	}
	sig->publication = pubRec;

	/* Remove previous weaker authentication records. */
	res = removeWeakAuthRecords(sig);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_Signature_sign(KSI_CTX *ctx, const KSI_DataHash *hsh, KSI_Signature **signature) {
	KSI_ERR err;
	int res;
	KSI_NetHandle *handle = NULL;
	KSI_Signature *sign = NULL;

	unsigned char *req = NULL;
	int req_len = 0;

	const unsigned char *resp = NULL;
	int resp_len = 0;

	KSI_PRE(&err, hsh != NULL) goto cleanup;
	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	res = createSignRequest(ctx, hsh, &req, &req_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Request", req, req_len);

	res = KSI_sendSignRequest(ctx, req, req_len, &handle);
	KSI_CATCH(&err, res) goto cleanup;

	/* Wait for the response. */
	res = KSI_NetHandle_receive(handle);
	KSI_CATCH(&err, res) goto cleanup;
	/* Read the response. */
	res = KSI_NetHandle_getResponse(handle, &resp, &resp_len);
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

int KSI_Signature_extend(const KSI_Signature *signature, const KSI_PublicationRecord *pubRec, KSI_Signature **extended) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	KSI_Signature *tmp = NULL;
	KSI_ExtendResp *response = NULL;
	KSI_CalendarHashChain *calHashChain = NULL;
	KSI_Integer *respStatus = NULL;
	KSI_Integer *signTime = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_PublicationData *pubData = NULL;
	KSI_PublicationRecord *pubRecClone = NULL;

	unsigned char *rawReq = NULL;
	int rawReq_len = 0;

	const unsigned char *rawResp = NULL;
	int rawResp_len = 0;

	KSI_TLV *respTlv = NULL;
	KSI_ExtendPdu *pdu = NULL;
	KSI_NetHandle *handle = NULL;

	KSI_PRE(&err, pubRec != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_PRE(&err, extended != NULL) goto cleanup;

	ctx = KSI_Signature_getCtx(signature);
	KSI_BEGIN(ctx, &err);

	/* Make a copy of the original publication record .*/
	res = KSI_PublicationRecord_new(ctx, &pubRecClone);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_deepCopy(ctx, pubRec, KSI_TLV_TEMPLATE(KSI_PublicationRecord), pubRecClone);
	KSI_CATCH(&err, res) goto cleanup;

	/* Make a copy of the original signature */
	res = KSI_Signature_clone(signature, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	/* Request the calendar hash chain from this moment on. */
	res = KSI_Signature_getSigningTime(tmp, &signTime);
	KSI_CATCH(&err, res) goto cleanup;

	/* Extract the published data object. */
	res = KSI_PublicationRecord_getPublishedData(pubRecClone, &pubData);
	KSI_CATCH(&err, res) goto cleanup;

	/* Read the publication time from the published data object. */
	res = KSI_PublicationData_getTime(pubData, &pubTime);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create request. */
	res = createExtendRequest(ctx, signTime, pubTime, &rawReq, &rawReq_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Extend request", rawReq, rawReq_len);

	/* Send the actual request. */
	res = KSI_sendExtendRequest(ctx, rawReq, rawReq_len, &handle);
	KSI_CATCH(&err, res) goto cleanup;

	/* Wait for the response. */
	res = KSI_NetHandle_receive(handle);
	KSI_CATCH(&err, res) goto cleanup;

	/* Read the response. */
	res = KSI_NetHandle_getResponse(handle, &rawResp, &rawResp_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Extend response", rawResp, rawResp_len);

	res = KSI_TLV_parseBlob(ctx, rawResp, rawResp_len, &respTlv);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create response PDU object. */
	res = KSI_ExtendPdu_new(ctx, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	/* Evaluate response PDU object. */
	res = KSI_TlvTemplate_extract(ctx, pdu, respTlv, KSI_TLV_TEMPLATE(KSI_ExtendPdu), NULL);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Parsed part of the response", respTlv);

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

		KSI_FAIL(&err, KSI_EXTENDER_ERROR, KSI_Utf8String_cstr(error));
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
	res = replaceCalendarChain(tmp, calHashChain);
	KSI_CATCH(&err, res) goto cleanup;

	/* Set the publication as the trust anchor. */
	res = setPublicationRecord(tmp, pubRecClone);
	KSI_CATCH(&err, res) goto cleanup;
	pubRecClone = NULL;

	/* Validate signature before returning. */
	res = validateSignature(ctx, tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*extended = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_PublicationRecord_free(pubRecClone);
	KSI_ExtendPdu_free(pdu);
	KSI_NetHandle_free(handle);
	KSI_TLV_free(respTlv);
	KSI_free(rawReq);
	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);
}


void KSI_Signature_free(KSI_Signature *sig) {
	if (sig != NULL) {
		KSI_TLV_free(sig->baseTlv);
		KSI_CalendarHashChain_free(sig->calendarChain);
		AggrChainRecList_free(sig->aggregationChainList);
		CalAuthRec_free(sig->calAuth);
		AggrAuthRec_free(sig->aggrAuth);
		KSI_PublicationRecord_free(sig->publication);
		KSI_free(sig);
	}
}

int KSI_parseAggregationResponse(KSI_CTX *ctx, const unsigned char *response, int response_len, KSI_Signature **signature) {
	KSI_ERR err;
	int res;
	KSI_TLV *sigTlv = NULL;
	KSI_TLV *tmpTlv = NULL;
	KSI_Signature *tmp = NULL;

	/* PDU Specific objects */
	KSI_Integer *status = NULL;
	KSI_Integer *requestId = NULL;
	char *errorMessage = NULL;
	HeaderRec *hdr = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, response != NULL) goto cleanup;
	KSI_PRE(&err, response_len > 0) goto cleanup;

	KSI_BEGIN(ctx, &err);

	res = HeaderRec_new(ctx, &hdr);
	KSI_CATCH(&err, res) goto cleanup;

	/* Parse the pdu */
	res = KSI_TLV_parseBlob(ctx, response, response_len, &tmpTlv);
	KSI_CATCH(&err, res) goto cleanup;

	/* Validate tag value */
	if (KSI_TLV_getTag(tmpTlv) != 0x200) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	/* Make it a composite object */
	res = KSI_TLV_cast(tmpTlv, KSI_TLV_PAYLOAD_TLV);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create signature TLV */
	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, 0x800, 0, 0, &sigTlv);
	KSI_CATCH(&err, res) goto cleanup;

	// FIXME: Replace with templates
	KSI_TLV_PARSE_BEGIN(ctx, tmpTlv)
		KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x202)
			KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x01)
				KSI_PARSE_TLV_ELEMENT_INTEGER(0x05, &hdr->instanceId)
				KSI_PARSE_TLV_ELEMENT_INTEGER(0x06, &hdr->messageId)
				KSI_PARSE_TLV_ELEMENT_RAW(0x07, &hdr->clientId, &hdr->clientId_length);
				KSI_PARSE_TLV_ELEMENT_UNKNONW_NON_CRITICAL_IGNORE
			KSI_PARSE_TLV_NESTED_ELEMENT_END

			KSI_PARSE_TLV_ELEMENT_INTEGER(0x02, &requestId)
			KSI_PARSE_TLV_ELEMENT_INTEGER(0x05, &status)
			KSI_PARSE_TLV_ELEMENT_UTF8STR(0x06, &errorMessage)

			KSI_PARSE_TLV_ELEMENT_UNKNOWN_FWD(sigTlv)
		KSI_PARSE_TLV_NESTED_ELEMENT_END
	KSI_TLV_PARSE_END(res);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Signature", sigTlv);


	/* NB! By casting the TLV into raw we force it to decouple from the
	 * base TLV structure (i.e nested values may use the values from
	 * the parents.*/
	res = KSI_TLV_cast(sigTlv, KSI_TLV_PAYLOAD_RAW);
	KSI_CATCH(&err, res) goto cleanup;

	// TODO What else can we do with message header ?
	KSI_LOG_debug(ctx, "Aggregation response: instanceId = %ld, messageId = %ld",
			(unsigned long long) KSI_Integer_getUInt64(hdr->instanceId),
			(unsigned long long) KSI_Integer_getUInt64(hdr->messageId));

	if (status != NULL && !KSI_Integer_equalsUInt(status, 0)) {
		char msg[1024];

		snprintf(msg, sizeof(msg), "Aggregation failed: %s", errorMessage);
		KSI_FAIL_EXT(&err, KSI_AGGREGATOR_ERROR, (unsigned long long)KSI_Integer_getUInt64(status), errorMessage);
		goto cleanup;
	}

	res = extractSignature(ctx, sigTlv, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	/* The tlv is referenced from the signature now */
	tmp->baseTlv = sigTlv;
	sigTlv = NULL;

	*signature = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(sigTlv);
	HeaderRec_free(hdr);
	KSI_Signature_free(tmp);
	KSI_TLV_free(tmpTlv);

	return KSI_RETURN(&err);

}

int KSI_Signature_getDataHash(KSI_Signature *sig, const KSI_DataHash **hsh) {
	KSI_ERR err;
	AggrChainRec *aggr = NULL;
	int res;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, hsh != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	res = AggrChainRecList_elementAt(sig->aggregationChainList, 0, &aggr);
	KSI_CATCH(&err, res) goto cleanup;

	*hsh = aggr->inputHash;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(aggr);

	return KSI_RETURN(&err);
}

int KSI_Signature_getSigningTime(const KSI_Signature *sig, KSI_Integer **signTime) {
	KSI_ERR err;
	int res;
	KSI_Integer *signingTime = NULL;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	if (sig->calendarChain == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &signingTime);
	KSI_CATCH(&err, res) goto cleanup;

	if (signingTime == NULL) {
		res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &signingTime);
		KSI_CATCH(&err, res) goto cleanup;

		if (signTime == NULL){
			KSI_FAIL(&err, KSI_INVALID_SIGNATURE, NULL);
			goto cleanup;
		}

	}

	*signTime = signingTime;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_Signature_clone(const KSI_Signature *sig, KSI_Signature **clone) {
	KSI_ERR err;
	KSI_TLV *tlv = NULL;
	KSI_Signature *tmp = NULL;
	int res;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, clone != NULL) goto cleanup;

	KSI_BEGIN(sig->ctx, &err);

	res = KSI_TLV_clone(sig->baseTlv, &tlv);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(sig->ctx, KSI_LOG_DEBUG, "Original TLV", sig->baseTlv);
	KSI_LOG_logTlv(sig->ctx, KSI_LOG_DEBUG, "Cloned TLV", tlv);

	res = extractSignature(sig->ctx, tlv, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	tmp->baseTlv = tlv;
	tlv = NULL;

	*clone = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tlv);
	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_Signature_parse(KSI_CTX *ctx, unsigned char *raw, int raw_len, KSI_Signature **sig) {
	KSI_ERR err;
	KSI_TLV *tlv = NULL;
	KSI_Signature *tmp = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len > 0) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_parseBlob(ctx, raw, raw_len, &tlv);
	KSI_CATCH(&err, res) goto cleanup;

	res = extractSignature(ctx, tlv, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	tmp->baseTlv = tlv;
	tlv = NULL;

	*sig = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tlv);
	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_Signature_fromFile(KSI_CTX *ctx, const char *fileName, KSI_Signature **sig) {
	KSI_ERR err;
	int res;
	FILE *f = NULL;
	unsigned char *raw = NULL;
	int raw_size = 0xfffff;
	size_t raw_len = 0;
	KSI_Signature *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, fileName != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	raw = KSI_calloc(raw_size, 1);
	if (raw == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	f = fopen(fileName, "rb");
	if (f == NULL) {
		KSI_FAIL(&err, KSI_IO_ERROR, "Unable to open file.");
		goto cleanup;
	}

	raw_len = fread(raw, 1, raw_size, f);
	if (raw_len == 0) {
		KSI_FAIL(&err, KSI_IO_ERROR, "Unable to read file.");
		goto cleanup;
	}

	if (!feof(f)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Input too long for a valid signature.");
		goto cleanup;
	}

	res = KSI_Signature_parse(ctx, raw, (int)raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*sig = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	if (f != NULL) fclose(f);
	KSI_Signature_free(tmp);
	KSI_free(raw);

	return KSI_RETURN(&err);
}

int KSI_Signature_serialize(KSI_Signature *sig, unsigned char **raw, int *raw_len) {
	KSI_ERR err;
	int res;
	unsigned char *tmp = NULL;
	int tmp_len;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	/* We assume that the baseTlv tree is up to date! */
	res = KSI_TLV_serialize(sig->baseTlv, &tmp, &tmp_len);
	KSI_CATCH(&err, res) goto cleanup;

	*raw = tmp;
	tmp = NULL;

	*raw_len = tmp_len;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp);

	return KSI_RETURN(&err);

}

int KSI_Signature_getSignerIdentity(KSI_Signature *sig, char **signerIdentity) {
	KSI_ERR err;
	int res;
	int i, j;
	KSI_LIST(KSI_Utf8String) *idList = NULL;
	KSI_Utf8String *clientId = NULL;
	char *signerId = NULL;
	int signerId_size = 0;
	int signerId_len = 0;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, signerIdentity != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	/* Create a list of separate signer identities. */
	res = KSI_Utf8StringList_new(sig->ctx, &idList);
	KSI_CATCH(&err, res) goto cleanup;

	/* Extract all identities from all aggregation chains. */
	for (i = 0; i < AggrChainRecList_length(sig->aggregationChainList); i++) {
		AggrChainRec *aggrRec = NULL;

		res = AggrChainRecList_elementAt(sig->aggregationChainList, i, &aggrRec);
		KSI_CATCH(&err, res) goto cleanup;

		for (j = 0; j < KSI_HashChainLinkList_length(aggrRec->chain); j++) {
			KSI_HashChainLink *link = NULL;
			KSI_MetaData *metaData = NULL;

			res = KSI_HashChainLinkList_elementAt(aggrRec->chain, j, &link);
			KSI_CATCH(&err, res) goto cleanup;

			KSI_HashChainLink_getMetaData(link, &metaData);
			KSI_CATCH(&err, res) goto cleanup;

			/* Exit inner loop if this chain link does not contain a metadata block. */
			if (metaData == NULL) continue;

			res = KSI_MetaData_getClientId(metaData, &clientId);
			KSI_CATCH(&err, res) goto cleanup;

			signerId_size += strlen((char *)clientId) + 1; /* +1 for dot (.) or ending zero character. */

			res = KSI_Utf8StringList_append(idList, clientId);
			clientId = NULL;

		}
	}

	/* Concatenate all together. */
	for (i = 0; i < KSI_Utf8StringList_length(idList); i++) {
		KSI_Utf8String *tmp = NULL;

		res = KSI_Utf8StringList_elementAt(idList, i, &tmp);
		KSI_CATCH(&err, res) goto cleanup;

		signerId_len += sprintf(signerId + signerId_len, "%s%s", signerId_len > 0 ? ".": "", KSI_Utf8String_cstr(tmp));
	}

	*signerIdentity = signerId;
	signerId = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(signerId);
	KSI_Utf8StringList_free(idList);
	KSI_free(clientId);

	return KSI_RETURN(&err);
}

KSI_IMPLEMENT_GET_CTX(KSI_Signature);
