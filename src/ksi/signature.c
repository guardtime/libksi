#include <string.h>

#include "internal.h"

typedef struct headerRec_st HeaderRec;

KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarHashChain);
KSI_IMPORT_TLV_TEMPLATE(KSI_HashChainLink);
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationHashChain)
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationAuthRec)
KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarAuthRec)

struct KSI_CalendarAuthRec_st {
	KSI_CTX *ctx;

	KSI_TLV *pubDataTlv;
	KSI_PublicationData *pubData;
	KSI_Utf8String *signatureAlgo;
	KSI_PKISignedData *signatureData;
};

struct KSI_AggregationAuthRec_st {
	KSI_CTX *ctx;
	KSI_Integer *aggregationTime;
	KSI_LIST(KSI_Integer) *chainIndexesList;
	KSI_DataHash *inputHash;

	KSI_Utf8String *signatureAlgo;

	KSI_PKISignedData *signatureData;
};

struct KSI_AggregationHashChain_st {
	KSI_CTX *ctx;
	KSI_Integer *aggregationTime;
	KSI_LIST(KSI_Integer) *chainIndex;
	KSI_OctetString *inputData;
	KSI_DataHash *inputHash;
	KSI_Integer *aggrHashId;
	KSI_LIST(KSI_HashChainLink) *chain;
};

/**
 * KSI Signature object
 */
struct KSI_Signature_st {
	KSI_CTX *ctx;

	/* Base TLV - when serialized, this value will be used. */
	KSI_TLV *baseTlv;

	KSI_CalendarHashChain *calendarChain;

	KSI_LIST(KSI_AggregationHashChain) *aggregationChainList;

	KSI_CalendarAuthRec *calendarAuthRec;
	KSI_AggregationAuthRec *aggregationAuthRec;
	KSI_PublicationRecord *publication;

};

/**
 * KSI_Signature
 */
static KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_CalendarHashChain*, calendarChain, CalendarChain)
static KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_LIST(KSI_AggregationHashChain)*, aggregationChainList, AggregationChainList)
static KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_CalendarAuthRec*, calendarAuthRec, CalendarAuthRecord)
static KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_AggregationAuthRec*, aggregationAuthRec, AggregationAuthRecord)

static KSI_IMPLEMENT_SETTER(KSI_Signature, KSI_CalendarHashChain*, calendarChain, CalendarChain)
static KSI_IMPLEMENT_SETTER(KSI_Signature, KSI_LIST(KSI_AggregationHashChain)*, aggregationChainList, AggregationChainList)
static KSI_IMPLEMENT_SETTER(KSI_Signature, KSI_CalendarAuthRec*, calendarAuthRec, CalendarAuthRecord)
static KSI_IMPLEMENT_SETTER(KSI_Signature, KSI_AggregationAuthRec*, aggregationAuthRec, AggregationAuthRecord)
static KSI_IMPLEMENT_SETTER(KSI_Signature, KSI_PublicationRecord*, publication, PublicationRecord)

/**
 * KSI_AggregationHashChain
 */
void KSI_AggregationHashChain_free(KSI_AggregationHashChain *aggr) {
	if (aggr != NULL) {
		KSI_Integer_free(aggr->aggrHashId);
		KSI_Integer_free(aggr->aggregationTime);
		KSI_IntegerList_freeAll(aggr->chainIndex);
		KSI_OctetString_free(aggr->inputData);
		KSI_DataHash_free(aggr->inputHash);
		KSI_HashChainLinkList_freeAll(aggr->chain);
		KSI_free(aggr);
	}
}

int KSI_AggregationHashChain_new(KSI_CTX *ctx, KSI_AggregationHashChain **out) {
	KSI_ERR err;
	KSI_AggregationHashChain *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, out != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_AggregationHashChain);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->aggregationTime = NULL;
	tmp->chain = NULL;
	tmp->chainIndex = NULL;
	tmp->inputData = NULL;
	tmp->inputHash = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_AggregationHashChain_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_AggregationHashChain_compareTo(const KSI_AggregationHashChain *left, const KSI_AggregationHashChain *right) {
	if (left == NULL || right == NULL) {
		return left == right;
	} else {
		return KSI_IntegerList_length(right->chainIndex) - KSI_IntegerList_length(left->chainIndex);
	}
}

KSI_IMPLEMENT_GETTER(KSI_AggregationHashChain, KSI_Integer*, aggregationTime, AggregationTime)
KSI_IMPLEMENT_GETTER(KSI_AggregationHashChain, KSI_LIST(KSI_Integer)*, chainIndex, ChainIndex)
KSI_IMPLEMENT_GETTER(KSI_AggregationHashChain, KSI_OctetString*, inputData, InputData)
KSI_IMPLEMENT_GETTER(KSI_AggregationHashChain, KSI_DataHash*, inputHash, InputHash)
KSI_IMPLEMENT_GETTER(KSI_AggregationHashChain, KSI_Integer*, aggrHashId, AggrHashId)

KSI_IMPLEMENT_SETTER(KSI_AggregationHashChain, KSI_Integer*, aggregationTime, AggregationTime)
KSI_IMPLEMENT_SETTER(KSI_AggregationHashChain, KSI_LIST(KSI_Integer)*, chainIndex, ChainIndex)
KSI_IMPLEMENT_SETTER(KSI_AggregationHashChain, KSI_OctetString*, inputData, InputData)
KSI_IMPLEMENT_SETTER(KSI_AggregationHashChain, KSI_DataHash*, inputHash, InputHash)
KSI_IMPLEMENT_SETTER(KSI_AggregationHashChain, KSI_Integer*, aggrHashId, AggrHashId)

/**
 * KSI_AggregationAuthRec
 */
void KSI_AggregationAuthRec_free(KSI_AggregationAuthRec *aar) {
	if (aar != NULL) {
		KSI_Integer_free(aar->aggregationTime);
		KSI_IntegerList_freeAll(aar->chainIndexesList);
		KSI_DataHash_free(aar->inputHash);
		KSI_Utf8String_free(aar->signatureAlgo);
		KSI_PKISignedData_free(aar->signatureData);
		KSI_free(aar);
	}
}

int KSI_AggregationAuthRec_new(KSI_CTX *ctx, KSI_AggregationAuthRec **out) {
	KSI_ERR err;
	KSI_AggregationAuthRec *tmp = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, out != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_AggregationAuthRec);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = KSI_IntegerList_new(ctx, &tmp->chainIndexesList);
	KSI_CATCH(&err, res) goto cleanup;

	tmp->inputHash = NULL;
	tmp->ctx = ctx;
	tmp->signatureAlgo = NULL;
	tmp->signatureData = NULL;
	tmp->aggregationTime = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_AggregationAuthRec_free(tmp);

	return KSI_RETURN(&err);
}

KSI_IMPLEMENT_GETTER(KSI_AggregationAuthRec, KSI_Integer*, aggregationTime, AggregationTime)
KSI_IMPLEMENT_GETTER(KSI_AggregationAuthRec, KSI_LIST(KSI_Integer)*, chainIndexesList, ChainIndex)
KSI_IMPLEMENT_GETTER(KSI_AggregationAuthRec, KSI_DataHash*, inputHash, InputHash)
KSI_IMPLEMENT_GETTER(KSI_AggregationAuthRec, KSI_Utf8String*, signatureAlgo, SigAlgo)
KSI_IMPLEMENT_GETTER(KSI_AggregationAuthRec, KSI_PKISignedData*, signatureData, SigData)

KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_Integer*, aggregationTime, AggregationTime)
KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_LIST(KSI_Integer)*, chainIndexesList, ChainIndex)
KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_DataHash*, inputHash, InputHash)
KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_Utf8String*, signatureAlgo, SigAlgo)
KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_PKISignedData*, signatureData, SigData)

/**
 * KSI_CalendarAuthRec
 */

void KSI_CalendarAuthRec_free(KSI_CalendarAuthRec *calAuth) {
	if (calAuth != NULL) {
		KSI_TLV_free(calAuth->pubDataTlv);
		KSI_PublicationData_free(calAuth->pubData);
		KSI_Utf8String_free(calAuth->signatureAlgo);
		KSI_PKISignedData_free(calAuth->signatureData);

		KSI_free(calAuth);
	}
}

int KSI_CalendarAuthRec_new(KSI_CTX *ctx, KSI_CalendarAuthRec **out) {
	KSI_ERR err;
	KSI_CalendarAuthRec *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, out != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_CalendarAuthRec);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->pubData = NULL;
	tmp->signatureAlgo = NULL;
	tmp->signatureData = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_CalendarAuthRec_free(tmp);

	return KSI_RETURN(&err);

}

KSI_IMPLEMENT_SETTER(KSI_CalendarAuthRec, KSI_TLV*, pubDataTlv, SignedData)
KSI_IMPLEMENT_SETTER(KSI_CalendarAuthRec, KSI_PublicationData*, pubData, PublishedData)
KSI_IMPLEMENT_SETTER(KSI_CalendarAuthRec, KSI_Utf8String*, signatureAlgo, SignatureAlgo)
KSI_IMPLEMENT_SETTER(KSI_CalendarAuthRec, KSI_PKISignedData*, signatureData, SignatureData)

KSI_IMPLEMENT_GETTER(KSI_CalendarAuthRec, KSI_TLV*, pubDataTlv, SignedData)
KSI_IMPLEMENT_GETTER(KSI_CalendarAuthRec, KSI_PublicationData*, pubData, PublishedData)
KSI_IMPLEMENT_GETTER(KSI_CalendarAuthRec, KSI_Utf8String*, signatureAlgo, SignatureAlgo)
KSI_IMPLEMENT_GETTER(KSI_CalendarAuthRec, KSI_PKISignedData*, signatureData, SignatureData)

int KSI_AggregationHashChain_toTlv(KSI_TLV *tlv, KSI_AggregationHashChain **rec) {
	return KSI_UNKNOWN_ERROR;
}

KSI_IMPLEMENT_LIST(KSI_AggregationHashChain, KSI_AggregationHashChain_free);

int KSI_AggregationHashChain_fromTlv(KSI_TLV *tlv, KSI_AggregationHashChain **rec) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	KSI_AggregationHashChain *tmp = NULL;
	KSI_LIST(KSI_TLV) *chainLinks = NULL;
	KSI_HashChainLink *link = NULL;
	KSI_TLV *linkTlv = NULL;
	int isLeft;
	size_t i;
	int res;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, rec != NULL) goto cleanup;
	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	/* Create new element */
	res = KSI_AggregationHashChain_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create list for the left and right hash chain TLVs. */
	res = KSI_TLVList_new(ctx, &chainLinks);
	KSI_CATCH(&err, res) goto cleanup;

	/* Extract all except the hash chain TLVs. */
	res = KSI_TlvTemplate_extract(ctx, tmp, tlv, KSI_TLV_TEMPLATE(KSI_AggregationHashChain), chainLinks);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create a new list for the chain. */
	res = KSI_HashChainLinkList_new(ctx, &tmp->chain);
	KSI_CATCH(&err, res) goto cleanup;

	/* Parse all the chain links. */
	for (i = 0; i < KSI_TLVList_length(chainLinks); i++) {
		/* Get the tlv from the list. */
		res = KSI_TLVList_elementAt(chainLinks, i, &linkTlv);
		KSI_CATCH(&err, res) goto cleanup;

		switch (KSI_TLV_getTag(linkTlv)) {
			case 0x07:
				isLeft = 1;
				break;
			case 0x08:
				isLeft = 0;
				break;
			default:
				if (!KSI_TLV_isLenient(linkTlv)) {
					KSI_LOG_error(ctx, "Unknown aggregation chain record critical tag 0x%02x", KSI_TLV_getTag(linkTlv));
					KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
					goto cleanup;
				}
				KSI_LOG_debug(ctx, "Ignoring aggregation chain record non-critical tag 0x%02x", KSI_TLV_getTag(linkTlv));
				continue;
		}

		/* Create a new chain link object. */
		res = KSI_HashChainLink_new(ctx, &link);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_HashChainLink_setIsLeft(link, isLeft);
		KSI_CATCH(&err, res) goto cleanup;

		/* Extract the values. */
		res = KSI_TlvTemplate_extract(ctx, link, linkTlv, KSI_TLV_TEMPLATE(KSI_HashChainLink), NULL);
		KSI_CATCH(&err, res) goto cleanup;

		/* Add the link to the chain. */
		res = KSI_HashChainLinkList_append(tmp->chain, link);
		KSI_CATCH(&err, res) goto cleanup;

		link = NULL;
	}

	*rec = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLVList_free(chainLinks);
	KSI_nofree(chainLinks);
	KSI_HashChainLink_free(link);
	KSI_AggregationHashChain_free(tmp);
	return KSI_RETURN(&err);
}

KSI_DEFINE_TLV_TEMPLATE(KSI_Signature)
	KSI_TLV_OBJECT_LIST(0x0801, 0, 0, KSI_Signature_getAggregationChainList, KSI_Signature_setAggregationChainList, KSI_AggregationHashChain)
	KSI_TLV_COMPOSITE(0x0802, 0, 0, KSI_Signature_getCalendarChain, KSI_Signature_setCalendarChain, KSI_CalendarHashChain)
	KSI_TLV_COMPOSITE(0x0803, 0, 0, KSI_Signature_getPublicationRecord, KSI_Signature_setPublicationRecord, KSI_PublicationRecord)
	KSI_TLV_COMPOSITE(0x0804, 0, 0, KSI_Signature_getAggregationAuthRecord, KSI_Signature_setAggregationAuthRecord, KSI_AggregationAuthRec)
	KSI_TLV_COMPOSITE(0x0805, 0, 0, KSI_Signature_getCalendarAuthRecord, KSI_Signature_setCalendarAuthRecord, KSI_CalendarAuthRec)
KSI_END_TLV_TEMPLATE

static int KSI_Signature_new(KSI_CTX *ctx, KSI_Signature **sig) {
	KSI_ERR err;
	KSI_Signature *tmp = NULL;

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
	tmp->aggregationAuthRec = NULL;
	tmp->aggregationChainList = NULL;

	*sig = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);

}

static int verifyPublicationData(KSI_CTX *ctx, KSI_CalendarAuthRec *calAuth, const unsigned char *raw, unsigned raw_len, KSI_PKICertificate *cert) {
	KSI_ERR err;
	int res;
	unsigned char *data = NULL;
	unsigned data_len;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, calAuth != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len >= 0) goto cleanup;
	KSI_PRE(&err, cert != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_serialize(calAuth->pubDataTlv, &data, &data_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKITruststore_verifyRawSignature(ctx, data, data_len, KSI_Utf8String_cstr(calAuth->signatureAlgo), raw, raw_len, cert);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(data);

	return KSI_RETURN(&err);
}

static int KSI_CalendarAuthRec_verify(KSI_CTX *ctx, KSI_CalendarAuthRec *calAuth) {
	KSI_ERR err;
	int res;
	KSI_PKICertificate *cert = NULL;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_OctetString *certId = NULL;
	KSI_OctetString *signatureValue = NULL;
	const unsigned char *raw = NULL;
	unsigned int raw_len = 0;

	KSI_PRE(&err, calAuth != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_PKISignedData_getCertId(calAuth->signatureData, &certId);
	KSI_CATCH(&err, res) goto cleanup;

	if (certId == NULL) {
		res = KSI_PKISignedData_getCert(calAuth->signatureData, &cert);
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

	res = KSI_PKISignedData_getSignatureValue(calAuth->signatureData, &signatureValue);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_OctetString_extract(signatureValue, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = verifyPublicationData(ctx, calAuth, raw, raw_len, cert);
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

static int verifySignatureWithExtender(KSI_CTX *ctx, KSI_Signature *sig) {
	KSI_ERR err;
	int res;
	KSI_Integer *sigTime = NULL;


	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_Signature_getSigningTime(sig, &sigTime);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_Signature_extend(sig, NULL, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int verifySignatureWithPublication(KSI_CTX *ctx, KSI_Signature *sig) {
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

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

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

static int verifySignature_internal(KSI_Signature *sig) {
	KSI_ERR err;
	KSI_DataHash *hsh = NULL;
	KSI_DataHash *pubHsh = NULL;
	time_t utc_time;
	int res;
	int level;
	size_t i;
	KSI_Integer *aggregationTime = NULL;
	KSI_Integer *publicationTime = NULL;
	KSI_LIST(KSI_HashChainLink) *chain = NULL;
	KSI_DataHash *inputHash = NULL;
	int hash_id;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	if (sig->aggregationChainList == NULL || KSI_AggregationHashChainList_length(sig->aggregationChainList) == 0) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signature does not contain any aggregation chains.");
		goto cleanup;
	}

	if (sig->calendarChain == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signature does not contain a calendar chain.");
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


	if ((time_t)KSI_Integer_getUInt64(aggregationTime) != utc_time) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Aggregation time mismatch.");
		goto cleanup;
	}

	/* Aggregate aggregation chains. */
	hsh = NULL;
	level = 0;

	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		const KSI_AggregationHashChain* aggregationChain = NULL;
		KSI_DataHash *tmpHash = NULL;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain);
		KSI_CATCH(&err, res) goto cleanup;

		if (aggregationChain == NULL) break;

		if (hsh != NULL) {
			/* Validate input hash */
			if (!KSI_DataHash_equals(hsh, aggregationChain->inputHash)) {
				KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Aggregation chain mismatch,");
			}
		}

		res = KSI_HashChain_aggregate(aggregationChain->chain, aggregationChain->inputHash, level, (int)KSI_Integer_getUInt64(aggregationChain->aggrHashId), &level, &tmpHash);
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


	if (sig->calendarAuthRec != NULL) {
		res = KSI_PublicationData_getImprint(sig->calendarAuthRec->pubData, &pubHsh);
		KSI_CATCH(&err, res) goto cleanup;

		/* Validate calendar root hash */
		if (!KSI_DataHash_equals(hsh, pubHsh)) {
			KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Calendar chain root hash mismatch.");
			goto cleanup;
		}
	}

	if (sig->aggregationAuthRec != NULL) {
		/* TODO! */
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Validation using aggregation auth record not implemented.");
		goto cleanup;
	}


	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(hsh);

	return KSI_RETURN(&err);
}


static int KSI_Signature_verifyInternal(KSI_CTX *ctx, KSI_Signature *sig) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = verifySignature_internal(sig);
	KSI_CATCH(&err, res) goto cleanup;

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

	/* Parse and extract the signature. */
	res = KSI_TlvTemplate_extract(ctx, sig, tlv, KSI_TLV_TEMPLATE(KSI_Signature), NULL);
	KSI_CATCH(&err, res) goto cleanup;


	int i;
	printf("Before\n");
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		KSI_AggregationHashChain *tmp = NULL;
		KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &tmp);
		printf("%d. @0x%x\n", i, tmp);
	}

	/* Make sure the aggregation chains are in correct order. */
	res = KSI_AggregationHashChainList_sort(sig->aggregationChainList, KSI_AggregationHashChain_compareTo);
	KSI_CATCH(&err, res) goto cleanup;

	printf("After\n");
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		KSI_AggregationHashChain *tmp = NULL;
		KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &tmp);
		printf("%d. @0x%x\n", i, tmp);
	}


	/* Verify the internal correctness. */
	res = KSI_Signature_verifyInternal(ctx, sig);
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

static int createPduTlv(KSI_CTX *ctx, unsigned tag, KSI_TLV **pdu) {
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
static int createSignRequest(KSI_CTX *ctx, const KSI_DataHash *hsh, unsigned char **raw, unsigned *raw_len) {
	KSI_ERR err;
	int res;
	KSI_AggregationReq *req = NULL;
	KSI_AggregationPdu *pdu = NULL;

	KSI_DataHash *tmpHash = NULL;
	KSI_TLV *pduTlv = NULL;

	unsigned char *tmp = NULL;
	unsigned tmp_len = 0;

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
static int createExtendRequest(KSI_CTX *ctx, const KSI_Integer *start, const KSI_Integer *end, unsigned char **raw, unsigned *raw_len) {
	KSI_ERR err;
	int res;
	KSI_TLV *pduTLV = NULL;
	KSI_ExtendPdu *pdu = NULL;
	KSI_ExtendReq *req = NULL;

	unsigned char *tmp = NULL;
	unsigned tmp_len = 0;

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

	if (end != NULL) {
		res = KSI_ExtendReq_setPublicationTime(req, KSI_Integer_clone(end));
		KSI_CATCH(&err, res) goto cleanup;
	}

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
	KSI_LIST(KSI_TLV) *nestedList = NULL;
	size_t i;

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

	res = KSI_TLV_getNestedList(sig->baseTlv, &nestedList);
	KSI_CATCH(&err, res) goto cleanup;

	for (i = 0; i < KSI_TLVList_length(nestedList); i++) {
		res = KSI_TLVList_elementAt(nestedList,i, &oldCalChainTlv);
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

	KSI_nofree(nestedList);
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
	for (i = (int)KSI_TLVList_length(nested) - 1; i >= 0; i--) {
		unsigned tag;

		res = KSI_TLVList_elementAt(nested, (unsigned)i, &tlv);
		KSI_CATCH(&err, res) goto cleanup;

		tag = KSI_TLV_getTag(tlv);

		if (tag == 0x0804 || tag == 0x0805) {
			res = KSI_TLVList_remove(nested, (unsigned)i);
			KSI_CATCH(&err, res) goto cleanup;

			KSI_TLV_free(tlv);
			tlv = NULL;
		}
	}

	if (sig->calendarAuthRec != NULL) {
		KSI_CalendarAuthRec_free(sig->calendarAuthRec);
		sig->calendarAuthRec = NULL;
	}

	if (sig->aggregationAuthRec != NULL) {
		KSI_AggregationAuthRec_free(sig->aggregationAuthRec);
		sig->aggregationAuthRec = NULL;
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
	size_t oldPubTlvPos = 0;
	bool oldPubTlvPos_found = false;


	KSI_LIST(KSI_TLV) *nestedList = NULL;
	int res;
	size_t i;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	if (pubRec != NULL) {
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
				oldPubTlvPos_found = true;
				break;
			}

			KSI_nofree(tmp);
		}

		if (oldPubTlvPos_found) {
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
	}
	/* Remove previous weaker authentication records. */
	res = removeWeakAuthRecords(sig);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int KSI_parseAggregationResponse(KSI_CTX *ctx, const unsigned char *response, unsigned response_len, KSI_Signature **signature) {
	KSI_ERR err;
	int res;
	KSI_TLV *pduTlv = NULL;
	KSI_TLV *tmpTlv = NULL;
	KSI_TLV *respTlv = NULL;
	KSI_Signature *tmp = NULL;
	KSI_AggregationPdu *pdu = NULL;
	KSI_AggregationResp *resp = NULL;
	KSI_LIST(KSI_TLV) *tlvList = NULL;

	/* PDU Specific objects */
	KSI_Integer *status = NULL;
	size_t i;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, response != NULL) goto cleanup;
	KSI_PRE(&err, response_len > 0) goto cleanup;

	KSI_BEGIN(ctx, &err);

	/* Parse the pdu */
	res = KSI_TLV_parseBlob(ctx, response, response_len, &pduTlv);
	KSI_CATCH(&err, res) goto cleanup;

	/* Validate tag value */
	if (KSI_TLV_getTag(pduTlv) != 0x200) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_AggregationPdu_new(ctx, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_extract(ctx, pdu, pduTlv, KSI_TLV_TEMPLATE(KSI_AggregationPdu), NULL);
	KSI_CATCH(&err, res) goto cleanup;


	res = KSI_AggregationPdu_getResponse(pdu, &resp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_AggregationResp_getStatus(resp, &status);
	KSI_CATCH(&err, res) goto cleanup;

	/* Check for the status of the response. */
	if (status != NULL && !KSI_Integer_equalsUInt(status, 0)) {
		KSI_Utf8String *errorMessage = NULL;
		char msg[1024];

		res = KSI_AggregationResp_getErrorMsg(resp, &errorMessage);
		KSI_CATCH(&err, res) goto cleanup;

		snprintf(msg, sizeof(msg), "Aggregation failed: %s", KSI_Utf8String_cstr(errorMessage));
		KSI_FAIL_EXT(&err, KSI_AGGREGATOR_ERROR, (long)KSI_Integer_getUInt64(status), KSI_Utf8String_cstr(errorMessage));
		goto cleanup;
	}

	res = KSI_Signature_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_AggregationResp_getAggregationAuthRec(resp, &tmp->aggregationAuthRec);
	KSI_CATCH(&err, res) goto cleanup;
	res = KSI_AggregationResp_setAggregationAuthRec(resp, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_AggregationResp_getAggregationChainList(resp, &tmp->aggregationChainList);
	KSI_CATCH(&err, res) goto cleanup;
	res = KSI_AggregationResp_setAggregationChainList(resp, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_AggregationResp_getCalendarAuthRec(resp, &tmp->calendarAuthRec);
	KSI_CATCH(&err, res) goto cleanup;
	res = KSI_AggregationResp_setCalendarAuthRec(resp, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_AggregationResp_getCalendarChain(resp, &tmp->calendarChain);
	KSI_CATCH(&err, res) goto cleanup;
	res = KSI_AggregationResp_setCalendarChain(resp, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	/* Get all elements from the pdu */
	res = KSI_TLV_getNestedList(pduTlv, &tlvList);
	KSI_CATCH(&err, res) goto cleanup;

	if (KSI_TLVList_length(tlvList) != 1) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	/* Get the aggregation response object. */
	res = KSI_TLVList_elementAt(tlvList, 0, &respTlv);
	KSI_CATCH(&err, res) goto cleanup;

	if (KSI_TLV_getTag(respTlv) != 0x0202) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	/* Create signature TLV */
	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, 0x0800, 0, 0, &tmpTlv);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_getNestedList(respTlv, &tlvList);
	KSI_CATCH(&err, res) goto cleanup;

	i = 0;
	while (i < KSI_TLVList_length(tlvList)) {
		KSI_TLV *t = NULL;
		res = KSI_TLVList_elementAt(tlvList, i, &t);
		KSI_CATCH(&err, res) goto cleanup;

		switch(KSI_TLV_getTag(t)) {
			case 0x01:
			case 0x02:
			case 0x05:
			case 0x06:
			case 0x10:
			case 0x12:
				/* Ignore these tags. */
				i++;
				break;
			default:
				/* Copy this tag to the signature. */
				res = KSI_TLV_appendNestedTlv(tmpTlv, NULL, t);
				KSI_CATCH(&err, res) goto cleanup;

				/* Remove it from the original list. */
				res = KSI_TLVList_remove(tlvList, i);
				KSI_CATCH(&err, res) goto cleanup;
		}
	}

	res = KSI_TLV_clone(tmpTlv, &tmp->baseTlv);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Signature", tmp->baseTlv);

	*signature = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmpTlv);
	KSI_AggregationPdu_free(pdu);
	KSI_Signature_free(tmp);
	KSI_TLV_free(pduTlv);

	return KSI_RETURN(&err);

}

int KSI_Signature_verify(KSI_Signature *sig, KSI_CTX *ctx) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctxp = ctx;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	if (ctxp == NULL) ctxp = sig->ctx;


	if (sig->publication != NULL) {
		/* Verify using publication. */
		res = verifySignatureWithPublication(ctxp, sig);
		KSI_CATCH(&err, res) goto cleanup;
	} else {
		if (sig->calendarAuthRec != NULL) {
			res = KSI_CalendarAuthRec_verify(ctxp, sig->calendarAuthRec);
			KSI_CATCH(&err, res) goto cleanup;
		}
		/* Verify using extender. */
		res = verifySignatureWithExtender(ctxp, sig);
		KSI_CATCH(&err, res) goto cleanup;
	}


	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_Signature_create(KSI_CTX *ctx, const KSI_DataHash *hsh, KSI_Signature **signature) {
	KSI_ERR err;
	int res;
	KSI_RequestHandle *handle = NULL;
	KSI_Signature *sign = NULL;

	unsigned char *req = NULL;
	unsigned req_len = 0;

	const unsigned char *resp = NULL;
	unsigned resp_len = 0;

	KSI_PRE(&err, hsh != NULL) goto cleanup;
	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	res = createSignRequest(ctx, hsh, &req, &req_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Request", req, req_len);

	res = KSI_sendSignRequest(ctx, req, req_len, &handle);
	KSI_CATCH(&err, res) goto cleanup;

	/* Read the response. */
	res = KSI_RequestHandle_getResponse(handle, &resp, &resp_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Response", resp, resp_len);

	res = KSI_parseAggregationResponse(ctx, resp, resp_len, &sign);
	KSI_CATCH(&err, res) goto cleanup;
	*signature = sign;
	sign = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Signature_free(sign);
	KSI_RequestHandle_free(handle);
	KSI_free(req);

	return KSI_RETURN(&err);
}

/* TODO Refactor into shorter functions. */
int KSI_Signature_extend(const KSI_Signature *signature, const KSI_PublicationRecord *pubRec, KSI_Signature **extended) {
	KSI_ERR err;
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
	unsigned rawReq_len = 0;

	const unsigned char *rawResp = NULL;
	unsigned rawResp_len = 0;

	KSI_TLV *respTlv = NULL;
	KSI_ExtendPdu *pdu = NULL;
	KSI_RequestHandle *handle = NULL;

	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_BEGIN(signature->ctx, &err);

	/* Make a copy of the original signature */
	res = KSI_Signature_clone(signature, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	/* Request the calendar hash chain from this moment on. */
	res = KSI_Signature_getSigningTime(tmp, &signTime);
	KSI_CATCH(&err, res) goto cleanup;

	/* If publication record is present, extract the publication time. */
	if (pubRec != NULL) {
		/* Make a copy of the original publication record .*/
		res = KSI_PublicationRecord_new(signature->ctx, &pubRecClone);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_TlvTemplate_deepCopy(signature->ctx, pubRec, KSI_TLV_TEMPLATE(KSI_PublicationRecord), pubRecClone);
		KSI_CATCH(&err, res) goto cleanup;

		/* Extract the published data object. */
		res = KSI_PublicationRecord_getPublishedData(pubRecClone, &pubData);
		KSI_CATCH(&err, res) goto cleanup;

		/* Read the publication time from the published data object. */
		res = KSI_PublicationData_getTime(pubData, &pubTime);
		KSI_CATCH(&err, res) goto cleanup;
	}

	/* Create request. */
	res = createExtendRequest(signature->ctx, signTime, pubTime, &rawReq, &rawReq_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(signature->ctx, KSI_LOG_DEBUG, "Extend request", rawReq, rawReq_len);

	/* Send the actual request. */
	res = KSI_sendExtendRequest(signature->ctx, rawReq, rawReq_len, &handle);
	KSI_CATCH(&err, res) goto cleanup;

	/* Read the response. */
	res = KSI_RequestHandle_getResponse(handle, &rawResp, &rawResp_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(signature->ctx, KSI_LOG_DEBUG, "Extend response", rawResp, rawResp_len);

	res = KSI_TLV_parseBlob(signature->ctx, rawResp, rawResp_len, &respTlv);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create response PDU object. */
	res = KSI_ExtendPdu_new(signature->ctx, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	/* Evaluate response PDU object. */
	res = KSI_TlvTemplate_extract(signature->ctx, pdu, respTlv, KSI_TLV_TEMPLATE(KSI_ExtendPdu), NULL);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logTlv(signature->ctx, KSI_LOG_DEBUG, "Parsed part of the response", respTlv);

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
		KSI_CATCH(&err, res) goto cleanup;

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
	res = KSI_Signature_verifyInternal(signature->ctx, tmp);
	KSI_CATCH(&err, res) goto cleanup;

	/* Return the extended signature only when requested. */
	if (extended != NULL) {
		*extended = tmp;
		tmp = NULL;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_PublicationRecord_free(pubRecClone);
	KSI_ExtendPdu_free(pdu);
	KSI_RequestHandle_free(handle);
	KSI_TLV_free(respTlv);
	KSI_free(rawReq);
	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);
}


void KSI_Signature_free(KSI_Signature *sig) {
	if (sig != NULL) {
		KSI_TLV_free(sig->baseTlv);
		KSI_CalendarHashChain_free(sig->calendarChain);
		KSI_AggregationHashChainList_freeAll(sig->aggregationChainList);
		KSI_CalendarAuthRec_free(sig->calendarAuthRec);
		KSI_AggregationAuthRec_free(sig->aggregationAuthRec);
		KSI_PublicationRecord_free(sig->publication);
		KSI_free(sig);
	}
}


int KSI_Signature_getDocumentHash(KSI_Signature *sig, const KSI_DataHash **hsh) {
	KSI_ERR err;
	KSI_AggregationHashChain *aggr = NULL;
	int res;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, hsh != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggr);
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
	KSI_Integer *tmp = NULL;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	if (sig->calendarChain == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	if (tmp == NULL) {
		res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &tmp);
		KSI_CATCH(&err, res) goto cleanup;

		if (tmp == NULL){
			KSI_FAIL(&err, KSI_INVALID_SIGNATURE, NULL);
			goto cleanup;
		}

	}

	*signTime = tmp;

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

int KSI_Signature_parse(KSI_CTX *ctx, unsigned char *raw, unsigned raw_len, KSI_Signature **sig) {
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
	size_t raw_len = 0;

	KSI_Signature *tmp = NULL;

	const unsigned raw_size = 0xfffff;

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

	res = KSI_Signature_parse(ctx, raw, (unsigned)raw_len, &tmp);
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

int KSI_Signature_serialize(KSI_Signature *sig, unsigned char **raw, unsigned *raw_len) {
	KSI_ERR err;
	int res;
	unsigned char *tmp = NULL;
	unsigned tmp_len;

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
	size_t i, j;
	KSI_List *idList = NULL;
	char *signerId = NULL;
	size_t signerId_size = 100;
	size_t signerId_len = 0;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, signerIdentity != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	/* Create a list of separate signer identities. */
	res = KSI_List_new(NULL, &idList);
	KSI_CATCH(&err, res) goto cleanup;

	/* Extract all identities from all aggregation chains from top to bottom. */
	for (i = KSI_AggregationHashChainList_length(sig->aggregationChainList); i-- > 0;) {
		KSI_AggregationHashChain *aggrRec = NULL;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &aggrRec);
		KSI_CATCH(&err, res) goto cleanup;

		for (j = KSI_HashChainLinkList_length(aggrRec->chain); j-- > 0;) {
			KSI_HashChainLink *link = NULL;
			KSI_MetaData *metaData = NULL;
			KSI_DataHash *metaHash = NULL;

			res = KSI_HashChainLinkList_elementAt(aggrRec->chain, j, &link);
			KSI_CATCH(&err, res) goto cleanup;

			/* Extract MetaHash */
			KSI_HashChainLink_getMetaHash(link, &metaHash);
			KSI_CATCH(&err, res) goto cleanup;

			/* Extract MetaData */
			KSI_HashChainLink_getMetaData(link, &metaData);
			KSI_CATCH(&err, res) goto cleanup;

			if (metaHash != NULL) {
				const char *tmp = NULL;
				int tmp_len;

				res = KSI_MetaHash_MetaHash_parseMeta(metaHash, (const unsigned char **)&tmp, &tmp_len);
				KSI_CATCH(&err, res) goto cleanup;

				signerId_size += tmp_len + 4;

				res = KSI_List_append(idList, (void *)tmp);
				KSI_CATCH(&err, res) goto cleanup;

			} else if (metaData != NULL) {
				KSI_Utf8String *clientId = NULL;

				res = KSI_MetaData_getClientId(metaData, &clientId);
				KSI_CATCH(&err, res) goto cleanup;

				signerId_size += KSI_Utf8String_size(clientId) + 4;

				res = KSI_List_append(idList, (void *)KSI_Utf8String_cstr(clientId));
				KSI_CATCH(&err, res) goto cleanup;
				clientId = NULL;

			} else {
				/* Exit inner loop if this chain link does not contain a meta value block. */
				continue;
			}


		}
	}

	/* Allocate the result buffer. */
	signerId = KSI_calloc(signerId_size, 1);
	if (signerId == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	/* Concatenate all together. */
	for (i = 0; i < KSI_List_length(idList); i++) {
		const char *tmp = NULL;

		res = KSI_List_elementAt(idList, i, (void **)&tmp);
		KSI_CATCH(&err, res) goto cleanup;

		signerId_len += (unsigned)snprintf(signerId + signerId_len, signerId_size - signerId_len, "%s%s", signerId_len > 0 ? " :: " : "", tmp);
	}

	*signerIdentity = signerId;
	signerId = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(signerId);
	KSI_List_free(idList);

	return KSI_RETURN(&err);
}

KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_PublicationRecord*, publication, PublicationRecord)

int KSI_Signature_getHashAlgorithm(KSI_Signature *sig, int *hash_id) {
	KSI_ERR err;
	const KSI_DataHash *hsh = NULL;
	int res;
	int tmp = -1;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	res = KSI_Signature_getDocumentHash(sig, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHash_extract(hsh, &tmp, NULL, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	*hash_id = tmp;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(hsh);

	return KSI_RETURN(&err);
}

int KSI_Signature_verifyDataHash(KSI_Signature *sig, KSI_DataHash *hsh) {
	KSI_ERR err;
	int res;
	const KSI_DataHash *sigHsh = NULL;

	KSI_PRE(&err, sig != KSI_OK) goto cleanup;
	KSI_PRE(&err, hsh != KSI_OK) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	res = KSI_Signature_getDocumentHash(sig, &sigHsh);
	KSI_CATCH(&err, res) goto cleanup;
	if (!KSI_DataHash_equals(hsh, sigHsh)) {
		KSI_FAIL(&err, KSI_WRONG_DOCUMENT, NULL);
		goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(sigHsh);

	return KSI_RETURN(&err);
}

int KSI_Signature_verifyDocument(KSI_Signature *sig, void *doc, size_t doc_len) {
	KSI_ERR err;
	int res;
	KSI_DataHash *hsh = NULL;

	int hash_id = -1;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, doc != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	res = KSI_Signature_getHashAlgorithm(sig, &hash_id);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHash_create(sig->ctx, doc, doc_len, hash_id, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_Signature_verifyDataHash(sig, hsh);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(hsh);

	return KSI_RETURN(&err);
}

int KSI_Signature_createDataHasher(KSI_Signature *sig, KSI_DataHasher **hsr) {
	KSI_ERR err;
	int res;
	KSI_DataHasher *tmp = NULL;
	int hash_id = -1;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, hsr != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	res = KSI_Signature_getHashAlgorithm(sig, &hash_id);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHasher_open(sig->ctx, hash_id, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*hsr = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHasher_free(tmp);

	return KSI_RETURN(&err);
}
