/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#include <string.h>

#include "internal.h"
#include "verification_impl.h"
#include "signature_impl.h"
#include "publicationsfile_impl.h"
#include "tlv.h"
#include "ctx_impl.h"
#include "tlv_template.h"
#include "hashchain.h"

typedef struct headerRec_st HeaderRec;

KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarHashChain);
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationHashChain)
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationAuthRec)
KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarAuthRec)

static int KSI_Signature_verifyPolicy(KSI_Signature *sig, unsigned *policy, KSI_CTX *ctx);

#define KSI_DEFINE_VERIFICATION_POLICY(name) unsigned name[] = {
#define KSI_END_VERIFICATION_POLICY , 0};

KSI_DEFINE_VERIFICATION_POLICY(KSI_VP_INTERNAL)
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN
KSI_END_VERIFICATION_POLICY

KSI_DEFINE_VERIFICATION_POLICY(KSI_VP_OFFLINE)
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC | KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE,
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBFILE
KSI_END_VERIFICATION_POLICY


KSI_DEFINE_VERIFICATION_POLICY(KSI_VP_DOCUMENT)
	KSI_VERIFY_DOCUMENT | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC | KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE,
	KSI_VERIFY_DOCUMENT | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBFILE,
	KSI_VERIFY_DOCUMENT | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_ONLINE
KSI_END_VERIFICATION_POLICY

KSI_DEFINE_VERIFICATION_POLICY(KSI_VP_SIGNATURE)
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC | KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE,
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBFILE,
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_ONLINE
KSI_END_VERIFICATION_POLICY


KSI_DEFINE_VERIFICATION_POLICY(KSI_VP_PARANOID)
	KSI_VERIFY_PUBFILE_SIGNATURE | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC | KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE | KSI_VERIFY_CALCHAIN_ONLINE,
	KSI_VERIFY_PUBFILE_SIGNATURE | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBFILE | KSI_VERIFY_CALCHAIN_ONLINE,
	KSI_VERIFY_PUBFILE_SIGNATURE | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_ONLINE
KSI_END_VERIFICATION_POLICY

static int addRequestId(
		KSI_CTX *ctx,
		void *req,
		int(getId)(void *, KSI_Integer **),
		int(setId)(void *, KSI_Integer *)) {
	KSI_ERR err;
	KSI_Integer *reqId = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, req != NULL) goto cleanup;
	KSI_PRE(&err, getId != NULL) goto cleanup;
	KSI_PRE(&err, setId != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = getId(req, &reqId);
	KSI_CATCH(&err, res) goto cleanup;

	if (reqId != NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Request already contains a request Id.");
		goto cleanup;
	}

	res = KSI_Integer_new(ctx, ++ctx->requestCounter, &reqId);
	KSI_CATCH(&err, res) goto cleanup;

	res = setId(req, reqId);
	KSI_CATCH(&err, res) goto cleanup;

	reqId = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Integer_free(reqId);

	return KSI_RETURN(&err);
}

static int addExtendRequestId(KSI_CTX *ctx, KSI_ExtendReq *req) {
	return addRequestId(
			ctx,
			req,
			(int(*)(void *, KSI_Integer **))KSI_ExtendReq_getRequestId,
			(int(*)(void *, KSI_Integer *))KSI_ExtendReq_setRequestId);
}

static int addAggregationRequestId(KSI_CTX *ctx, KSI_AggregationReq *req) {
	return addRequestId(
			ctx,
			req,
			(int(*)(void *, KSI_Integer **))KSI_AggregationReq_getRequestId,
			(int(*)(void *, KSI_Integer *))KSI_AggregationReq_setRequestId);
}

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

static int checkSignatureInternals(KSI_Signature *sig) {
	if (sig == NULL) return KSI_INVALID_ARGUMENT;
	if (sig->aggregationChainList == NULL || KSI_AggregationHashChainList_length(sig->aggregationChainList) == 0) return KSI_INVALID_FORMAT;
	if (sig->calendarChain == NULL && (sig->calendarAuthRec != NULL || sig->publication != NULL)) return KSI_INVALID_FORMAT;
	return KSI_OK;
}

/**
 * KSI_AggregationHashChain
 */
void KSI_AggregationHashChain_free(KSI_AggregationHashChain *aggr) {
	if (aggr != NULL) {
		KSI_Integer_free(aggr->aggrHashId);
		KSI_Integer_free(aggr->aggregationTime);
		KSI_IntegerList_free(aggr->chainIndex);
		KSI_OctetString_free(aggr->inputData);
		KSI_DataHash_free(aggr->inputHash);
		KSI_HashChainLinkList_free(aggr->chain);
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
	tmp->aggrHashId = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_AggregationHashChain_free(tmp);

	return KSI_RETURN(&err);
}

KSI_IMPLEMENT_GETTER(KSI_AggregationHashChain, KSI_Integer*, aggregationTime, AggregationTime)
KSI_IMPLEMENT_GETTER(KSI_AggregationHashChain, KSI_LIST(KSI_Integer)*, chainIndex, ChainIndex)
KSI_IMPLEMENT_GETTER(KSI_AggregationHashChain, KSI_OctetString*, inputData, InputData)
KSI_IMPLEMENT_GETTER(KSI_AggregationHashChain, KSI_DataHash*, inputHash, InputHash)
KSI_IMPLEMENT_GETTER(KSI_AggregationHashChain, KSI_Integer*, aggrHashId, AggrHashId)
KSI_IMPLEMENT_GETTER(KSI_AggregationHashChain, KSI_LIST(KSI_HashChainLink) *, chain, Chain)

KSI_IMPLEMENT_SETTER(KSI_AggregationHashChain, KSI_Integer*, aggregationTime, AggregationTime)
KSI_IMPLEMENT_SETTER(KSI_AggregationHashChain, KSI_LIST(KSI_Integer)*, chainIndex, ChainIndex)
KSI_IMPLEMENT_SETTER(KSI_AggregationHashChain, KSI_OctetString*, inputData, InputData)
KSI_IMPLEMENT_SETTER(KSI_AggregationHashChain, KSI_DataHash*, inputHash, InputHash)
KSI_IMPLEMENT_SETTER(KSI_AggregationHashChain, KSI_Integer*, aggrHashId, AggrHashId)
KSI_IMPLEMENT_SETTER(KSI_AggregationHashChain, KSI_LIST(KSI_HashChainLink) *, chain, Chain)

/**
 * KSI_AggregationAuthRec
 */
void KSI_AggregationAuthRec_free(KSI_AggregationAuthRec *aar) {
	if (aar != NULL) {
		KSI_Integer_free(aar->aggregationTime);
		KSI_IntegerList_free(aar->chainIndexesList);
		KSI_DataHash_free(aar->inputHash);
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
	res = KSI_IntegerList_new(&tmp->chainIndexesList);
	KSI_CATCH(&err, res) goto cleanup;

	tmp->inputHash = NULL;
	tmp->ctx = ctx;
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
KSI_IMPLEMENT_GETTER(KSI_AggregationAuthRec, KSI_PKISignedData*, signatureData, SigData)

KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_Integer*, aggregationTime, AggregationTime)
KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_LIST(KSI_Integer)*, chainIndexesList, ChainIndex)
KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_DataHash*, inputHash, InputHash)
KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_PKISignedData*, signatureData, SigData)

/**
 * KSI_CalendarAuthRec
 */

void KSI_CalendarAuthRec_free(KSI_CalendarAuthRec *calAuth) {
	if (calAuth != NULL) {
		KSI_PublicationData_free(calAuth->pubData);
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
	tmp->signatureData = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_CalendarAuthRec_free(tmp);

	return KSI_RETURN(&err);

}
KSI_IMPLEMENT_SETTER(KSI_CalendarAuthRec, KSI_PublicationData*, pubData, PublishedData)
KSI_IMPLEMENT_SETTER(KSI_CalendarAuthRec, KSI_PKISignedData*, signatureData, SignatureData)

KSI_IMPLEMENT_GETTER(KSI_CalendarAuthRec, KSI_PublicationData*, pubData, PublishedData)
KSI_IMPLEMENT_GETTER(KSI_CalendarAuthRec, KSI_PKISignedData*, signatureData, SignatureData)

KSI_IMPLEMENT_LIST(KSI_AggregationHashChain, KSI_AggregationHashChain_free);

KSI_DEFINE_TLV_TEMPLATE(KSI_Signature)
	KSI_TLV_COMPOSITE_LIST(0x0801, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Signature_getAggregationChainList, KSI_Signature_setAggregationChainList, KSI_AggregationHashChain, "aggr_chain")
	KSI_TLV_COMPOSITE(0x0802, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Signature_getCalendarChain, KSI_Signature_setCalendarChain, KSI_CalendarHashChain, "cal_chain")
	KSI_TLV_COMPOSITE(0x0803, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_Signature_getPublicationRecord, KSI_Signature_setPublicationRecord, KSI_PublicationRecord, "pub_rec")
	KSI_TLV_COMPOSITE(0x0804, KSI_TLV_TMPL_FLG_NONE, KSI_Signature_getAggregationAuthRecord, KSI_Signature_setAggregationAuthRecord, KSI_AggregationAuthRec, "aggr_auth_rec")
	KSI_TLV_COMPOSITE(0x0805, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_Signature_getCalendarAuthRecord, KSI_Signature_setCalendarAuthRecord, KSI_CalendarAuthRec, "cal_auth_rec")
KSI_END_TLV_TEMPLATE

static int KSI_Signature_new(KSI_CTX *ctx, KSI_Signature **sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || sig == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_Signature);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->calendarChain = NULL;
	tmp->baseTlv = NULL;
	tmp->publication = NULL;
	tmp->aggregationChainList = NULL;
	tmp->aggregationAuthRec = NULL;
	tmp->aggregationChainList = NULL;
	tmp->calendarAuthRec = NULL;
	tmp->publication = NULL;

	res = KSI_VerificationResult_init(&tmp->verificationResult, ctx);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*sig = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Signature_free(tmp);

	return res;

}

static int intCmp(KSI_uint64_t a, KSI_uint64_t b){
	if (a == b) return 0;
	else if (a > b) return 1;
	else return -1;
}

static int aggregationHashChainCmp(const KSI_AggregationHashChain **left, const KSI_AggregationHashChain **right) {
	const KSI_AggregationHashChain *l = *left;
	const KSI_AggregationHashChain *r = *right;
	if (l == r || l == NULL || r == NULL || l->chainIndex == NULL || r->chainIndex == NULL) {
		return intCmp((KSI_uint64_t)right, (KSI_uint64_t)left);
	}
	return intCmp(KSI_IntegerList_length(r->chainIndex), KSI_IntegerList_length(l->chainIndex));
}

static int extractSignature(KSI_CTX *ctx, KSI_TLV *tlv, KSI_Signature **signature) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_Signature *sig = NULL;
	KSI_CalendarHashChain *cal = NULL;
	KSI_Integer *aggregationTime = NULL;
	KSI_Integer *publicationTime = NULL;
	KSI_DataHash *inputHash = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || tlv == NULL || signature == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (KSI_TLV_getTag(tlv) != 0x800) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_Signature_new(ctx, &sig);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Parse and extract the signature. */
	res = KSI_TlvTemplate_extract(ctx, sig, tlv, KSI_TLV_TEMPLATE(KSI_Signature));
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = checkSignatureInternals(sig);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Make sure the aggregation chains are in correct order. */
	res = KSI_AggregationHashChainList_sort(sig->aggregationChainList, aggregationHashChainCmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*signature = sig;
	sig = NULL;

	KSI_LOG_debug(ctx, "Finished parsing successfully.");

	res = KSI_OK;

cleanup:

	KSI_Integer_free(aggregationTime);
	KSI_Integer_free(publicationTime);
	KSI_DataHash_free(inputHash);

	KSI_CalendarHashChain_free(cal);
	KSI_Signature_free(sig);

	return res;
}

/***************
 * SIGN REQUEST
 ***************/
static int createSignRequest(KSI_CTX *ctx, KSI_DataHash *hsh, KSI_AggregationReq **request) {
	KSI_ERR err;
	int res;
	KSI_AggregationReq *tmp = NULL;

	KSI_DataHash *tmpHash = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, hsh != NULL) goto cleanup;
	KSI_PRE(&err, request != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	/* Create request object */
	res = KSI_AggregationReq_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = addAggregationRequestId(ctx, tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHash_clone(hsh, &tmpHash);
	KSI_CATCH(&err, res) goto cleanup;

	/* Add the hash to the request */
	res = KSI_AggregationReq_setRequestHash(tmp, tmpHash);
	KSI_CATCH(&err, res) goto cleanup;
	tmpHash = NULL;

	*request = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:


	KSI_DataHash_free(tmpHash);
	KSI_AggregationReq_free(tmp);

	return KSI_RETURN(&err);
}

/*****************
 * EXTEND REQUEST
 *****************/
static int createExtendRequest(KSI_CTX *ctx, KSI_Integer *start, KSI_Integer *end, KSI_ExtendReq **request) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendReq *tmp = NULL;

	/* Validate input. */
	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || start == NULL || request == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* Validate correctness of end date. */
	if (end != NULL && KSI_Integer_compare(start, end) > 0) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Aggregation time may not be greater than the publication time.");
		goto cleanup;
	}

	/* Create extend request object. */
	res = KSI_ExtendReq_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = addExtendRequestId(ctx, tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Make a virtual copy of the start object. */
	KSI_Integer_ref(start);

	/* Set the aggregation time. */
	KSI_ExtendReq_setAggregationTime(tmp, start);

	if (end != NULL) {
		KSI_Integer_ref(end);
		KSI_ExtendReq_setPublicationTime(tmp, end);
	}

	*request = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_ExtendReq_free(tmp);

	return res;
}

int KSI_Signature_replaceCalendarChain(KSI_Signature *sig, KSI_CalendarHashChain *calendarHashChain) {
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

		if (KSI_TLV_getTag(oldCalChainTlv) == 0x0802) break;
	}

	res = KSI_TLV_new(sig->ctx, KSI_TLV_PAYLOAD_TLV, 0x0802, 0, 0, &newCalChainTlv);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_construct(sig->ctx, newCalChainTlv, calendarHashChain, KSI_TLV_TEMPLATE(KSI_CalendarHashChain));
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_replaceNestedTlv(sig->baseTlv, oldCalChainTlv, newCalChainTlv);
	KSI_CATCH(&err, res) goto cleanup;
	newCalChainTlv = NULL;

	/* The memory was freed within KSI_TLV_replaceNestedTlv. */
	oldCalChainTlv = NULL;

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

static int removeCalAuthAndPublication(KSI_Signature *sig) {
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

		if (tag == 0x0803 || tag == 0x0805) {
			res = KSI_TLVList_remove(nested, (unsigned)i, NULL);
			KSI_CATCH(&err, res) goto cleanup;
			tlv = NULL;
		}
	}

	KSI_CalendarAuthRec_free(sig->calendarAuthRec);
	sig->calendarAuthRec = NULL;

	KSI_PublicationRecord_free(sig->publication);
	sig->publication = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(nested);
	KSI_nofree(tlv);

	return KSI_RETURN(&err);
}

int KSI_Signature_replacePublicationRecord(KSI_Signature *sig, KSI_PublicationRecord *pubRec) {
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
		/* Remove auth records. */
		res = removeCalAuthAndPublication(sig);
		KSI_CATCH(&err, res) goto cleanup;

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

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int KSI_parseAggregationResponse(KSI_CTX *ctx, KSI_AggregationResp *resp, KSI_Signature **signature) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmpTlv = NULL;
	KSI_TLV *respTlv = NULL;
	KSI_Signature *tmp = NULL;
	KSI_LIST(KSI_TLV) *tlvList = NULL;

	/* PDU Specific objects */
	KSI_Integer *status = NULL;
	size_t i;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, resp != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	/* Parse the pdu */
	res = KSI_AggregationResp_getBaseTlv(resp, &respTlv);
	KSI_CATCH(&err, res) goto cleanup;
	
	/* Validate tag value */
	if (KSI_TLV_getTag(respTlv) != 0x202) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_getStatus(resp, &status);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_convertAggregatorStatusCode(status);
	/* Check for the status of the response. */
	if (res != KSI_OK) {
		KSI_Utf8String *errorMessage = NULL;
		char msg[1024];

		KSI_AggregationResp_getErrorMsg(resp, &errorMessage);

		KSI_snprintf(msg, sizeof(msg), "Aggregation failed: %s", KSI_Utf8String_cstr(errorMessage));
		KSI_FAIL_EXT(&err, res, (long)KSI_Integer_getUInt64(status), KSI_Utf8String_cstr(errorMessage));
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

		switch (KSI_TLV_getTag(t)) {
			case 0x01:
			case 0x04:
			case 0x05:
			case 0x10:
			case 0x11:
				/* Ignore these tags. */
				i++;
				break;
			default:
				/* Remove it from the original list. */
				res = KSI_TLVList_remove(tlvList, i, &t);
				KSI_CATCH(&err, res) goto cleanup;

				/* Copy this tag to the signature. */
				res = KSI_TLV_appendNestedTlv(tmpTlv, NULL, t);
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
	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);
}


int KSI_Signature_create(KSI_CTX *ctx, KSI_DataHash *hsh, KSI_Signature **signature) {
	KSI_ERR err;
	int res;
	KSI_RequestHandle *handle = NULL;
	KSI_AggregationResp *response = NULL;
	KSI_Signature *sign = NULL;
	
	KSI_AggregationReq *req = NULL;


	KSI_PRE(&err, hsh != NULL) goto cleanup;
	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	res = createSignRequest(ctx, hsh, &req);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_sendSignRequest(ctx, req, &handle);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_RequestHandle_getAggregationResponse(handle, &response);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_parseAggregationResponse(ctx, response, &sign);
	KSI_CATCH(&err, res) goto cleanup;
	
	*signature = sign;
	sign = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_AggregationResp_free(response);
	KSI_Signature_free(sign);
	KSI_RequestHandle_free(handle);
	KSI_AggregationReq_free(req);

	return KSI_RETURN(&err);
}

static int failOnExtendRespError(KSI_CTX *ctx, KSI_ExtendResp *response) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *respStatus = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || response == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_ExtendResp_getStatus(response, &respStatus);
	if (res != KSI_OK) goto cleanup;

	res = KSI_convertExtenderStatusCode(respStatus);
	/* Fail if status is presend and does not equal to success (0) */
	if (res != KSI_OK) {
		char buf[1024];
		KSI_Utf8String *error = NULL;
		KSI_ExtendResp_getErrorMsg(response, &error);

		KSI_snprintf(buf, sizeof(buf), "Extender error(%u): %s", KSI_Integer_getUInt64(respStatus), KSI_Utf8String_cstr(error));

		KSI_pushError(ctx, res, buf); // FIXME: Add external error code.

		KSI_nofree(error);
		goto cleanup;
	}


	res = KSI_OK;

cleanup:

	KSI_nofree(respStatus);

	return res;
}

int KSI_Signature_extendTo(const KSI_Signature *sig, KSI_CTX *ctx, KSI_Integer *to, KSI_Signature **extended) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendReq *req = NULL;
	KSI_Integer *signTime = NULL;
	KSI_RequestHandle *handle = NULL;
	KSI_ExtendResp *response = NULL;
	KSI_CalendarHashChain *calHashChain = NULL;
	KSI_Signature *tmp = NULL;


	KSI_ERR_clearErrors(ctx);
	if (sig == NULL || ctx == NULL || extended == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* Make a copy of the original signature */
	res = KSI_Signature_clone(sig, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Request the calendar hash chain from this moment on. */
	res = KSI_Signature_getSigningTime(sig, &signTime);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Create request. */
	res = createExtendRequest(ctx, signTime, to, &req);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Send the actual request. */
	res = KSI_sendExtendRequest(ctx, req, &handle);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Get and parse the response. */
	res = KSI_RequestHandle_getExtendResponse(handle, &response);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Verify the response is ok. */
	res = failOnExtendRespError(ctx, response);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Extract the calendar hash chain */
	KSI_ExtendResp_getCalendarHashChain(response, &calHashChain);

	/* Remove the chain from the structure, as it will be freed when this function finishes. */
	KSI_ExtendResp_setCalendarHashChain(response, NULL);

	/* Add the hash chain to the signature. */
	res = KSI_Signature_replaceCalendarChain(tmp, calHashChain);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Remove calendar auth record and publication. */
	res = removeCalAuthAndPublication(tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Just to be sure, verify the internals. */
	res = KSI_Signature_verifyPolicy(tmp, KSI_VP_INTERNAL , ctx);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*extended = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_ExtendReq_free(req);
	KSI_ExtendResp_free(response);
	KSI_RequestHandle_free(handle);
	KSI_Signature_free(tmp);

	return res;
}

int KSI_Signature_extend(const KSI_Signature *signature, KSI_CTX *ctx, const KSI_PublicationRecord *pubRec, KSI_Signature **extended) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *respStatus = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_PublicationRecord *pubRecClone = NULL;
	KSI_Signature *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (signature == NULL || ctx == NULL || extended == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* If publication record is present, extract the publication time. */
	if (pubRec != NULL) {
		KSI_PublicationData *pubData = NULL;

		/* Make a copy of the original publication record .*/
		res = KSI_PublicationRecord_new(signature->ctx, &pubRecClone);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_TlvTemplate_deepCopy(signature->ctx, pubRec, KSI_TLV_TEMPLATE(KSI_PublicationRecord), pubRecClone);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		/* Extract the published data object. */
		res = KSI_PublicationRecord_getPublishedData(pubRec, &pubData);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		/* Read the publication time from the published data object. */
		res = KSI_PublicationData_getTime(pubData, &pubTime);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Perform the actual extension. */
	res = KSI_Signature_extendTo(signature, ctx, pubTime, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Set the publication as the trust anchor. */
	res = KSI_Signature_replacePublicationRecord(tmp, pubRecClone);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	pubRecClone = NULL;

	/* To be sure we won't return a bad signature, lets verify it. */
	if (pubRecClone == NULL) {
		/* Just to be sure, verify the internals. */
		res = KSI_Signature_verifyPolicy(tmp, KSI_VP_INTERNAL, ctx);
	} else {
		/* Perform an actual verification. */
		res = KSI_Signature_verifyPolicy(tmp, KSI_VP_OFFLINE, ctx);
	}

	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*extended = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_PublicationRecord_free(pubRecClone);
	KSI_Signature_free(tmp);

	return res;
}

void KSI_Signature_free(KSI_Signature *sig) {
	if (sig != NULL) {
		KSI_TLV_free(sig->baseTlv);
		KSI_CalendarHashChain_free(sig->calendarChain);
		KSI_AggregationHashChainList_free(sig->aggregationChainList);
		KSI_CalendarAuthRec_free(sig->calendarAuthRec);
		KSI_AggregationAuthRec_free(sig->aggregationAuthRec);
		KSI_PublicationRecord_free(sig->publication);
		KSI_VerificationResult_reset(&sig->verificationResult);

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
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *tmp = NULL;

	if (sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(sig->ctx);

	if (signTime == NULL) {
		KSI_pushError(sig->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (sig->calendarChain == NULL) {
		KSI_pushError(sig->ctx, res = KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	if (tmp == NULL) {
		res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &tmp);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		if (tmp == NULL){
			KSI_pushError(sig->ctx, res = KSI_INVALID_SIGNATURE, NULL);
			goto cleanup;
		}

	}

	*signTime = tmp;

	res = KSI_OK;

cleanup:

	return res;
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

	const unsigned raw_size = 0xffff + 4;

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
	size_t signerId_size = 1; // At least 1 for trailing zero.
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

				res = KSI_DataHash_MetaHash_parseMeta(metaHash, (const unsigned char **)&tmp, &tmp_len);
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

		signerId_len += (unsigned)KSI_snprintf(signerId + signerId_len, signerId_size - signerId_len, "%s%s", signerId_len > 0 ? " :: " : "", tmp);
	}

	*signerIdentity = signerId;
	signerId = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(signerId);
	KSI_List_free(idList);

	return KSI_RETURN(&err);
}

KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_CalendarAuthRec*, calendarAuthRec, CalendarAuthRec)

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

int KSI_Signature_verifyDocument(KSI_Signature *sig, KSI_CTX *ctx, void *doc, size_t doc_len) {
	KSI_ERR err;
	int res;
	KSI_DataHash *hsh = NULL;

	int hash_id = -1;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, doc != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_Signature_getHashAlgorithm(sig, &hash_id);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHash_create(ctx, doc, doc_len, hash_id, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_Signature_verifyDataHash(sig, ctx, hsh);
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

static int initPublicationsFile(KSI_VerificationResult *info, KSI_CTX *ctx) {
	int res = KSI_UNKNOWN_ERROR;

	if (info->publicationsFile == NULL) {
		res = KSI_receivePublicationsFile(ctx, &info->publicationsFile);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;
cleanup:

	return res;
}

static int verifyInternallyAggregationChain(KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	int level;
	size_t i;
	int successCount = 0;
	KSI_VerificationStep step = KSI_VERIFY_AGGRCHAIN_INTERNALLY;
	KSI_VerificationResult *info = &sig->verificationResult;
	const KSI_AggregationHashChain *prevChain = NULL;

	/* Aggregate aggregation chains. */
	hsh = NULL;
	level = 0;

	KSI_LOG_info(sig->ctx, "Verifying aggregation hash chain internal consistency.");


	/* Aggregate all the aggregation chains. */
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		const KSI_AggregationHashChain* aggregationChain = NULL;
		KSI_DataHash *tmpHash = NULL;


		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain);
		if (res != KSI_OK) goto cleanup;

		if (aggregationChain == NULL) break;

		if (prevChain != NULL) {
			/* Verify aggregation time. */
			if (!KSI_Integer_equals(aggregationChain->aggregationTime, prevChain->aggregationTime)) {
				res = KSI_VerificationResult_addFailure(info, step, "Aggregation hash chain's from different aggregation rounds.");
				goto cleanup;
			}

			/* Verify chain index length. */
			if (KSI_IntegerList_length(prevChain->chainIndex) != KSI_IntegerList_length(aggregationChain->chainIndex) + 1) {
				res = KSI_VerificationResult_addFailure(info, step, "Unexpected chain index length in aggregation chain.");
				goto cleanup;
			} else {
				int j;
				for (j = 0; j < KSI_IntegerList_length(aggregationChain->chainIndex); j++) {
					KSI_Integer *chainIndex1 = NULL;
					KSI_Integer *chainIndex2 = NULL;

					res = KSI_IntegerList_elementAt(prevChain->chainIndex, j, &chainIndex1);
					if (res != KSI_OK) goto cleanup;

					res = KSI_IntegerList_elementAt(aggregationChain->chainIndex, j, &chainIndex2);
					if (res != KSI_OK) goto cleanup;

					if (!KSI_Integer_equals(chainIndex1, chainIndex2)) {
						res = KSI_VerificationResult_addFailure(info, step, "Aggregation chain chain index is not continuation of previous chain index.");
						goto cleanup;
					}
				}
			}



		}

		if (hsh != NULL) {
			/* Validate input hash */
			if (!KSI_DataHash_equals(hsh, aggregationChain->inputHash)) {
				KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Calculated hash", hsh);
				KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "  Expected hash", aggregationChain->inputHash);
				break;
			}
		}

		res = KSI_HashChain_aggregate(aggregationChain->ctx, aggregationChain->chain, aggregationChain->inputHash, level, (int)KSI_Integer_getUInt64(aggregationChain->aggrHashId), &level, &tmpHash);
		if (res != KSI_OK) goto cleanup;

		/* TODO! Instead of freeing the object - reuse it */
		if (hsh != NULL) {
			KSI_DataHash_free(hsh);
		}

		hsh = tmpHash;


		++successCount;

		prevChain = aggregationChain;
	}

	/* First verify internal calculations. */
	if (successCount != KSI_AggregationHashChainList_length(sig->aggregationChainList)) {
		res = KSI_VerificationResult_addFailure(info, step, "Aggregation hash chain calculation failed.");
		goto cleanup;
	}

	sig->verificationResult.aggregationHash = hsh;
	hsh = NULL;

	res = KSI_VerificationResult_addSuccess(info,  step,"Aggregation chain internally consistent.");

cleanup:

	KSI_DataHash_free(hsh);

	return res;
}

static int verifyAggregationRootWithCalendarChain(KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *inputHash = NULL;
	KSI_VerificationStep step = KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN;
	KSI_VerificationResult *info = &sig->verificationResult;
	KSI_AggregationHashChain *aggregationChain = NULL;
	KSI_Integer *calAggrTime = NULL;

	KSI_LOG_info(sig->ctx, "Verifying aggrgeation hash chain root.");

	res = KSI_CalendarHashChain_getInputHash(sig->calendarChain, &inputHash);
	if (res != KSI_OK) goto cleanup;

	/* Take the first aggregation hash chain, as all of the chain should have
	 * the same value for "aggregation time". */
	res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggregationChain);
	if (res != KSI_OK) goto cleanup;

	if (!KSI_DataHash_equals(sig->verificationResult.aggregationHash, inputHash)) {
		res = KSI_VerificationResult_addFailure(info, step, "Aggregation root hash mismatch.");
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &calAggrTime);
	if (res != KSI_OK) goto cleanup;

	if (!KSI_Integer_equals(calAggrTime, aggregationChain->aggregationTime)) {
		res = KSI_VerificationResult_addFailure(info, step, "Aggregation time in calendar chain and aggregation chain differ.");
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_VerificationResult_addSuccess(info, step, "Aggregation root matches with calendar chain.");
	if (res != KSI_OK) goto cleanup;

cleanup:

	KSI_nofree(calAggrTime);
	KSI_nofree(aggregationChain);

	return res;
}

static int verifyCalendarChain(KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *rootHash = NULL;
	KSI_Integer *calendarPubTm = NULL;
	KSI_PublicationData *pubData = NULL;
	KSI_DataHash *pubHash = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_VerificationStep step = KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC;
	KSI_VerificationResult *info = &sig->verificationResult;

	if (sig->calendarAuthRec == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(sig->ctx, "Verifying calendar hash chain.");

	/* Calculate the root hash value. */
	res = KSI_CalendarHashChain_aggregate(sig->calendarChain, &rootHash);
	if (res != KSI_OK) goto cleanup;

	/* Get the publication time from calendar hash chain. */
	res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &calendarPubTm);
	if (res != KSI_OK) goto cleanup;

	/* Get publication data. */
	res = KSI_CalendarAuthRec_getPublishedData(sig->calendarAuthRec, &pubData);
	if (res != KSI_OK) goto cleanup;

	/* Get published hash value. */
	res = KSI_PublicationData_getImprint(pubData, &pubHash);
	if (res != KSI_OK) goto cleanup;

	/* Get publication time. */
	res = KSI_PublicationData_getTime(pubData, &pubTime);
	if (res != KSI_OK) goto cleanup;

	if (KSI_Integer_equals(calendarPubTm, pubTime) && KSI_DataHash_equals(rootHash, pubHash)) {
		res = KSI_VerificationResult_addSuccess(info, step, "Calendar chain and authentication record match.");
	} else {
		res = KSI_VerificationResult_addFailure(info, step, "Calendar chain and authentication record mismatch.");
	}

	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(rootHash);

	return res;
}

static int verifyInternallyCalendarChain(KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;
	time_t calculatedAggrTm;
	KSI_Integer *calendarAggrTm = NULL;
	KSI_VerificationStep step = KSI_VERIFY_CALCHAIN_INTERNALLY;
	KSI_VerificationResult *info = &sig->verificationResult;

	KSI_LOG_info(sig->ctx, "Verifying calendar hash chain internally.");

	res = KSI_CalendarHashChain_calculateAggregationTime(sig->calendarChain, &calculatedAggrTm);
	if (res != KSI_OK) goto cleanup;

	res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &calendarAggrTm);
	if (res != KSI_OK) goto cleanup;

	if (KSI_Integer_equalsUInt(calendarAggrTm, (KSI_uint64_t) calculatedAggrTm)) {
		res = KSI_VerificationResult_addSuccess(info, step, "Calendar chain internally consistent.");
	} else {
		res = KSI_VerificationResult_addFailure(info, step, "Calendar chain internally inconsistent.");
	}

cleanup:

	return res;
}

static int verifyCalAuthRec(KSI_CTX *ctx, KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_OctetString *certId = NULL;
	KSI_PKICertificate *cert = NULL;
	KSI_OctetString *signatureValue = NULL;
	KSI_Utf8String *sigtype = NULL;
	const unsigned char *rawSignature = NULL;
	unsigned rawSignature_len;
	unsigned char *rawData = NULL;
	unsigned rawData_len;
	KSI_VerificationStep step = KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE;
	KSI_VerificationResult *info = &sig->verificationResult;


	if (sig->calendarAuthRec == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(sig->ctx, "Verifying calendar authentication record.");

	res = KSI_PKISignedData_getCertId(sig->calendarAuthRec->signatureData, &certId);
	if (res != KSI_OK) goto cleanup;

	if (certId == NULL) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	res = initPublicationsFile(&sig->verificationResult, ctx);
	if (res != KSI_OK) goto cleanup;

	res = KSI_PublicationsFile_getPKICertificateById(sig->verificationResult.publicationsFile, certId, &cert);
	if (res != KSI_OK) goto cleanup;

	if (cert == NULL) {
		res = KSI_VerificationResult_addFailure(info, step, "Certificate not found");
		goto cleanup;
	}

	res = KSI_PKISignedData_getSignatureValue(sig->calendarAuthRec->signatureData, &signatureValue);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OctetString_extract(signatureValue, &rawSignature, &rawSignature_len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TLV_serialize(sig->calendarAuthRec->pubData->baseTlv, &rawData, &rawData_len);
	if (res != KSI_OK) goto cleanup;
	
	res = KSI_PKISignedData_getSigType(sig->calendarAuthRec->signatureData, &sigtype);
	if (res != KSI_OK) goto cleanup;
	
		
	res = KSI_PKITruststore_verifyRawSignature(sig->ctx, rawData, rawData_len, KSI_Utf8String_cstr(sigtype), rawSignature, rawSignature_len, cert);

	if (res != KSI_OK) {
		res = KSI_VerificationResult_addFailure(info, step, "Calendar authentication record signature not verified.");
		goto cleanup;
	}

	res = KSI_VerificationResult_addSuccess(info, step, "Calendar authentication record correct.");

cleanup:

	KSI_free(rawData);

	return res;
}

static int verifyPublication(KSI_CTX *ctx, KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_VerificationStep step = KSI_VERIFY_PUBLICATION_WITH_PUBFILE;
	KSI_VerificationResult *info = &sig->verificationResult;


	if (sig->publication == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(sig->ctx, "Verifying publication");

	if (sig->verificationResult.useUserPublication) {
		res = KSI_OK;
		goto cleanup;
	}

	res = KSI_receivePublicationsFile(ctx, &pubFile);
	if (res != KSI_OK) goto cleanup;

	res = KSI_PublicationsFile_findPublication(pubFile, sig->publication, &pubRec);
	if (res != KSI_OK) goto cleanup;

	if (pubRec == NULL) {
		res = KSI_VerificationResult_addFailure(info, step, "Publication not trusted.");
		goto cleanup;
	}

	res = KSI_VerificationResult_addSuccess(info, step, "Publication trusted.");

cleanup:

	return res;
}

static int verifyDocument(KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;
	const KSI_DataHash *hsh = NULL;
	KSI_VerificationStep step = KSI_VERIFY_DOCUMENT;
	KSI_VerificationResult *info = &sig->verificationResult;

	if (!sig->verificationResult.verifyDocumentHash) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(sig->ctx, "Verifying document hash.");
	KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Verifying document hash", sig->verificationResult.documentHash);

	res = KSI_Signature_getDocumentHash(sig, &hsh);
	if (res != KSI_OK) goto cleanup;

	if (!KSI_DataHash_equals(hsh, sig->verificationResult.documentHash)) {
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Document hash", sig->verificationResult.documentHash);
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Signed   hash", hsh);

		res = KSI_VerificationResult_addFailure(info, step, "Wrong document");
		goto cleanup;
	}

	res = KSI_VerificationResult_addSuccess(info, step, "Document correct.");

cleanup:

	KSI_nofree(hsh);
	KSI_nofree(info);

	return res;
}

static int verifyPublicationsFile(KSI_CTX *ctx, KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationStep step = KSI_VERIFY_PUBFILE_SIGNATURE;
	KSI_VerificationResult *info = &sig->verificationResult;

	KSI_LOG_debug(sig->ctx, "Verifying publications file.");

	res = initPublicationsFile(&sig->verificationResult, ctx);
	if (res != KSI_OK) goto cleanup;

	res = KSI_PublicationsFile_verify(sig->verificationResult.publicationsFile, ctx);
	if (res == KSI_OK) {
		res = KSI_VerificationResult_addSuccess(info, step, "Publications file verified.");
	} else {
		res = KSI_VerificationResult_addFailure(info, step, "Publications file not verified.");
	}

cleanup:

	return res;
}

static int verifyOnline(KSI_CTX *ctx, KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_ExtendReq *req = NULL;
	KSI_Integer *start = NULL;
	KSI_Integer *end = NULL;
	KSI_RequestHandle *handle = NULL;
	KSI_DataHash *extHash = NULL;
	KSI_DataHash *calHash = NULL;
	KSI_ExtendResp *resp = NULL;
	KSI_Integer *status = NULL;
	KSI_CalendarHashChain *calChain = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_DataHash *pubHash = NULL;
	KSI_VerificationStep step = KSI_VERIFY_CALCHAIN_ONLINE;
	KSI_VerificationResult *info = &sig->verificationResult;

	KSI_LOG_info(sig->ctx, "Verifying signature online.");

	/* Extract start time */
	res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &start);
	if (res != KSI_OK) goto cleanup;

	/* Clone the start time object */
	res = KSI_Integer_ref(start);
	if (res != KSI_OK) goto cleanup;

	if (sig->verificationResult.useUserPublication) {
		/* Extract end time. */
		res = KSI_PublicationData_getTime(sig->verificationResult.userPublication, &end);
		if (res != KSI_OK) goto cleanup;
	}
	res = createExtendRequest(sig->ctx, start, end, &req);
	if (res != KSI_OK) goto cleanup;

	res = KSI_sendExtendRequest(ctx, req, &handle);
	if (res != KSI_OK) goto cleanup;

	res = KSI_RequestHandle_getExtendResponse(handle, &resp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_ExtendResp_getStatus(resp, &status);
	if (res != KSI_OK) goto cleanup;

	/* Verify status. */
	if (status != NULL && !KSI_Integer_equalsUInt(status, 0)) {
		KSI_Utf8String *respErr = NULL;
		char errm[1024];

		res = KSI_ExtendResp_getErrorMsg(resp, &respErr);
		if (res != KSI_OK) goto cleanup;

		KSI_snprintf(errm, sizeof(errm), "Extend failure from server: '%s'", KSI_Utf8String_cstr(respErr));

		res = KSI_VerificationResult_addFailure(info, step, errm);
		goto cleanup;
	}

	res = KSI_ExtendResp_getCalendarHashChain(resp, &calChain);
	if (res != KSI_OK) goto cleanup;

	res = KSI_CalendarHashChain_getInputHash(calChain, &extHash);
	if (res != KSI_OK) goto cleanup;

	res = KSI_CalendarHashChain_getInputHash(sig->calendarChain, &calHash);
	if (res != KSI_OK) goto cleanup;

	if (!KSI_DataHash_equals(extHash, calHash)) {
		res = KSI_VerificationResult_addFailure(info, step, "Extender returned different input hash for calendar hash chain.");
		goto cleanup;
	}

	if (sig->verificationResult.useUserPublication) {
		res = KSI_CalendarHashChain_aggregate(calChain, &rootHash);
		if (res != KSI_OK) goto cleanup;

		if (!KSI_DataHash_equals(rootHash, pubHash)) {
			res = KSI_VerificationResult_addFailure(info, step, "External publication imprint mismatch.");
			goto cleanup;
		}
	}

	res = KSI_VerificationResult_addSuccess(info, step, "Verified online.");

cleanup:

	KSI_Integer_free(start);
	KSI_ExtendReq_free(req);
	KSI_RequestHandle_free(handle);
	KSI_ExtendResp_free(resp);

	return res;
}

static int verifyCalendarChainWithPublication(KSI_Signature *sig){
	int res = KSI_UNKNOWN_ERROR;
	KSI_CalendarHashChain *calChain = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_PublicationRecord *sigPubRec = NULL;
	KSI_PublicationData *sigPubData = NULL;
	KSI_DataHash *publishedHash = NULL;
	KSI_Integer *publishedTime = NULL;
	KSI_VerificationStep step = KSI_VERIFY_CALCHAIN_WITH_PUBLICATION;
	KSI_VerificationResult *info = &sig->verificationResult;
	
	if (sig->publication == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_debug(sig->ctx, "Verifying calendar chain with publication.");

	calChain = sig->calendarChain;
	res = KSI_CalendarHashChain_getPublicationTime(calChain, &pubTime);
	if (res != KSI_OK) goto cleanup;
	
	res = KSI_CalendarHashChain_aggregate(calChain, &rootHash);
	if (res != KSI_OK) goto cleanup;
	
	sigPubRec = sig->publication;
	res = KSI_PublicationRecord_getPublishedData(sigPubRec, &sigPubData);
	if (res != KSI_OK) goto cleanup;
	
	res = KSI_PublicationData_getImprint(sigPubData, &publishedHash);
	if (res != KSI_OK) goto cleanup;
	
	res = KSI_PublicationData_getTime(sigPubData, &publishedTime);
	if (res != KSI_OK) goto cleanup;
	
	
	if (!KSI_DataHash_equals(rootHash, publishedHash)){
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Calendar root hash", rootHash);
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Published hash", publishedHash);
		res = KSI_VerificationResult_addFailure(info, step, "Published hash and calendar hash chain root hash mismatch.");
		goto cleanup;
	}

	if (!KSI_Integer_equals(pubTime, publishedTime)){
		KSI_LOG_debug(sig->ctx, "Calendar hash chain publication time: %i.", KSI_Integer_getUInt64(pubTime));
		KSI_LOG_debug(sig->ctx, "Published publication time: %i.", KSI_Integer_getUInt64(publishedTime));
		res = KSI_VerificationResult_addFailure(info, step, "Calendar hash chain publication time mismatch.");
		goto cleanup;
	}
	
	res = KSI_VerificationResult_addSuccess(info, step, "Calendar chain verified with publication.");
	
cleanup:
	
	KSI_DataHash_free(rootHash);		
			
	return res;	
}

static int performVerification(unsigned policy, KSI_Signature *sig, enum KSI_VerificationStep_en step) {
	return (policy & step) && !(sig->verificationResult.stepsPerformed & step) && !(sig->verificationResult.stepsFailed);
}

static int KSI_Signature_verifyPolicy(KSI_Signature *sig, unsigned *policy, KSI_CTX *ctx) {
	KSI_ERR err;
	int res;
	unsigned i;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, policy != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	for (i = 0; policy[i] != 0; i++) {
		unsigned pol = policy[i];
		KSI_LOG_debug(sig->ctx, "Verifying policy 0x%02x", pol);

		if (performVerification(pol, sig, KSI_VERIFY_PUBFILE_SIGNATURE)) {
			res = verifyPublicationsFile(ctx, sig);
			KSI_CATCH(&err, res) goto cleanup;
		}

		if (performVerification(pol, sig, KSI_VERIFY_DOCUMENT)) {
			res = verifyDocument(sig);
			KSI_CATCH(&err, res) goto cleanup;
		}

		if (performVerification(pol, sig, KSI_VERIFY_AGGRCHAIN_INTERNALLY)) {
			res = verifyInternallyAggregationChain(sig);
			KSI_CATCH(&err, res) goto cleanup;
		}

		if (performVerification(pol, sig, KSI_VERIFY_CALCHAIN_INTERNALLY)) {
			res = verifyInternallyCalendarChain(sig);
			KSI_CATCH(&err, res) goto cleanup;
		}

		if (performVerification(pol, sig, KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN)) {
			res = verifyAggregationRootWithCalendarChain(sig);
			KSI_CATCH(&err, res) goto cleanup;
		}

		if (performVerification(pol, sig, KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC)){
			res = verifyCalendarChain(sig);
			KSI_CATCH(&err, res) goto cleanup;
		}

		if (performVerification(pol, sig, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE)) {
			res = verifyCalAuthRec(ctx, sig);
			KSI_CATCH(&err, res) goto cleanup;
		}
		
		if (performVerification(pol, sig,  KSI_VERIFY_CALCHAIN_WITH_PUBLICATION)) {
			res = verifyCalendarChainWithPublication(sig);
			KSI_CATCH(&err, res) goto cleanup;
		}
		
		if (performVerification(pol, sig,  KSI_VERIFY_PUBLICATION_WITH_PUBFILE)) {
			res = verifyPublication(ctx, sig);
			KSI_CATCH(&err, res) goto cleanup;
		}

		if (performVerification(pol, sig, KSI_VERIFY_CALCHAIN_ONLINE)) {
			res = verifyOnline(ctx, sig);
			KSI_CATCH(&err, res) goto cleanup;
		}

		if (sig->verificationResult.stepsFailed & pol) {
			KSI_LOG_debug(sig->ctx, "Verification failed with steps: 0x%02x", sig->verificationResult.stepsFailed);
			KSI_FAIL(&err, KSI_VERIFICATION_FAILURE, "One of the performed verification steps failed.");
			continue;
		}

		if ((pol & sig->verificationResult.stepsPerformed) == pol) {
			KSI_LOG_debug(sig->ctx, "Verification successful with policy 0x%02x (steps performed 0x%02x)", pol, sig->verificationResult.stepsPerformed);
			KSI_SUCCESS(&err);
			goto cleanup;
		}
	}

	KSI_FAIL(&err, KSI_VERIFICATION_FAILURE, "Signature not verified - no suitable policy.");

cleanup:

	return KSI_RETURN(&err);

}

int KSI_Signature_verify(KSI_Signature *sig, KSI_CTX *ctx) {
	KSI_ERR err;
	int res;
	KSI_CTX *useCtx = ctx;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	if (useCtx == NULL) {
		useCtx = sig->ctx;
	}

	res = KSI_Signature_verifyPolicy(sig, KSI_VP_SIGNATURE, useCtx);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_Signature_verifyDataHash(KSI_Signature *sig, KSI_CTX *ctx, const KSI_DataHash *docHash) {
	KSI_ERR err;
	int res;
	KSI_CTX *useCtx = ctx;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, docHash != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	if (useCtx == NULL) {
		useCtx = sig->ctx;
	}

	KSI_VerificationResult_reset(&sig->verificationResult);

	/* Set the document hash. */
	sig->verificationResult.documentHash = docHash;
	sig->verificationResult.verifyDocumentHash = true;

	res = KSI_Signature_verifyPolicy(sig, KSI_VP_DOCUMENT, useCtx);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_Signature_getVerificationResult(KSI_Signature *sig, const KSI_VerificationResult **info) {
	KSI_ERR err;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, info != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	if (!sig->verificationResult.stepsPerformed) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Signature not verified.");
		goto cleanup;
	}

	*info = &sig->verificationResult;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}
