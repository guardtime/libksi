/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
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
#include "net.h"
#include "pkitruststore.h"

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
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBSTRING,
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBFILE
KSI_END_VERIFICATION_POLICY

KSI_DEFINE_VERIFICATION_POLICY(KSI_VP_ONLINE)
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_ONLINE
KSI_END_VERIFICATION_POLICY

KSI_DEFINE_VERIFICATION_POLICY(KSI_VP_DOCUMENT)
	KSI_VERIFY_DOCUMENT | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC | KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE,
	KSI_VERIFY_DOCUMENT | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBSTRING,
	KSI_VERIFY_DOCUMENT | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBFILE,
	KSI_VERIFY_DOCUMENT | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_ONLINE
KSI_END_VERIFICATION_POLICY

KSI_DEFINE_VERIFICATION_POLICY(KSI_VP_SIGNATURE)
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC | KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE,
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBSTRING,
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBFILE,
	KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_ONLINE
KSI_END_VERIFICATION_POLICY


KSI_DEFINE_VERIFICATION_POLICY(KSI_VP_PARANOID)
	KSI_VERIFY_PUBFILE_SIGNATURE | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC | KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE | KSI_VERIFY_CALCHAIN_ONLINE,
	KSI_VERIFY_PUBFILE_SIGNATURE | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBSTRING | KSI_VERIFY_CALCHAIN_ONLINE,
	KSI_VERIFY_PUBFILE_SIGNATURE | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION | KSI_VERIFY_PUBLICATION_WITH_PUBFILE | KSI_VERIFY_CALCHAIN_ONLINE,
	KSI_VERIFY_PUBFILE_SIGNATURE | KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_ONLINE
KSI_END_VERIFICATION_POLICY

static int addRequestId(
		KSI_CTX *ctx,
		void *req,
		int(getId)(void *, KSI_Integer **),
		int(setId)(void *, KSI_Integer *)) {
	KSI_Integer *reqId = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || req == NULL || getId == NULL || setId == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = getId(req, &reqId);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (reqId != NULL) {
		KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Request already contains a request Id.");
		goto cleanup;
	}

	res = KSI_Integer_new(ctx, ++ctx->requestCounter, &reqId);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	res = setId(req, reqId);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	reqId = NULL;

	res = KSI_OK;

cleanup:

	KSI_Integer_free(reqId);

	return res;
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
	KSI_AggregationHashChain *tmp = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || out == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_AggregationHashChain);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
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

	res = KSI_OK;

cleanup:

	KSI_AggregationHashChain_free(tmp);

	return res;
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
	KSI_AggregationAuthRec *tmp = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || out == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_AggregationAuthRec);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;

	}
	res = KSI_IntegerList_new(&tmp->chainIndexesList);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->inputHash = NULL;
	tmp->ctx = ctx;
	tmp->signatureData = NULL;
	tmp->aggregationTime = NULL;

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_AggregationAuthRec_free(tmp);

	return res;
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
	KSI_CalendarAuthRec *tmp = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || out == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_CalendarAuthRec);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->pubData = NULL;
	tmp->signatureData = NULL;

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_CalendarAuthRec_free(tmp);

	return res;
}
KSI_IMPLEMENT_SETTER(KSI_CalendarAuthRec, KSI_PublicationData*, pubData, PublishedData)
KSI_IMPLEMENT_SETTER(KSI_CalendarAuthRec, KSI_PKISignedData*, signatureData, SignatureData)

KSI_IMPLEMENT_GETTER(KSI_CalendarAuthRec, KSI_PublicationData*, pubData, PublishedData)
KSI_IMPLEMENT_GETTER(KSI_CalendarAuthRec, KSI_PKISignedData*, signatureData, SignatureData)

KSI_IMPLEMENT_LIST(KSI_AggregationHashChain, KSI_AggregationHashChain_free);

KSI_DEFINE_TLV_TEMPLATE(KSI_Signature)
	KSI_TLV_COMPOSITE_LIST(0x0801, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Signature_getAggregationChainList, KSI_Signature_setAggregationChainList, KSI_AggregationHashChain, "aggr_chain")
	KSI_TLV_COMPOSITE(0x0802, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Signature_getCalendarChain, KSI_Signature_setCalendarChain, KSI_CalendarHashChain, "cal_chain")
	KSI_TLV_COMPOSITE(0x0803, KSI_TLV_TMPL_FLG_MOST_ONE_G0, KSI_Signature_getPublicationRecord, KSI_Signature_setPublicationRecord, KSI_PublicationRecord, "pub_rec")
	KSI_TLV_COMPOSITE(0x0804, KSI_TLV_TMPL_FLG_NONE, KSI_Signature_getAggregationAuthRecord, KSI_Signature_setAggregationAuthRecord, KSI_AggregationAuthRec, "aggr_auth_rec")
	KSI_TLV_COMPOSITE(0x0805, KSI_TLV_TMPL_FLG_MOST_ONE_G0, KSI_Signature_getCalendarAuthRecord, KSI_Signature_setCalendarAuthRecord, KSI_CalendarAuthRec, "cal_auth_rec")
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
static int createSignRequest(KSI_CTX *ctx, KSI_DataHash *hsh, int lvl, KSI_AggregationReq **request) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationReq *tmp = NULL;
	KSI_Integer *level = NULL;
	KSI_DataHash *tmpHash = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || hsh == NULL || request == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* For now, the level may be just a single byte. */
	if (lvl < 0 || lvl > 0xff) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Aggregation level may be only between 0x00 and 0xff");
		goto cleanup;
	}

	/* Create request object */
	res = KSI_AggregationReq_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add the request Id. */
	res = addAggregationRequestId(ctx, tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Make sure it is safe to pass the pointer to the request object. */
	res = KSI_DataHash_clone(hsh, &tmpHash);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add the hash to the request */
	res = KSI_AggregationReq_setRequestHash(tmp, tmpHash);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	/* Will be freed by KSI_AggregationReq_free. */
	tmpHash = NULL;

	/* If the level is specified, add it to the request. */
	if (lvl > 0) {
		/* Create a new integer object. */
		res = KSI_Integer_new(ctx, (KSI_uint64_t) lvl, &level);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		/* Attach it to the request. */
		res = KSI_AggregationReq_setRequestLevel(tmp, level);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
		/* Will be freed by KSI_AggregationReq_free */
		level = NULL;
	}

	*request = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Integer_free(level);
	KSI_DataHash_free(tmpHash);
	KSI_AggregationReq_free(tmp);

	return res;
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
	int res;
	KSI_DataHash *newInputHash = NULL;
	KSI_DataHash *oldInputHash = NULL;
	KSI_TLV *oldCalChainTlv = NULL;
	KSI_TLV *newCalChainTlv = NULL;
	KSI_LIST(KSI_TLV) *nestedList = NULL;
	size_t i;

	if (sig == NULL || calendarHashChain == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);


	if (sig->calendarChain == NULL) {
		KSI_pushError(sig->ctx, res = KSI_INVALID_FORMAT, "Signature does not contain a hash chain.");
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getInputHash(calendarHashChain, &newInputHash);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	if (newInputHash == NULL) {
		KSI_pushError(sig->ctx, res = KSI_INVALID_FORMAT, "Given calendar hash chain does not contain an input hash.");
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getInputHash(sig->calendarChain, &oldInputHash);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}
	/* The output hash and input hash have to be equal */
	if (!KSI_DataHash_equals(newInputHash, oldInputHash)) {
		KSI_pushError(sig->ctx, res = KSI_EXTEND_WRONG_CAL_CHAIN, NULL);
		goto cleanup;
	}

	res = KSI_TLV_getNestedList(sig->baseTlv, &nestedList);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	for (i = 0; i < KSI_TLVList_length(nestedList); i++) {
		res = KSI_TLVList_elementAt(nestedList,i, &oldCalChainTlv);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		if (oldCalChainTlv == NULL) {
			KSI_pushError(sig->ctx, res = KSI_INVALID_SIGNATURE, "Signature does not contain calendar chain.");
			goto cleanup;
		}

		if (KSI_TLV_getTag(oldCalChainTlv) == 0x0802) break;
	}

	res = KSI_TLV_new(sig->ctx, KSI_TLV_PAYLOAD_TLV, 0x0802, 0, 0, &newCalChainTlv);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TlvTemplate_construct(sig->ctx, newCalChainTlv, calendarHashChain, KSI_TLV_TEMPLATE(KSI_CalendarHashChain));
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_replaceNestedTlv(sig->baseTlv, oldCalChainTlv, newCalChainTlv);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	newCalChainTlv = NULL;

	/* The memory was freed within KSI_TLV_replaceNestedTlv. */
	oldCalChainTlv = NULL;

	KSI_CalendarHashChain_free(sig->calendarChain);
	sig->calendarChain = calendarHashChain;


	res = KSI_OK;

cleanup:

	KSI_nofree(nestedList);
	KSI_nofree(oldInputHash);
	KSI_nofree(newInputHash);

	KSI_TLV_free(newCalChainTlv);

	KSI_nofree(newInputHash);

	return res;
}

static int removeCalAuthAndPublication(KSI_Signature *sig) {
	KSI_LIST(KSI_TLV) *nested = NULL;
	KSI_TLV *tlv = NULL;
	int res;
	int i;

	if (sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);


	res = KSI_TLV_getNestedList(sig->baseTlv, &nested);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}
	/* By looping in reverse order, we can safely remove elements
	 * and continue. */
	for (i = (int)KSI_TLVList_length(nested) - 1; i >= 0; i--) {
		unsigned tag;

		res = KSI_TLVList_elementAt(nested, (unsigned)i, &tlv);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		tag = KSI_TLV_getTag(tlv);

		if (tag == 0x0803 || tag == 0x0805) {
			res = KSI_TLVList_remove(nested, (unsigned)i, NULL);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
			tlv = NULL;
		}
	}

	KSI_CalendarAuthRec_free(sig->calendarAuthRec);
	sig->calendarAuthRec = NULL;

	KSI_PublicationRecord_free(sig->publication);
	sig->publication = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(nested);
	KSI_nofree(tlv);

	return res;
}

int KSI_Signature_replacePublicationRecord(KSI_Signature *sig, KSI_PublicationRecord *pubRec) {
	KSI_TLV *newPubTlv = NULL;
	size_t oldPubTlvPos = 0;
	bool oldPubTlvPos_found = false;

	KSI_LIST(KSI_TLV) *nestedList = NULL;
	int res;
	size_t i;

	if (sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);


	if (pubRec != NULL) {
		/* Remove auth records. */
		res = removeCalAuthAndPublication(sig);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		/* Create a new TLV object */
		res = KSI_TLV_new(sig->ctx, KSI_TLV_PAYLOAD_TLV, 0x0803, 0, 0, &newPubTlv);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		/* Evaluate the TLV object */
		res = KSI_TlvTemplate_construct(sig->ctx, newPubTlv, pubRec, KSI_TLV_TEMPLATE(KSI_PublicationRecord));
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		/* Find previous publication */
		res = KSI_TLV_getNestedList(sig->baseTlv, &nestedList);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		for (i = 0; i < KSI_TLVList_length(nestedList); i++) {
			KSI_TLV *tmp = NULL;
			res = KSI_TLVList_elementAt(nestedList, i, &tmp);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}

			if (KSI_TLV_getTag(tmp) == 0x0803) {
				oldPubTlvPos = i;
				oldPubTlvPos_found = true;
				break;
			}

			KSI_nofree(tmp);
		}

		if (oldPubTlvPos_found) {
			res = KSI_TLVList_replaceAt(nestedList, oldPubTlvPos, newPubTlv);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		} else {
			res = KSI_TLVList_append(nestedList, newPubTlv);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (sig->publication != NULL) {
			KSI_PublicationRecord_free(sig->publication);
		}
		sig->publication = pubRec;
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int parseAggregationResponse(KSI_CTX *ctx, KSI_AggregationResp *resp, KSI_Signature **signature) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmpTlv = NULL;
	KSI_TLV *respTlv = NULL;
	KSI_Signature *tmp = NULL;
	KSI_LIST(KSI_TLV) *tlvList = NULL;

	/* PDU Specific objects */
	KSI_Integer *status = NULL;
	size_t i;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || resp == NULL || signature == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}



	/* Parse the pdu */
	res = KSI_AggregationResp_getBaseTlv(resp, &respTlv);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Validate tag value */
	if (KSI_TLV_getTag(respTlv) != 0x202) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_getStatus(resp, &status);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_convertAggregatorStatusCode(status);
	/* Check for the status of the response. */
	if (res != KSI_OK) {
		KSI_Utf8String *errorMessage = NULL;
		char msg[1024];

		KSI_AggregationResp_getErrorMsg(resp, &errorMessage);

		KSI_snprintf(msg, sizeof(msg), "Aggregation failed: %s", KSI_Utf8String_cstr(errorMessage));
		KSI_ERR_push(ctx, res, (long)KSI_Integer_getUInt64(status), __FILE__, __LINE__, KSI_Utf8String_cstr(errorMessage));
		goto cleanup;
	}

	res = KSI_Signature_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_getAggregationAuthRec(resp, &tmp->aggregationAuthRec);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_setAggregationAuthRec(resp, NULL);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_getAggregationChainList(resp, &tmp->aggregationChainList);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_setAggregationChainList(resp, NULL);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_getCalendarAuthRec(resp, &tmp->calendarAuthRec);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_setCalendarAuthRec(resp, NULL);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_getCalendarChain(resp, &tmp->calendarChain);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_setCalendarChain(resp, NULL);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}


	/* Create signature TLV */
	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, 0x0800, 0, 0, &tmpTlv);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_getNestedList(respTlv, &tlvList);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	i = 0;
	while (i < KSI_TLVList_length(tlvList)) {
		KSI_TLV *t = NULL;
		res = KSI_TLVList_elementAt(tlvList, i, &t);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

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
				if (res != KSI_OK) {
					KSI_pushError(ctx, res, NULL);
					goto cleanup;
				}

				/* Copy this tag to the signature. */
				res = KSI_TLV_appendNestedTlv(tmpTlv, t);
				if (res != KSI_OK) {
					KSI_pushError(ctx, res, NULL);
					goto cleanup;
				}

		}
	}

	res = KSI_TLV_clone(tmpTlv, &tmp->baseTlv);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Signature", tmp->baseTlv);

	*signature = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tmpTlv);
	KSI_Signature_free(tmp);

	return res;
}


int KSI_Signature_createAggregated(KSI_CTX *ctx, KSI_DataHash *rootHash, KSI_uint64_t rootLevel, KSI_Signature **signature) {
	KSI_ERR err;
	int res;
	KSI_RequestHandle *handle = NULL;
	KSI_AggregationResp *response = NULL;
	KSI_Signature *sign = NULL;

	KSI_AggregationReq *req = NULL;

	KSI_PRE(&err, rootHash != NULL) goto cleanup;
	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	res = createSignRequest(ctx, rootHash, rootLevel, &req);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_sendSignRequest(ctx, req, &handle);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_RequestHandle_getAggregationResponse(handle, &response);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = parseAggregationResponse(ctx, response, &sign);
	KSI_CATCH(&err, res) goto cleanup;

	*signature = sign;
	sign = NULL;

	res = KSI_OK;

cleanup:

	KSI_AggregationResp_free(response);
	KSI_Signature_free(sign);
	KSI_RequestHandle_free(handle);
	KSI_AggregationReq_free(req);

	return res;
}

int KSI_Signature_create(KSI_CTX *ctx, KSI_DataHash *hsh, KSI_Signature **signature) {
	return KSI_Signature_createAggregated(ctx, hsh, 0, signature);
}

int KSI_Signature_extendTo(const KSI_Signature *sig, KSI_CTX *ctx, KSI_Integer *to, KSI_Signature **extended) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendReq *req = NULL;
	KSI_Integer *signTime = NULL;
	KSI_RequestHandle *handle = NULL;
	KSI_ExtendResp *resp = NULL;
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
	res = KSI_RequestHandle_getExtendResponse(handle, &resp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Verify the correctness of the response. */
	res = KSI_ExtendResp_verifyWithRequest(resp, req);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Extract the calendar hash chain */
	KSI_ExtendResp_getCalendarHashChain(resp, &calHashChain);

	/* Remove the chain from the structure, as it will be freed when this function finishes. */
	KSI_ExtendResp_setCalendarHashChain(resp, NULL);

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
	KSI_ExtendResp_free(resp);
	KSI_RequestHandle_free(handle);
	KSI_Signature_free(tmp);

	return res;
}

int KSI_Signature_extend(const KSI_Signature *signature, KSI_CTX *ctx, const KSI_PublicationRecord *pubRec, KSI_Signature **extended) {
	int res = KSI_UNKNOWN_ERROR;
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


int KSI_Signature_getDocumentHash(KSI_Signature *sig, KSI_DataHash **hsh) {
	KSI_AggregationHashChain *aggr = NULL;
	int res;

	if (sig == NULL || hsh == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);


	res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggr);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	*hsh = aggr->inputHash;

	res = KSI_OK;

cleanup:

	KSI_nofree(aggr);

	return res;
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
	KSI_TLV *tlv = NULL;
	KSI_Signature *tmp = NULL;
	int res;

	if (sig == NULL || clone == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);


	res = KSI_TLV_clone(sig->baseTlv, &tlv);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logTlv(sig->ctx, KSI_LOG_DEBUG, "Original TLV", sig->baseTlv);
	KSI_LOG_logTlv(sig->ctx, KSI_LOG_DEBUG, "Cloned TLV", tlv);

	res = extractSignature(sig->ctx, tlv, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	tmp->baseTlv = tlv;
	tlv = NULL;

	*clone = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tlv);
	KSI_Signature_free(tmp);

	return res;
}

int KSI_Signature_parse(KSI_CTX *ctx, unsigned char *raw, unsigned raw_len, KSI_Signature **sig) {
	KSI_TLV *tlv = NULL;
	KSI_Signature *tmp = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || raw == NULL || raw_len == 0 || sig == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_parseBlob(ctx, raw, raw_len, &tlv);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = extractSignature(ctx, tlv, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->baseTlv = tlv;
	tlv = NULL;

	*sig = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tlv);
	KSI_Signature_free(tmp);

	return res;
}

int KSI_Signature_fromFile(KSI_CTX *ctx, const char *fileName, KSI_Signature **sig) {
	int res;
	FILE *f = NULL;

	unsigned char *raw = NULL;
	size_t raw_len = 0;

	KSI_Signature *tmp = NULL;

	const unsigned raw_size = 0xffff + 4;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || fileName == NULL || sig == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	raw = KSI_calloc(raw_size, 1);
	if (raw == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	f = fopen(fileName, "rb");
	if (f == NULL) {
		KSI_pushError(ctx, res = KSI_IO_ERROR, "Unable to open file.");
		goto cleanup;
	}

	raw_len = fread(raw, 1, raw_size, f);
	if (raw_len == 0) {
		KSI_pushError(ctx, res = KSI_IO_ERROR, "Unable to read file.");
		goto cleanup;
	}

	if (!feof(f)) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Input too long for a valid signature.");
		goto cleanup;
	}

	res = KSI_Signature_parse(ctx, raw, (unsigned)raw_len, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*sig = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	if (f != NULL) fclose(f);
	KSI_Signature_free(tmp);
	KSI_free(raw);

	return res;
}

int KSI_Signature_serialize(KSI_Signature *sig, unsigned char **raw, unsigned *raw_len) {
	int res;
	unsigned char *tmp = NULL;
	unsigned tmp_len;

	if (sig == NULL || raw == NULL || raw_len == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);


	/* We assume that the baseTlv tree is up to date! */
	res = KSI_TLV_serialize(sig->baseTlv, &tmp, &tmp_len);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	*raw = tmp;
	tmp = NULL;

	*raw_len = tmp_len;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);

	return res;

}

int KSI_Signature_getSignerIdentity(KSI_Signature *sig, char **signerIdentity) {
	int res;
	size_t i, j;
	KSI_List *idList = NULL;
	char *signerId = NULL;
	size_t signerId_size = 1; // At least 1 for trailing zero.
	size_t signerId_len = 0;

	if (sig == NULL || signerIdentity == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	/* Create a list of separate signer identities. */
	res = KSI_List_new(NULL, &idList);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	/* Extract all identities from all aggregation chains from top to bottom. */
	for (i = KSI_AggregationHashChainList_length(sig->aggregationChainList); i-- > 0;) {
		KSI_AggregationHashChain *aggrRec = NULL;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &aggrRec);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		for (j = KSI_HashChainLinkList_length(aggrRec->chain); j-- > 0;) {
			KSI_HashChainLink *link = NULL;
			KSI_MetaData *metaData = NULL;
			KSI_DataHash *metaHash = NULL;

			res = KSI_HashChainLinkList_elementAt(aggrRec->chain, j, &link);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}

			/* Extract MetaHash */
			res = KSI_HashChainLink_getMetaHash(link, &metaHash);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}

			/* Extract MetaData */
			res = KSI_HashChainLink_getMetaData(link, &metaData);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}

			if (metaHash != NULL) {
				const char *tmp = NULL;
				int tmp_len;

				res = KSI_DataHash_MetaHash_parseMeta(metaHash, (const unsigned char **)&tmp, &tmp_len);
				if (res != KSI_OK) {
					KSI_pushError(sig->ctx, res, NULL);
					goto cleanup;
				}

				signerId_size += tmp_len + 4;

				res = KSI_List_append(idList, (void *)tmp);
				if (res != KSI_OK) {
					KSI_pushError(sig->ctx, res, NULL);
					goto cleanup;
				}

			} else if (metaData != NULL) {
				KSI_Utf8String *clientId = NULL;

				res = KSI_MetaData_getClientId(metaData, &clientId);
				if (res != KSI_OK) {
					KSI_pushError(sig->ctx, res, NULL);
					goto cleanup;
				}

				signerId_size += KSI_Utf8String_size(clientId) + 4;

				res = KSI_List_append(idList, (void *)KSI_Utf8String_cstr(clientId));
				if (res != KSI_OK) {
					KSI_pushError(sig->ctx, res, NULL);
					goto cleanup;
				}

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
		KSI_pushError(sig->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	/* Concatenate all together. */
	for (i = 0; i < KSI_List_length(idList); i++) {
		const char *tmp = NULL;

		res = KSI_List_elementAt(idList, i, (void **)&tmp);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		signerId_len += (unsigned)KSI_snprintf(signerId + signerId_len, signerId_size - signerId_len, "%s%s", signerId_len > 0 ? " :: " : "", tmp);
	}

	*signerIdentity = signerId;
	signerId = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(signerId);
	KSI_List_free(idList);

	return res;
}

KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_CalendarAuthRec*, calendarAuthRec, CalendarAuthRec)

KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_PublicationRecord*, publication, PublicationRecord)

int KSI_Signature_getHashAlgorithm(KSI_Signature *sig, int *hash_id) {
	KSI_DataHash *hsh = NULL;
	int res;
	int tmp = -1;

	if (sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);


	res = KSI_Signature_getDocumentHash(sig, &hsh);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_extract(hsh, &tmp, NULL, NULL);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	*hash_id = tmp;

	res = KSI_OK;

cleanup:

	KSI_nofree(hsh);

	return res;
}

int KSI_Signature_verifyDocument(KSI_Signature *sig, KSI_CTX *ctx, void *doc, size_t doc_len) {
	int res;
	KSI_DataHash *hsh = NULL;

	int hash_id = -1;

	KSI_ERR_clearErrors(ctx);
	if (sig == NULL || ctx == NULL || doc == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_Signature_getHashAlgorithm(sig, &hash_id);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_create(ctx, doc, doc_len, hash_id, &hsh);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Signature_verifyDataHash(sig, ctx, hsh);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(hsh);

	return res;
}

int KSI_Signature_createDataHasher(KSI_Signature *sig, KSI_DataHasher **hsr) {
	int res;
	KSI_DataHasher *tmp = NULL;
	int hash_id = -1;

	if (sig == NULL || hsr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	res = KSI_Signature_getHashAlgorithm(sig, &hash_id);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_open(sig->ctx, hash_id, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	*hsr = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHasher_free(tmp);

	return res;
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

	/* The aggregation level might not be 0 in case of local aggregation. */
	level = sig->verificationResult.docAggrLevel;

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
				unsigned j;
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

	KSI_LOG_info(sig->ctx, "Verifying aggregation hash chain root.");

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

	res = KSI_VerificationResult_addSuccess(info, step, "Calendar authentication record verified.");

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

static int verifyPublicationWithPubString(KSI_CTX *ctx, KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationStep step = KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;
	KSI_VerificationResult *info = &sig->verificationResult;
	KSI_Integer *time1 = NULL;
	KSI_Integer *time2 = NULL;
	KSI_DataHash *hsh1 = NULL;
	KSI_DataHash *hsh2 = NULL;


	if (sig->publication == NULL || sig->verificationResult.useUserPublication == false) {
		res = KSI_OK;
		goto cleanup;
	}


	KSI_LOG_info(sig->ctx, "Verifying publication with publication string");

	if (sig->verificationResult.userPublication == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_PublicationData_getTime(sig->verificationResult.userPublication, &time1);
	if (res != KSI_OK) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_PublicationData_getImprint(sig->verificationResult.userPublication, &hsh1);
	if (res != KSI_OK) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_PublicationData_getTime(sig->publication->publishedData, &time2);
	if (res != KSI_OK) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_PublicationData_getImprint(sig->publication->publishedData, &hsh2);
	if (res != KSI_OK) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (KSI_Integer_compare(time1, time2) != 0) {
		KSI_LOG_debug(sig->ctx, "Publication time from publication record:", time2);
		KSI_LOG_debug(sig->ctx, "Publication time from user publication  :", time1);
		res = KSI_VerificationResult_addFailure(info, step, "Publication not trusted.");
		goto cleanup;
	}

	if (KSI_DataHash_equals(hsh1, hsh2) != 1) {
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Root hash from publication record:", hsh2);
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Root hash from user publication:", hsh1);
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
	KSI_Integer_ref(start);

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

	/* Verify the correctness of the response. */
	res = KSI_ExtendResp_verifyWithRequest(resp, req);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

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
	int res;
	unsigned i;

	if (sig == NULL || policy == NULL || ctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	for (i = 0; policy[i] != 0; i++) {
		unsigned pol = policy[i];
		KSI_LOG_debug(sig->ctx, "Verifying policy 0x%02x", pol);

		if (performVerification(pol, sig, KSI_VERIFY_PUBFILE_SIGNATURE)) {
			res = verifyPublicationsFile(ctx, sig);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (performVerification(pol, sig, KSI_VERIFY_DOCUMENT)) {
			res = verifyDocument(sig);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (performVerification(pol, sig, KSI_VERIFY_AGGRCHAIN_INTERNALLY)) {
			res = verifyInternallyAggregationChain(sig);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (performVerification(pol, sig, KSI_VERIFY_CALCHAIN_INTERNALLY)) {
			res = verifyInternallyCalendarChain(sig);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (performVerification(pol, sig, KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN)) {
			res = verifyAggregationRootWithCalendarChain(sig);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (performVerification(pol, sig, KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC)){
			res = verifyCalendarChain(sig);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (performVerification(pol, sig, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE)) {
			res = verifyCalAuthRec(ctx, sig);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (performVerification(pol, sig,  KSI_VERIFY_CALCHAIN_WITH_PUBLICATION)) {
			res = verifyCalendarChainWithPublication(sig);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (performVerification(pol, sig,  KSI_VERIFY_PUBLICATION_WITH_PUBSTRING)) {
			res = verifyPublicationWithPubString(ctx, sig);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (performVerification(pol, sig,  KSI_VERIFY_PUBLICATION_WITH_PUBFILE)) {
			res = verifyPublication(ctx, sig);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (performVerification(pol, sig, KSI_VERIFY_CALCHAIN_ONLINE)) {
			res = verifyOnline(ctx, sig);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
		}

		if (sig->verificationResult.stepsFailed & pol) {
			KSI_LOG_debug(sig->ctx, "Verification failed with steps: 0x%02x", sig->verificationResult.stepsFailed);
			KSI_pushError(sig->ctx, res = KSI_VERIFICATION_FAILURE, KSI_VerificationResult_lastFailureMessage(&sig->verificationResult));
			goto cleanup;
		}

		if ((pol & sig->verificationResult.stepsPerformed) == pol) {
			KSI_LOG_debug(sig->ctx, "Verification successful with policy 0x%02x (steps performed 0x%02x)", pol, sig->verificationResult.stepsPerformed);
			res = KSI_OK;
			goto cleanup;
		}
	}

	KSI_pushError(sig->ctx, res = KSI_VERIFICATION_FAILURE, "Signature not verified - no suitable policy.");

cleanup:

	return res;

}

int KSI_Signature_verifyAggregated(KSI_Signature *sig, KSI_CTX *ctx, KSI_uint64_t level) {
	KSI_ERR err;
	int res;
	KSI_CTX *useCtx = ctx;

	if (sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);


	if (useCtx == NULL) {
		useCtx = sig->ctx;
	}

	KSI_VerificationResult_reset(&sig->verificationResult);
	sig->verificationResult.docAggrLevel = level;

	res = KSI_Signature_verifyPolicy(sig, KSI_VP_SIGNATURE, useCtx);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Signature_verify(KSI_Signature *sig, KSI_CTX *ctx) {
	return KSI_Signature_verifyAggregated(sig, ctx, 0);
}

int KSI_Signature_verifyOnline(KSI_Signature *sig, KSI_CTX *ctx){
	int res;
	KSI_CTX *useCtx = ctx;

	if (sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	if (useCtx == NULL) {
		useCtx = sig->ctx;
	}

	res = KSI_Signature_verifyPolicy(sig, KSI_VP_ONLINE, useCtx);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Signature_verifyAggregatedHash(KSI_Signature *sig, KSI_CTX *ctx, const KSI_DataHash *rootHash, KSI_uint64_t rootLevel) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *useCtx = ctx;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || sig == NULL || rootHash == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* Pick a context to use. */
	if (useCtx == NULL) {
		useCtx = sig->ctx;
	}

	KSI_VerificationResult_reset(&sig->verificationResult);

	/* Set the document hash. */
	sig->verificationResult.documentHash = rootHash;
	sig->verificationResult.docAggrLevel = rootLevel;
	sig->verificationResult.verifyDocumentHash = true;

	res = KSI_Signature_verifyPolicy(sig, KSI_VP_DOCUMENT, useCtx);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Signature_verifyDataHash(KSI_Signature *sig, KSI_CTX *ctx, const KSI_DataHash *docHash) {
	return KSI_Signature_verifyAggregatedHash(sig, ctx, docHash, 0);
}

int KSI_Signature_verifyWithPublication(KSI_Signature *sig, KSI_CTX *ctx, const KSI_PublicationData *publication) {
	int res;
	KSI_CTX *useCtx = ctx;

	if (sig == NULL || ctx == NULL || publication == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);


	if (useCtx == NULL) {
		useCtx = sig->ctx;
	}

	KSI_VerificationResult_reset(&sig->verificationResult);

	/* Set the document hash. */
	sig->verificationResult.userPublication = publication;
	sig->verificationResult.useUserPublication = true;

	res = KSI_Signature_verifyPolicy(sig, KSI_VP_OFFLINE, useCtx);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Signature_getVerificationResult(KSI_Signature *sig, const KSI_VerificationResult **info) {
	int res;

	if (sig == NULL || info == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	if (!sig->verificationResult.stepsPerformed) {
		KSI_pushError(sig->ctx, res = KSI_INVALID_ARGUMENT, "Signature not verified.");
		goto cleanup;
	}

	*info = &sig->verificationResult;

	res = KSI_OK;

cleanup:

	return res;
}
