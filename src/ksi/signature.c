/*
 * Copyright 2013-2016 Guardtime, Inc.
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
#include "policy.h"
#include "signature_builder.h"
#include "signature_builder_impl.h"

typedef struct headerRec_st HeaderRec;

KSI_IMPORT_TLV_TEMPLATE(KSI_Signature);
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationAuthRec);
KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarAuthRec);
KSI_IMPORT_TLV_TEMPLATE(KSI_RFC3161);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationHashChain);

KSI_IMPLEMENT_REF(KSI_Signature);

/**
 * KSI_AggregationHashChain
 */


int KSI_Signature_appendAggregationChain(KSI_Signature *sig, KSI_AggregationHashChain *aggr) {
	return sig->appendAggregationChain(sig, aggr);
}

int KSI_Signature_appendAggregationHashChain(const KSI_Signature *sig, KSI_AggregationHashChain *aggr, KSI_Signature **signature) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;
	int rootLevel = 0;
	KSI_CTX *ctx = NULL;

	if (sig == NULL || aggr == NULL || signature == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = sig->ctx;
	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_clone(sig, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Get signature root level by aggregating the hash chain. */
	res = KSI_AggregationHashChain_aggregate(aggr, 0, &rootLevel, NULL);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Remove applied level correction in signature. */
	if (rootLevel != 0) {
		res = tmp->subRootLevel(tmp, rootLevel);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	res = tmp->appendAggregationChain(tmp, aggr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*signature = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_Signature_free(tmp);
	return res;
}


/**
 * KSI_AggregationAuthRec
 */
void KSI_AggregationAuthRec_free(KSI_AggregationAuthRec *aar) {
	if (aar != NULL && --aar->ref == 0) {
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
	tmp->ref = 1;

	tmp->signatureData = NULL;
	tmp->aggregationTime = NULL;

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_AggregationAuthRec_free(tmp);

	return res;
}

KSI_IMPLEMENT_REF(KSI_AggregationAuthRec);
KSI_IMPLEMENT_WRITE_BYTES(KSI_AggregationAuthRec, 0x0804, 0, 0);
KSI_IMPLEMENT_GETTER(KSI_AggregationAuthRec, KSI_Integer*, aggregationTime, AggregationTime)
KSI_IMPLEMENT_GETTER(KSI_AggregationAuthRec, KSI_LIST(KSI_Integer)*, chainIndexesList, ChainIndex)
KSI_IMPLEMENT_GETTER(KSI_AggregationAuthRec, KSI_DataHash*, inputHash, InputHash)
KSI_IMPLEMENT_GETTER(KSI_AggregationAuthRec, KSI_PKISignedData*, signatureData, SigData)

KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_Integer*, aggregationTime, AggregationTime)
KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_LIST(KSI_Integer)*, chainIndexesList, ChainIndex)
KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_DataHash*, inputHash, InputHash)
KSI_IMPLEMENT_SETTER(KSI_AggregationAuthRec, KSI_PKISignedData*, signatureData, SigData)

KSI_IMPLEMENT_LIST(KSI_AggregationAuthRec, KSI_AggregationAuthRec_free);
/**
 * KSI_CalendarAuthRec
 */

void KSI_CalendarAuthRec_free(KSI_CalendarAuthRec *calAuth) {
	if (calAuth != NULL && --calAuth->ref == 0) {
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
	tmp->ref = 1;

	tmp->pubData = NULL;
	tmp->signatureData = NULL;

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_CalendarAuthRec_free(tmp);

	return res;
}

KSI_IMPLEMENT_REF(KSI_CalendarAuthRec);
KSI_IMPLEMENT_WRITE_BYTES(KSI_CalendarAuthRec, 0x0805, 0, 0);
KSI_IMPLEMENT_SETTER(KSI_CalendarAuthRec, KSI_PublicationData*, pubData, PublishedData);
KSI_IMPLEMENT_SETTER(KSI_CalendarAuthRec, KSI_PKISignedData*, signatureData, SignatureData);

KSI_IMPLEMENT_GETTER(KSI_CalendarAuthRec, KSI_PublicationData*, pubData, PublishedData);
KSI_IMPLEMENT_GETTER(KSI_CalendarAuthRec, KSI_PKISignedData*, signatureData, SignatureData);

KSI_IMPLEMENT_LIST(KSI_AggregationHashChain, KSI_AggregationHashChain_free);

KSI_IMPLEMENT_LIST(KSI_CalendarAuthRec, KSI_CalendarAuthRec_free);

/**
 * KSI_RFC3161
 */
void KSI_RFC3161_free(KSI_RFC3161 *rfc) {
	if (rfc != NULL && --rfc->ref == 0) {
		KSI_Integer_free(rfc->aggregationTime);
		KSI_IntegerList_free(rfc->chainIndex);
		KSI_DataHash_free(rfc->inputHash);

		KSI_OctetString_free(rfc->tstInfoPrefix);
		KSI_OctetString_free(rfc->tstInfoSuffix);
		KSI_Integer_free(rfc->tstInfoAlgo);

		KSI_OctetString_free(rfc->sigAttrPrefix);
		KSI_OctetString_free(rfc->sigAttrSuffix);
		KSI_Integer_free(rfc->sigAttrAlgo);

		KSI_free(rfc);
	}
}

int KSI_RFC3161_new(KSI_CTX *ctx, KSI_RFC3161 **out) {
	KSI_RFC3161 *tmp = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || out == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_RFC3161);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;
	tmp->aggregationTime = NULL;
	tmp->chainIndex = NULL;
	tmp->inputHash = NULL;

	tmp->tstInfoPrefix = NULL;
	tmp->tstInfoSuffix = NULL;
	tmp->tstInfoAlgo = NULL;

	tmp->sigAttrPrefix = NULL;
	tmp->sigAttrSuffix = NULL;
	tmp->sigAttrAlgo = NULL;

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_RFC3161_free(tmp);

	return res;
}

KSI_IMPLEMENT_REF(KSI_RFC3161);
KSI_IMPLEMENT_WRITE_BYTES(KSI_RFC3161, 0x0806, 0, 0);

KSI_IMPLEMENT_GETTER(KSI_RFC3161, KSI_Integer*, aggregationTime, AggregationTime)
KSI_IMPLEMENT_GETTER(KSI_RFC3161, KSI_LIST(KSI_Integer)*, chainIndex, ChainIndex)
KSI_IMPLEMENT_GETTER(KSI_RFC3161, KSI_DataHash*, inputHash, InputHash)
KSI_IMPLEMENT_GETTER(KSI_RFC3161, KSI_OctetString*, tstInfoPrefix, TstInfoPrefix)
KSI_IMPLEMENT_GETTER(KSI_RFC3161, KSI_OctetString*, tstInfoSuffix, TstInfoSuffix)
KSI_IMPLEMENT_GETTER(KSI_RFC3161, KSI_Integer*, tstInfoAlgo, TstInfoAlgo)
KSI_IMPLEMENT_GETTER(KSI_RFC3161, KSI_OctetString*, sigAttrPrefix, SigAttrPrefix)
KSI_IMPLEMENT_GETTER(KSI_RFC3161, KSI_OctetString*, sigAttrSuffix, SigAttrSuffix)
KSI_IMPLEMENT_GETTER(KSI_RFC3161, KSI_Integer*, sigAttrAlgo, SigAttrAlgo)


KSI_IMPLEMENT_SETTER(KSI_RFC3161, KSI_Integer*, aggregationTime, AggregationTime)
KSI_IMPLEMENT_SETTER(KSI_RFC3161, KSI_LIST(KSI_Integer)*, chainIndex, ChainIndex)
KSI_IMPLEMENT_SETTER(KSI_RFC3161, KSI_DataHash*, inputHash, InputHash)
KSI_IMPLEMENT_SETTER(KSI_RFC3161, KSI_OctetString*, tstInfoPrefix, TstInfoPrefix)
KSI_IMPLEMENT_SETTER(KSI_RFC3161, KSI_OctetString*, tstInfoSuffix, TstInfoSuffix)
KSI_IMPLEMENT_SETTER(KSI_RFC3161, KSI_Integer*, tstInfoAlgo, TstInfoAlgo)
KSI_IMPLEMENT_SETTER(KSI_RFC3161, KSI_OctetString*, sigAttrPrefix, SigAttrPrefix)
KSI_IMPLEMENT_SETTER(KSI_RFC3161, KSI_OctetString*, sigAttrSuffix, SigAttrSuffix)
KSI_IMPLEMENT_SETTER(KSI_RFC3161, KSI_Integer*, sigAttrAlgo, SigAttrAlgo)

KSI_IMPLEMENT_LIST(KSI_RFC3161, KSI_RFC3161_free);

static int extractSignature(KSI_CTX *ctx, KSI_TLV *tlv, KSI_Signature **signature) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_SignatureBuilder *builder = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || tlv == NULL || signature == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (KSI_TLV_getTag(tlv) != 0x800) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Uni-Signature element is missing.");
		goto cleanup;
	}

	/* Create a new signature builder object. */
	res = KSI_SignatureBuilder_open(ctx, &builder);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Parse and extract the signature. */
	res = KSI_TlvTemplate_extract(ctx, builder->sig, tlv, KSI_TLV_TEMPLATE(KSI_Signature));
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_clone(tlv, &builder->sig->baseTlv);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Turn off the verification. */
	builder->noVerify = 1;
	res = KSI_SignatureBuilder_close(builder, 0, signature);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_debug(ctx, "Finished parsing successfully.");

	res = KSI_OK;

cleanup:

	KSI_SignatureBuilder_free(builder);

	return res;
}

/***************
 * SIGN REQUEST
 ***************/
int KSI_createSignRequest(KSI_CTX *ctx, KSI_DataHash *hsh, int lvl, KSI_AggregationReq **request) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationReq *tmp = NULL;
	KSI_Integer *level = NULL;

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

	{
		KSI_DataHash *ref = NULL;
		/* Add the hash to the request. */
		res = KSI_AggregationReq_setRequestHash(tmp, ref = KSI_DataHash_ref(hsh));
		if (res != KSI_OK) {
			/* Cleanup the reference. */
			KSI_DataHash_free(ref);

			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

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
	KSI_AggregationReq_free(tmp);

	return res;
}

/*****************
 * EXTEND REQUEST
 *****************/
int KSI_createExtendRequest(KSI_CTX *ctx, KSI_Integer *start, KSI_Integer *end, KSI_ExtendReq **request) {
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

	{
		KSI_Integer *ref = NULL;
		/* Set the aggregation time. */
		res = KSI_ExtendReq_setAggregationTime(tmp, ref = KSI_Integer_ref(start));
		if (res != KSI_OK) {
			/* Cleanup the reference. */
			KSI_Integer_free(ref);

			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		/* Use the end value, if set. */
		if (end != NULL) {
			res = KSI_ExtendReq_setPublicationTime(tmp, ref = KSI_Integer_ref(end));
			if (res != KSI_OK) {
				/* Cleanup the reference. */
				KSI_Integer_free(ref);

				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}
		}
	}

	*request = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_ExtendReq_free(tmp);

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

	KSI_LIST(KSI_TLV) *nestedList = NULL;
	int res;

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
		res = KSI_TLV_new(sig->ctx, 0x0803, 0, 0, &newPubTlv);
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

		res = KSI_TLVList_append(nestedList, newPubTlv);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
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

static int parseAggregationResponse(KSI_CTX *ctx, KSI_uint64_t rootLevel, KSI_AggregationResp *resp, KSI_Signature **signature) {
	int res;
	KSI_TLV *tmpTlv = NULL;
	KSI_TLV *respTlv = NULL;
	KSI_LIST(KSI_TLV) *tlvList = NULL;
	KSI_SignatureBuilder *builder = NULL;

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
	if (KSI_TLV_getTag(respTlv) != 0x202 && KSI_TLV_getTag(respTlv) != 0x02) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Aggregation response element is missing.");
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

	/* Create a new signature builder object. */
	res = KSI_SignatureBuilder_open(ctx, &builder);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_getAggregationAuthRec(resp, &builder->sig->aggregationAuthRec);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_setAggregationAuthRec(resp, NULL);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_getAggregationChainList(resp, &builder->sig->aggregationChainList);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_setAggregationChainList(resp, NULL);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_getCalendarAuthRec(resp, &builder->sig->calendarAuthRec);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_setCalendarAuthRec(resp, NULL);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_getCalendarChain(resp, &builder->sig->calendarChain);
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
	res = KSI_TLV_new(ctx, 0x0800, 0, 0, &tmpTlv);
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

	res = KSI_TLV_clone(tmpTlv, &builder->sig->baseTlv);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Turn off the verification. */
	builder->noVerify = 1;
	res = KSI_SignatureBuilder_close(builder, rootLevel, signature);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tmpTlv);
	KSI_SignatureBuilder_free(builder);

	return res;
}

static int KSI_SignatureVerifier_verifyWithPolicy(KSI_CTX *ctx, KSI_Signature *sig, KSI_uint64_t rootLevel, const KSI_DataHash *docHsh, const KSI_Policy *policy, KSI_VerificationContext *verificationContext) {
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (rootLevel > 0xff) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Aggregation level can't be larger than 0xff.");
		goto cleanup;
	}

	res = KSI_VerificationContext_init(&context, ctx);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (verificationContext == NULL) {
		context.documentHash = docHsh;
	} else {
		context = *verificationContext;
	}
	context.signature = sig;

	res = KSI_SignatureVerifier_verify(policy, &context, &result);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, "Internal verification of signature aborted due to an error.");
		goto cleanup;
	}

	if (result->finalResult.resultCode != KSI_VER_RES_OK) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_pushError(ctx, res, "Internal verification of signature failed.");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_PolicyVerificationResult_free(result);

	return res;
}

#define KSI_SignatureVerifier_verifyInternally(ctx, sig, rootLevel, docHsh)\
	KSI_SignatureVerifier_verifyWithPolicy(ctx, sig, rootLevel, docHsh, KSI_VERIFICATION_POLICY_INTERNAL, NULL)

int KSI_Signature_signAggregatedWithPolicy(KSI_CTX *ctx, KSI_DataHash *rootHash, KSI_uint64_t rootLevel,
		const KSI_Policy *policy, KSI_VerificationContext *context, KSI_Signature **signature) {
	int res;
	KSI_RequestHandle *handle = NULL;
	KSI_AggregationResp *response = NULL;
	KSI_Signature *sign = NULL;
	KSI_AggregationReq *req = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || rootHash == NULL || signature == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (!KSI_IS_VALID_TREE_LEVEL(rootLevel)) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Aggregation level can't be larger than 0xff.");
		goto cleanup;
	}

	res = KSI_createSignRequest(ctx, rootHash, (int)rootLevel, &req);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_sendSignRequest(ctx, req, &handle);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_RequestHandle_perform(handle);
	if (res != KSI_OK) {
		KSI_pushError(ctx,res, NULL);
		goto cleanup;
	}

	res = KSI_RequestHandle_getAggregationResponse(handle, &response);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_verifyWithRequest(response, req);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = parseAggregationResponse(ctx, rootLevel, response, &sign);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_SignatureVerifier_verifyWithPolicy(ctx, sign, 0, rootHash, policy, context);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

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

int KSI_Signature_signAggregationChain(KSI_CTX *ctx, int level, KSI_AggregationHashChain *chn, KSI_Signature **signature) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;
	KSI_DataHash *root = NULL;
	int root_level;

	if (ctx == NULL || level > 0xff || level < 0 || chn == NULL || signature == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	/* Aggregate the hash chain. */
	res = KSI_AggregationHashChain_aggregate(chn, level, &root_level, &root);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Signature_signAggregated(ctx, root, root_level, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Remove applied level correction in signature. */
	if (root_level != 0) {
		res = tmp->subRootLevel(tmp, root_level);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	res = tmp->appendAggregationChain(tmp, chn);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*signature = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Signature_free(tmp);
	KSI_DataHash_free(root);

	return res;
}

static int KSI_signature_extendToWithoutVerification(const KSI_Signature *sig, KSI_CTX *ctx, KSI_Integer *to, KSI_Signature **extended) {
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
	res = KSI_createExtendRequest(ctx, signTime, to, &req);
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

	res = KSI_RequestHandle_perform(handle);
	if (res != KSI_OK) {
		KSI_pushError(ctx,res, NULL);
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
	res = KSI_ExtendResp_getCalendarHashChain(resp, &calHashChain);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add the hash chain to the signature. */
	res = tmp->replaceCalendarChain(tmp, calHashChain);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Remove the chain from the structure, as it will be freed when this function finishes. */
	res = KSI_ExtendResp_setCalendarHashChain(resp, NULL);
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

int KSI_Signature_extendToWithPolicy(const KSI_Signature *sig, KSI_CTX *ctx, KSI_Integer *to,
		const KSI_Policy *policy, KSI_VerificationContext *context, KSI_Signature **extended) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;


	KSI_ERR_clearErrors(ctx);
	if (sig == NULL || ctx == NULL || extended == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_signature_extendToWithoutVerification(sig, ctx, to, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_SignatureVerifier_verifyWithPolicy(ctx, tmp, 0, NULL, policy, context);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*extended = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Signature_free(tmp);

	return res;
}

int KSI_Signature_extendWithPolicy(const KSI_Signature *signature, KSI_CTX *ctx, const KSI_PublicationRecord *pubRec, const KSI_Policy *policy, KSI_VerificationContext *context, KSI_Signature **extended) {
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
		res = KSI_PublicationRecord_clone(pubRec, &pubRecClone);
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
	res = KSI_signature_extendToWithoutVerification(signature, ctx, pubTime, &tmp);
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

	res = KSI_SignatureVerifier_verifyWithPolicy(ctx, tmp, 0, NULL, policy, context);
	if (res != KSI_OK && res) {
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
	if (sig != NULL && --sig->ref == 0) {
		KSI_TLV_free(sig->baseTlv);
		KSI_CalendarHashChain_free(sig->calendarChain);
		KSI_AggregationHashChainList_free(sig->aggregationChainList);
		KSI_CalendarAuthRec_free(sig->calendarAuthRec);
		KSI_AggregationAuthRec_free(sig->aggregationAuthRec);
		KSI_PublicationRecord_free(sig->publication);
		KSI_RFC3161_free(sig->rfc3161);
		KSI_VerificationResult_reset(&sig->verificationResult);
		KSI_PolicyVerificationResult_free(sig->policyVerificationResult);

		KSI_free(sig);
	}
}


int KSI_Signature_getDocumentHash(const KSI_Signature *sig, KSI_DataHash **hsh) {
	KSI_AggregationHashChain *aggr = NULL;
	KSI_DataHash *inputHash = NULL;
	int res;

	if (sig == NULL || hsh == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	if (sig->rfc3161 == NULL) {
		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggr);
		if (res != KSI_OK || aggr == NULL) {
			KSI_pushError(sig->ctx, res != KSI_OK ? res : (res = KSI_INVALID_STATE), NULL);
			goto cleanup;
		}

		res = KSI_AggregationHashChain_getInputHash(aggr, &inputHash);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
	} else {
		res = KSI_RFC3161_getInputHash(sig->rfc3161, &inputHash);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
	}

	*hsh = inputHash;

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

	if (sig->calendarChain != NULL) {
		res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &tmp);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
	} else {
		KSI_AggregationHashChain *ptr = NULL;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &ptr);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_AggregationHashChain_getAggregationTime(ptr, &tmp);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
	}

	*signTime = tmp;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Signature_clone(const KSI_Signature *sig, KSI_Signature **clone) {
	KSI_Signature *tmp = NULL;
	int res;

	if (sig == NULL || clone == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	res = extractSignature(sig->ctx, sig->baseTlv, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	*clone = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:
	KSI_Signature_free(tmp);

	return res;
}

int KSI_Signature_parseWithPolicy(KSI_CTX *ctx, const unsigned char *raw, size_t raw_len, const KSI_Policy *policy, KSI_VerificationContext *context, KSI_Signature **sig) {
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

	res = KSI_SignatureVerifier_verifyWithPolicy(ctx, tmp, 0, NULL, policy, context);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*sig = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tlv);
	KSI_Signature_free(tmp);

	return res;
}


int KSI_Signature_serialize(const KSI_Signature *sig, unsigned char **raw, size_t *raw_len) {
	int res;
	unsigned char *tmp = NULL;
	size_t tmp_len;

	if (sig == NULL || raw == NULL || raw_len == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	if (sig->baseTlv != NULL) {
		/* We assume that the baseTlv tree is up to date! */
		res = KSI_TLV_serialize(sig->baseTlv, &tmp, &tmp_len);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
	} else {
		res = KSI_TlvTemplate_serializeObject(sig->ctx, sig, 0x0800, 0, 0, KSI_TLV_TEMPLATE(KSI_Signature), &tmp, &tmp_len);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
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
	KSI_Utf8StringList *idList = NULL;
	char *signerId = NULL;
	size_t signerId_size = 1; // At least 1 for trailing zero.
	size_t signerId_len = 0;
	KSI_LIST(KSI_HashChainLink) *pLinks = NULL;

	if (sig == NULL || signerIdentity == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	/* Create a list of separate signer identities. */
	res = KSI_Utf8StringList_new(&idList);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	/* Extract all identities from all aggregation hash chains from top to bottom. */
	for (i = KSI_AggregationHashChainList_length(sig->aggregationChainList); i-- > 0;) {
		KSI_AggregationHashChain *aggrRec = NULL;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &aggrRec);
		if (res != KSI_OK || aggrRec == NULL) {
			KSI_pushError(sig->ctx, res != KSI_OK ? res : (res = KSI_INVALID_STATE), NULL);
			goto cleanup;
		}

		res = KSI_AggregationHashChain_getChain(aggrRec, &pLinks);
		if (res != KSI_OK || pLinks == NULL) {
			KSI_pushError(sig->ctx, res != KSI_OK ? res : (res = KSI_INVALID_STATE), NULL);
			goto cleanup;
		}

		for (j = KSI_HashChainLinkList_length(pLinks); j-- > 0;) {
			KSI_HashChainLink *link = NULL;
			KSI_MetaDataElement *metaData = NULL;
			KSI_OctetString *legacyId = NULL;

			res = KSI_HashChainLinkList_elementAt(pLinks, j, &link);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}

			/* Extract legacyId */
			res = KSI_HashChainLink_getLegacyId(link, &legacyId);
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

			if (legacyId != NULL) {
				KSI_Utf8String *clientId = NULL;

				res = KSI_OctetString_LegacyId_getUtf8String(legacyId, &clientId);
				if (res != KSI_OK) {
					KSI_pushError(sig->ctx, res, NULL);
					goto cleanup;
				}

				signerId_size += KSI_Utf8String_size(clientId) + 4;

				res = KSI_Utf8StringList_append(idList, clientId);
				if (res != KSI_OK) {
					KSI_pushError(sig->ctx, res, NULL);
					goto cleanup;
				}

			} else if (metaData != NULL) {
				KSI_Utf8String *clientId = NULL;
				KSI_Utf8String *ref = NULL;

				res = KSI_MetaDataElement_getClientId(metaData, &clientId);
				if (res != KSI_OK) {
					KSI_pushError(sig->ctx, res, NULL);
					goto cleanup;
				}

				signerId_size += KSI_Utf8String_size(clientId) + 4;

				res = KSI_Utf8StringList_append(idList, ref = KSI_Utf8String_ref(clientId));
				if (res != KSI_OK) {
					/* Cleanup the reference. */
					KSI_Utf8String_free(ref);

					KSI_pushError(sig->ctx, res, NULL);
					goto cleanup;
				}

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
	for (i = 0; i < KSI_Utf8StringList_length(idList); i++) {
		KSI_Utf8String *tmp = NULL;

		res = KSI_Utf8StringList_elementAt(idList, i, &tmp);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		signerId_len += KSI_snprintf(signerId + signerId_len, signerId_size - signerId_len, "%s%s", signerId_len > 0 ? " :: " : "", KSI_Utf8String_cstr(tmp));
	}

	*signerIdentity = signerId;
	signerId = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(signerId);
	KSI_Utf8StringList_free(idList);

	return res;
}

int KSI_Signature_getAggregationHashChainIdentity(const KSI_Signature *sig, KSI_HashChainLinkIdentityList **identity) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	KSI_HashChainLinkIdentityList *tmp = NULL;
	KSI_HashChainLinkIdentityList *aggrId = NULL;
	KSI_HashChainLinkIdentity *linkId = NULL;

	if (sig == NULL || identity == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	res = KSI_HashChainLinkIdentityList_new(&tmp);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	/* Extract all identities from all aggregation hash chains from top to bottom. */
	for (i = KSI_AggregationHashChainList_length(sig->aggregationChainList); i-- > 0;) {
		size_t k;
		KSI_AggregationHashChain *aggr = NULL;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &aggr);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_AggregationHashChain_getIdentity(aggr, &aggrId);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}

		for (k = 0; k < KSI_HashChainLinkIdentityList_length(aggrId); k++) {
			KSI_HashChainLinkIdentity *tmpId = NULL;

			res = KSI_HashChainLinkIdentityList_elementAt(aggrId, k, &tmpId);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}

			res = KSI_HashChainLinkIdentityList_append(tmp, linkId = KSI_HashChainLinkIdentity_ref(tmpId));
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}
			linkId = NULL;
		}
		KSI_HashChainLinkIdentityList_free(aggrId);
		aggrId = NULL;
	}

	*identity = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:
	KSI_HashChainLinkIdentityList_free(aggrId);
	KSI_HashChainLinkIdentityList_free(tmp);
	KSI_HashChainLinkIdentity_free(linkId);

	return res;
}

KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_CalendarAuthRec*, calendarAuthRec, CalendarAuthRec)

KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_PublicationRecord*, publication, PublicationRecord)

static int copyUtf8StringElement(KSI_Utf8String *str, void *list) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Utf8String *ref = NULL;

	res = KSI_Utf8StringList_append((KSI_LIST(KSI_Utf8String)*)list, ref = KSI_Utf8String_ref(str));
	if (res != KSI_OK) {
		/* Cleanup the reference. */
		KSI_Utf8String_free(ref);

		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Signature_getPublicationInfo(const KSI_Signature *sig,
		KSI_DataHash **pubHsh, KSI_Utf8String **pubStr, time_t *pubDate,
		KSI_LIST(KSI_Utf8String) **pubRefs, KSI_LIST(KSI_Utf8String) **repUrls) {
	int res;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_PublicationData *pubData = NULL;
	char *tmpStr = NULL;
	KSI_DataHash *tmpPubHsh = NULL;
	KSI_Utf8String *tmpPubStr = NULL;
	time_t tmpPubDate = 0;
	KSI_LIST(KSI_Utf8String) *tmpPubRefs = NULL;
	KSI_LIST(KSI_Utf8String) *tmpRepUrls = NULL;

	if (sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(sig->ctx);

	res = KSI_Signature_getPublicationRecord(sig, &pubRec);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}
	/* Check whether publication record is valid */
	if (pubRec == NULL) {
		KSI_pushError(sig->ctx, res = KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	/* Get publication reference list */
	if (pubRefs != NULL) {
		res = KSI_Utf8StringList_new(&tmpPubRefs);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
		res = KSI_Utf8StringList_foldl(pubRec->publicationRef, tmpPubRefs, copyUtf8StringElement);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Get Repository URL list*/
	if (repUrls != NULL) {
		res = KSI_Utf8StringList_new(&tmpRepUrls);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
		res = KSI_Utf8StringList_foldl(pubRec->repositoryUriList, tmpRepUrls, copyUtf8StringElement);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Get publication data */
	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubData);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	/* Convert publication data into base-32 string */
	if (pubStr != NULL) {
		res = KSI_PublicationData_toBase32(pubData, &tmpStr);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
		res = KSI_Utf8String_new(sig->ctx, tmpStr, strlen(tmpStr) + 1, &tmpPubStr);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Get publication time */
	if (pubDate != NULL) {
		tmpPubDate = KSI_Integer_getUInt64(pubData->time);
	}

	/* Get data hash imprint */
	if (pubHsh != NULL) {
		tmpPubHsh = KSI_DataHash_ref(pubData->imprint);
	}

	if (pubHsh != NULL) {
		*pubHsh = tmpPubHsh;
		tmpPubHsh = NULL;
	}
	if (pubStr != NULL) {
		*pubStr = tmpPubStr;
		tmpPubStr = NULL;
	}
	if (pubDate != NULL) {
		*pubDate = tmpPubDate;
	}
	if (pubRefs != NULL) {
		*pubRefs = tmpPubRefs;
		tmpPubRefs = NULL;
	}
	if (repUrls != NULL) {
		*repUrls = tmpRepUrls;
		tmpRepUrls = NULL;
	}

	res = KSI_OK;

cleanup:

	if (tmpStr) KSI_free(tmpStr);

	KSI_DataHash_free(tmpPubHsh);
	KSI_Utf8String_free(tmpPubStr);
	KSI_Utf8StringList_free(tmpPubRefs);
	KSI_Utf8StringList_free(tmpRepUrls);

	return res;
}
