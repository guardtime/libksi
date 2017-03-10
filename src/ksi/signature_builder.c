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
#include "signature_builder.h"
#include "signature_builder_impl.h"
#include "internal.h"
#include "signature_impl.h"
#include "tlv.h"
#include "tlv_template.h"
#include "hashchain.h"

KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarHashChain);
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationHashChain);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationAuthRec);
KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarAuthRec);
KSI_IMPORT_TLV_TEMPLATE(KSI_RFC3161);

static KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_CalendarHashChain*, calendarChain, CalendarChain)
static KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_LIST(KSI_AggregationHashChain)*, aggregationChainList, AggregationChainList)
static KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_CalendarAuthRec*, calendarAuthRec, CalendarAuthRecord)
static KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_AggregationAuthRec*, aggregationAuthRec, AggregationAuthRecord)
static KSI_IMPLEMENT_GETTER(KSI_Signature, KSI_RFC3161*, rfc3161, RFC3161)

static KSI_IMPLEMENT_SETTER(KSI_Signature, KSI_CalendarHashChain*, calendarChain, CalendarChain)
static KSI_IMPLEMENT_SETTER(KSI_Signature, KSI_LIST(KSI_AggregationHashChain)*, aggregationChainList, AggregationChainList)
static KSI_IMPLEMENT_SETTER(KSI_Signature, KSI_CalendarAuthRec*, calendarAuthRec, CalendarAuthRecord)
static KSI_IMPLEMENT_SETTER(KSI_Signature, KSI_AggregationAuthRec*, aggregationAuthRec, AggregationAuthRecord)
static KSI_IMPLEMENT_SETTER(KSI_Signature, KSI_PublicationRecord*, publication, PublicationRecord)
static KSI_IMPLEMENT_SETTER(KSI_Signature, KSI_RFC3161*, rfc3161, RFC3161)

KSI_DEFINE_TLV_TEMPLATE(KSI_Signature)
	KSI_TLV_COMPOSITE_LIST(0x0801, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Signature_getAggregationChainList, KSI_Signature_setAggregationChainList, KSI_AggregationHashChain, "aggr_chain")
	KSI_TLV_COMPOSITE(0x0802, KSI_TLV_TMPL_FLG_NONE, KSI_Signature_getCalendarChain, KSI_Signature_setCalendarChain, KSI_CalendarHashChain, "cal_chain")
	KSI_TLV_COMPOSITE(0x0803, KSI_TLV_TMPL_FLG_MOST_ONE_G0, KSI_Signature_getPublicationRecord, KSI_Signature_setPublicationRecord, KSI_PublicationRecord, "pub_rec")
	KSI_TLV_COMPOSITE(0x0804, KSI_TLV_TMPL_FLG_NONE, KSI_Signature_getAggregationAuthRecord, KSI_Signature_setAggregationAuthRecord, KSI_AggregationAuthRec, "aggr_auth_rec")
	KSI_TLV_COMPOSITE(0x0805, KSI_TLV_TMPL_FLG_MOST_ONE_G0, KSI_Signature_getCalendarAuthRecord, KSI_Signature_setCalendarAuthRecord, KSI_CalendarAuthRec, "cal_auth_rec")
	KSI_TLV_COMPOSITE(0x0806, KSI_TLV_TMPL_FLG_NONE, KSI_Signature_getRFC3161, KSI_Signature_setRFC3161, KSI_RFC3161, "rfc3161_rec")
KSI_END_TLV_TEMPLATE

static int replaceCalendarChain(KSI_Signature *sig, KSI_CalendarHashChain *calendarHashChain) {
	int res;
	KSI_DataHash *aggrOutputHash = NULL;
	KSI_TLV *oldCalChainTlv = NULL;
	KSI_TLV *newCalChainTlv = NULL;
	KSI_LIST(KSI_TLV) *nestedList = NULL;
	size_t i;

	if (sig == NULL || calendarHashChain == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	res = KSI_TLV_getNestedList(sig->baseTlv, &nestedList);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	if (sig->calendarChain != NULL) {
		for (i = 0; i < KSI_TLVList_length(nestedList); i++) {
			res = KSI_TLVList_elementAt(nestedList,i, &oldCalChainTlv);
			if (res != KSI_OK) {
				KSI_pushError(sig->ctx, res, NULL);
				goto cleanup;
			}

			if (oldCalChainTlv == NULL) {
				KSI_pushError(sig->ctx, res = KSI_INVALID_SIGNATURE, "Signature TLV element missing.");
				goto cleanup;
			}

			if (KSI_TLV_getTag(oldCalChainTlv) == 0x0802) break;
		}
	}

	res = KSI_TLV_new(sig->ctx, 0x0802, 0, 0, &newCalChainTlv);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TlvTemplate_construct(sig->ctx, newCalChainTlv, calendarHashChain, KSI_TLV_TEMPLATE(KSI_CalendarHashChain));
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = (sig->calendarChain == NULL) ?
			/* In case there is no calendar hash chain attached, append a new one. */
			KSI_TLV_appendNestedTlv(sig->baseTlv, newCalChainTlv) :
			/* Otherwise replace the calendar hash chain. */
			KSI_TLV_replaceNestedTlv(sig->baseTlv, oldCalChainTlv, newCalChainTlv);
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

	KSI_DataHash_free(aggrOutputHash);
	KSI_TLV_free(newCalChainTlv);

	return res;
}

static int add(KSI_uint64_t r, KSI_uint64_t l, KSI_uint64_t *res) {
	KSI_uint64_t t;
	t = r + l;
	if (t < r || t < l) return KSI_BUFFER_OVERFLOW;
	*res = t;
	return KSI_OK;
}

static int sub(KSI_uint64_t r, KSI_uint64_t l, KSI_uint64_t *res) {
	if (r < l) return KSI_INVALID_FORMAT;
	*res = r - l;
	return KSI_OK;
}

static int updateLevelCorrection(KSI_CTX *ctx, KSI_Signature *sig, KSI_uint64_t rootLevel,
		int (*calc)(KSI_uint64_t, KSI_uint64_t, KSI_uint64_t*)) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationHashChain *aggr = NULL;
	KSI_LIST(KSI_HashChainLink) *chain = NULL;
	KSI_HashChainLink *link = NULL;
	KSI_Integer *oldLvl = NULL;
	KSI_Integer *newLvl = NULL;
	KSI_uint64_t lvlVal = 0;
	KSI_TLV *newTlv = NULL;
	KSI_TLV *oldTlv = NULL;
	KSI_LIST(KSI_TLV) *tlvList = NULL;
	size_t i;
	KSI_AggregationHashChain *aggrFromTlv = NULL;
	if (ctx == NULL || sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (!KSI_IS_VALID_TREE_LEVEL(rootLevel)) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Aggregation level can't be larger than 0xff.");
		goto cleanup;
	}

	if (rootLevel == 0) {
		res = KSI_OK;
		goto cleanup;
	}

	/* Get first aggregation hash chain first link. */
	res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationHashChain_getChain(aggr, &chain);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_HashChainLinkList_elementAt(chain, 0, &link);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Apply new level correction. */
	res = KSI_HashChainLink_getLevelCorrection(link, &oldLvl);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = calc(KSI_Integer_getUInt64(oldLvl), rootLevel, &lvlVal);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Integer_new(ctx, lvlVal, &newLvl);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_HashChainLink_setLevelCorrection(link, newLvl);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	newLvl = NULL;
	KSI_Integer_free(oldLvl);
	oldLvl = NULL;


	/* Replace the the updated aggregation hash chain in the signature base TLV. */
	res = KSI_TLV_new(sig->ctx, 0x0801, 0, 0, &newTlv);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TlvTemplate_construct(ctx, newTlv, aggr, KSI_TLV_TEMPLATE(KSI_AggregationHashChain));
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_getNestedList(sig->baseTlv, &tlvList);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	for (i = 0; i < KSI_TLVList_length(tlvList); i++) {
		KSI_TLV *t = NULL;

		res = KSI_TLVList_elementAt(tlvList, i, &t);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (KSI_TLV_getTag(t) == 0x0801) {
			res = KSI_AggregationHashChain_new(ctx, &aggrFromTlv);
			if (res != KSI_OK) {
				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}

			res = KSI_TlvTemplate_extract(ctx, aggrFromTlv, t, KSI_TLV_TEMPLATE(KSI_AggregationHashChain));
			if (res != KSI_OK) {
				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}

			if (KSI_AggregationHashChain_compare((const KSI_AggregationHashChain**)&aggr, (const KSI_AggregationHashChain**)&aggrFromTlv) == 0) {
				oldTlv = t;
				break;
			}

			KSI_AggregationHashChain_free(aggrFromTlv);
			aggrFromTlv = NULL;
		}
	}

	res = KSI_TLV_replaceNestedTlv(sig->baseTlv, oldTlv, newTlv);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}
	newTlv = NULL;

	res = KSI_OK;
cleanup:
	KSI_Integer_free(newLvl);
	KSI_TLV_free(newTlv);
	KSI_AggregationHashChain_free(aggrFromTlv);

	return res;
}

static int addRootLevel(KSI_CTX *ctx, KSI_Signature *sig, KSI_uint64_t rootLevel) {
	return updateLevelCorrection(ctx, sig, rootLevel, add);
}

static int subRootLevel(KSI_CTX *ctx, KSI_Signature *sig, KSI_uint64_t rootLevel) {
	return updateLevelCorrection(ctx, sig, rootLevel, sub);
}

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
	tmp->ref = 1;
	tmp->calendarChain = NULL;
	tmp->baseTlv = NULL;
	tmp->publication = NULL;
	tmp->aggregationChainList = NULL;
	tmp->aggregationAuthRec = NULL;
	tmp->aggregationChainList = NULL;
	tmp->calendarAuthRec = NULL;
	tmp->rfc3161 = NULL;
	tmp->publication = NULL;
	tmp->replaceCalendarChain = replaceCalendarChain;
	tmp->addRootLevel = addRootLevel;
	tmp->subRootLevel = subRootLevel;

	res = KSI_VerificationResult_init(&tmp->verificationResult, ctx);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->policyVerificationResult = NULL;

	*sig = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Signature_free(tmp);

	return res;

}


int KSI_SignatureBuilder_open(KSI_CTX *ctx, KSI_SignatureBuilder **builder) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_SignatureBuilder *tmp = NULL;

	if (ctx == NULL || builder == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	tmp = KSI_new(KSI_SignatureBuilder);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->noVerify = 0;
	tmp->sig = NULL;

	res = KSI_Signature_new(ctx, &tmp->sig);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*builder = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_SignatureBuilder_free(tmp);

	return res;
}

static int checkSignatureInternals(KSI_CTX *ctx, KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;

	if (ctx == NULL || sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* A valid signature must have at least one aggregation chain. */
	if (sig->aggregationChainList == NULL || KSI_AggregationHashChainList_length(sig->aggregationChainList) == 0) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "A valid signature must have at least one aggregation hash chain.");
		goto cleanup;
	}

	/* If there is no calendar chain, there can not be a calendar auth record nor a publication record. */
	if (sig->calendarChain == NULL && (sig->calendarAuthRec != NULL || sig->publication != NULL)) {
		KSI_pushError(ctx, KSI_INVALID_FORMAT, "Calendar auth record or publication record may not be specified if the calendar chain is missing.");
		goto cleanup;
	}

	/* Make sure the signature does not have both calendar auth record and a publication in it. */
	if (sig->calendarAuthRec != NULL && sig->publication != NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Only calendar auth record or publication record may be present.");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_SignatureBuilder_close(KSI_SignatureBuilder *builder, KSI_uint64_t rootLevel, KSI_Signature **sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	int tlvConstructed = 0;
	KSI_Signature *clone = NULL;

	if (builder == NULL || sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_VerificationContext_init(&context, builder->ctx);
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}

	/* Make sure the aggregation hash chains are in correct order. */
	res = KSI_AggregationHashChainList_sort(builder->sig->aggregationChainList, KSI_AggregationHashChain_compare);
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}

	res = checkSignatureInternals(builder->ctx, builder->sig);
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, "Signature internal structures are invalid.");
		goto cleanup;
	}

	if (builder->sig->baseTlv == NULL) {
		/* Construct TLV object. */

		res = KSI_TLV_new(builder->ctx, 0x0800, 0, 0, &builder->sig->baseTlv);
		if (res != KSI_OK) {
			KSI_pushError(builder->ctx, res, NULL);
			goto cleanup;
		}
		tlvConstructed = 1;

		res = KSI_TlvTemplate_construct(builder->ctx, builder->sig->baseTlv, builder->sig, KSI_TLV_TEMPLATE(KSI_Signature));
		if (res != KSI_OK) {
			KSI_pushError(builder->ctx, res, NULL);
			goto cleanup;
		}
	}

	if (rootLevel != 0) {
		res = addRootLevel(builder->ctx, builder->sig, rootLevel);
		if (res != KSI_OK) {
			KSI_pushError(builder->ctx, res, NULL);
			goto cleanup;
		}
	}

	KSI_LOG_logTlv(builder->ctx, KSI_LOG_DEBUG, "Signature", builder->sig->baseTlv);

	if (!builder->noVerify) {
		/* Verify the signature. */

		KSI_Signature_clone(builder->sig, &clone);
		context.signature = clone;

		res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
		if (res != KSI_OK) {
			KSI_pushError(builder->ctx, res, NULL);
			goto cleanup;
		}

		if (result->finalResult.resultCode != KSI_VER_RES_OK) {
			KSI_pushError(builder->ctx, res = KSI_VERIFICATION_FAILURE, "Internal verification of signature failed.");
			goto cleanup;
		}
	}

	*sig = builder->sig;
	builder->sig = NULL;

	res = KSI_OK;

cleanup:
	if (res != KSI_OK && tlvConstructed) {
		KSI_TLV_free(builder->sig->baseTlv);
		builder->sig->baseTlv = NULL;
	}
	KSI_Signature_free(clone);
	KSI_VerificationContext_clean(&context);
	KSI_PolicyVerificationResult_free(result);

	return res;
}

void KSI_SignatureBuilder_free(KSI_SignatureBuilder *builder) {
	if (builder != NULL) {
		KSI_Signature_free(builder->sig);
		KSI_free(builder);
	}
}

int KSI_SignatureBuilder_setCalendarHashChain(KSI_SignatureBuilder *builder, KSI_CalendarHashChain *cal) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CalendarHashChain *tmp = NULL;

	if (builder == NULL || cal == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Do not allow overriding of the value, as it is likely an error. */
	if (builder->sig->calendarChain != NULL) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The calendar hash chain has already been set.");
		goto cleanup;
	}

	res =  KSI_Signature_setCalendarChain(builder->sig, tmp = KSI_CalendarHashChain_ref(cal));
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_CalendarHashChain_free(tmp);

	return res;
}

int KSI_SignatureBuilder_addAggregationChain(KSI_SignatureBuilder *builder, KSI_AggregationHashChain *aggr) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationHashChain *tmp = NULL;

	if (builder == NULL || aggr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Make sure the builder is in a valid state. */
	if (builder->sig == NULL) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The builder has not been correctly initialized.");
		goto cleanup;
	}

	/* Make sure the list of aggregation chains has been initialized. */
	if (builder->sig->aggregationChainList == NULL) {
		res = KSI_AggregationHashChainList_new(&builder->sig->aggregationChainList);
		if (res != KSI_OK) {
			KSI_pushError(builder->ctx, res, NULL);
			goto cleanup;
		}
	}

	res = KSI_AggregationHashChainList_append(builder->sig->aggregationChainList, tmp = KSI_AggregationHashChain_ref(aggr));
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_AggregationHashChain_free(tmp);

	return res;
}

int KSI_SignatureBuilder_setCalendarAuthRecord(KSI_SignatureBuilder *builder, KSI_CalendarAuthRec *calAuth) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CalendarAuthRec *tmp = NULL;

	if (builder == NULL || calAuth == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Make sure the builder is in a valid state. */
	if (builder->sig == NULL) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The builder has not been correctly initialized.");
		goto cleanup;
	}

	/* Do not allow overriding of the value, as it is likely an error. */
	if (builder->sig->calendarAuthRec != NULL) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The authentication record has already been set.");
		goto cleanup;
	}

	res = KSI_Signature_setCalendarAuthRecord(builder->sig, tmp = KSI_CalendarAuthRec_ref(calAuth));
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_CalendarAuthRec_free(tmp);

	return res;
}
int KSI_SignatureBuilder_setPublication(KSI_SignatureBuilder *builder, KSI_PublicationRecord *pub) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationRecord *tmp = NULL;

	if (builder == NULL || pub == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Make sure the builder is in a valid state. */
	if (builder->sig == NULL) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The builder has not been correctly initialized.");
		goto cleanup;
	}

	/* Do not allow overriding of the value, as it is likely an error. */
	if (builder->sig->publication != NULL) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The publication has already been set.");
		goto cleanup;
	}

	res = KSI_Signature_setPublicationRecord(builder->sig, tmp = KSI_PublicationRecord_ref(pub));
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_PublicationRecord_free(tmp);

	return res;

}

int KSI_SignatureBuilder_setRFC3161(KSI_SignatureBuilder *builder, KSI_RFC3161 *rfc3161) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RFC3161 *tmp = NULL;

	if (builder == NULL || rfc3161 == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Make sure the builder is in a valid state. */
	if (builder->sig == NULL) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The builder has not been correctly initialized.");
		goto cleanup;
	}

	/* Do not allow overriding of the value, as it is likely an error. */
	if (builder->sig->rfc3161 != NULL) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The RFC3161 record has already been set.");
		goto cleanup;
	}

	res = KSI_Signature_setRFC3161(builder->sig, tmp = KSI_RFC3161_ref(rfc3161));
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_RFC3161_free(tmp);

	return res;

}
