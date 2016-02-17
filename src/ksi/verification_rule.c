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

#include "verification_rule.h"
#include "policy_impl.h"
#include "policy.h"
#include "internal.h"
#include "verification_impl.h"
#include "signature_impl.h"
#include "hashchain.h"

#define CATCH_KSI_ERR(func) \
	res = func; \
	if (res != KSI_OK) { \
		packVerificationErrorResult(result, NA, GEN_2); \
		goto cleanup; \
	}

static int packVerificationErrorResult(KSI_RuleVerificationResult *result, VerificationResultCode resCode, VerificationErrorCode errCode);
static int rfc3161_preSufHasher(KSI_CTX *ctx, const KSI_OctetString *prefix, const KSI_DataHash *hsh, const KSI_OctetString *suffix, int hsh_id, KSI_DataHash **out);
static int rfc3161_verify(KSI_CTX *ctx, const KSI_Signature *sig);
static int rfc3161_getOutputHash(const KSI_Signature *sig, KSI_DataHash **outputHash);
static int aggrHashChain_getOutputHash(KSI_CTX *ctx, KSI_Signature *sig, int level, KSI_DataHash **outputHash);
static int getExtendedCalendarHashChain(VerificationContext *info, KSI_Integer *pubTime, KSI_CalendarHashChain **extCalHashChain);


static int packVerificationErrorResult(KSI_RuleVerificationResult *result, VerificationResultCode resCode, VerificationErrorCode errCode) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->resultCode = resCode;
	result->errorCode  = errCode;

	res = KSI_OK;

cleanup:

	return res;
}

static int rfc3161_preSufHasher(KSI_CTX *ctx, const KSI_OctetString *prefix, const KSI_DataHash *hsh, const KSI_OctetString *suffix, int hsh_id, KSI_DataHash **out) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *tmp = NULL;
	const unsigned char *imprint = NULL;
	size_t imprint_len = 0;
	const unsigned char *data = NULL;
	size_t data_len = 0;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || prefix == NULL || hsh == NULL || suffix == NULL || out == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/*Generate TST Info structure and get its hash*/
	res = KSI_DataHasher_open(ctx, hsh_id, &hsr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OctetString_extract(prefix, &data, &data_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (data != NULL) {
		res = KSI_DataHasher_add(hsr, data, data_len);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_add(hsr, imprint + 1, imprint_len - 1);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OctetString_extract(suffix, &data, &data_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (data != NULL) {
		res = KSI_DataHasher_add(hsr, data, data_len);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}


	/*Get hash and its imprint*/
	res = KSI_DataHasher_close(hsr, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}


	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(tmp);

	return res;
}

static int rfc3161_verify(KSI_CTX *ctx, const KSI_Signature *sig) {
	int res;
	KSI_RFC3161 *rfc3161 = NULL;
	KSI_AggregationHashChain *firstChain = NULL;
	unsigned i;

	if (ctx == NULL || sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(ctx);

	rfc3161 = sig->rfc3161;
	if (rfc3161 == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	if (sig->aggregationChainList == NULL) {
		KSI_LOG_info(ctx, "Aggregation chain is missing.");
		goto cleanup;
	}

	res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &firstChain);
	if (res != KSI_OK) {
		goto cleanup;
	}

	if (KSI_Integer_compare(firstChain->aggregationTime, rfc3161->aggregationTime) != 0) {
		KSI_LOG_info(ctx, "Aggregation chain and RFC 3161 aggregation time mismatch.");
		KSI_LOG_debug(ctx, "Signatures aggregation time: %i.", KSI_Integer_getUInt64(firstChain->aggregationTime));
		KSI_LOG_debug(ctx, "RFC 3161 aggregation time:   %i.", KSI_Integer_getUInt64(rfc3161->aggregationTime));
		goto cleanup;
	}

	if (KSI_IntegerList_length(firstChain->chainIndex) != KSI_IntegerList_length(rfc3161->chainIndex)) {
		KSI_LOG_info(ctx, "Aggregation chain and RFC 3161 chain index mismatch.", KSI_IntegerList_length(firstChain->chainIndex));
		KSI_LOG_debug(ctx, "Signatures chain index length: %i.", KSI_IntegerList_length(firstChain->chainIndex));
		KSI_LOG_debug(ctx, "RFC 3161 chain index length:   %i.", KSI_IntegerList_length(rfc3161->chainIndex));
	} else {
		for (i = 0; i < KSI_IntegerList_length(firstChain->chainIndex); i++){
			KSI_Integer *ch1 = NULL;
			KSI_Integer *ch2 = NULL;

			res = KSI_IntegerList_elementAt(firstChain->chainIndex, i, &ch1);
			if (res != KSI_OK) {
				goto cleanup;
			}

			res = KSI_IntegerList_elementAt(rfc3161->chainIndex, i, &ch2);
			if (res != KSI_OK) {
				goto cleanup;
			}

			if (KSI_Integer_compare(ch1, ch2) != 0) {
				KSI_LOG_debug(ctx, "Aggregation chain and RFC 3161 chain index mismatch.");
				break;
			}
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int rfc3161_getOutputHash(const KSI_Signature *sig, KSI_DataHash **outputHash) {
	int res;
	KSI_CTX *ctx = NULL;
	KSI_DataHash *hsh_tstInfo = NULL;
	KSI_DataHash *hsh_sigAttr = NULL;
	KSI_DataHash *tmp = NULL;
	KSI_DataHasher *hsr = NULL;
	KSI_RFC3161 *rfc3161 = NULL;
	const unsigned char *imprint = NULL;
	size_t imprint_len = 0;
	KSI_HashAlgorithm algo_id = -1;
	KSI_HashAlgorithm tstInfoAlgoId;
	KSI_HashAlgorithm sigAttrAlgoId;

	if (sig == NULL || outputHash == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = sig->ctx;

	rfc3161 = sig->rfc3161;
	if (rfc3161 == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (KSI_Integer_getUInt64(rfc3161->tstInfoAlgo) > 0xff || KSI_Integer_getUInt64(rfc3161->sigAttrAlgo) > 0xff) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Hash algorithm can't be larger than 0xff.");
		goto cleanup;
	} else {
		tstInfoAlgoId = (int)KSI_Integer_getUInt64(rfc3161->tstInfoAlgo);
		sigAttrAlgoId = (int)KSI_Integer_getUInt64(rfc3161->sigAttrAlgo);
	}

	res = rfc3161_preSufHasher(ctx, rfc3161->tstInfoPrefix, rfc3161->inputHash, rfc3161->tstInfoSuffix, tstInfoAlgoId, &hsh_tstInfo);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = rfc3161_preSufHasher(ctx, rfc3161->sigAttrPrefix, hsh_tstInfo, rfc3161->sigAttrSuffix, sigAttrAlgoId, &hsh_sigAttr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_getImprint(hsh_sigAttr, &imprint, &imprint_len);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Signature_getHashAlgorithm((KSI_Signature *)sig, &algo_id);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_create(ctx, imprint, imprint_len, algo_id, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	*outputHash = tmp;
	tmp = NULL;

cleanup:

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh_tstInfo);
	KSI_DataHash_free(hsh_sigAttr);
	KSI_DataHash_free(tmp);

	return res;
}

int KSI_VerificationRule_AggregationChainInputHashVerification(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *rfc3161_outputHash = NULL;
	KSI_AggregationHashChain* firstChain = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	KSI_LOG_info(ctx, "Verifying aggregation hash input hash.");

	if (sig->rfc3161 != NULL) {
		res = rfc3161_verify(ctx, sig);
		if (res != KSI_OK){
			KSI_LOG_info(ctx, "RFC 3161 does not belong to this aggregation hash chain.");
			packVerificationErrorResult(result, FAIL, GEN_2);
			goto cleanup;
		}

		KSI_LOG_info(ctx, "Using input hash calculated from RFC 3161 for aggregation.");
		CATCH_KSI_ERR(rfc3161_getOutputHash(sig, &rfc3161_outputHash));

		if (sig->aggregationChainList == NULL) {
			res = KSI_INVALID_SIGNATURE;
			KSI_LOG_info(ctx, "Aggregation chain is missing.");
			packVerificationErrorResult(result, FAIL, GEN_2);
			goto cleanup;
		}

		CATCH_KSI_ERR(KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &firstChain));

		if (rfc3161_outputHash != NULL){
			if (!KSI_DataHash_equals(rfc3161_outputHash, firstChain->inputHash)) {
				KSI_pushError(ctx, res, "Aggregation hash chain's input hash does not match with RFC 3161 input hash.");
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Input hash from RFC 3161 :", rfc3161_outputHash);
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected input hash      :", firstChain->inputHash);
				packVerificationErrorResult(result, FAIL, INT_1);
				goto cleanup;
			}
		}
	}

	res = KSI_OK;

cleanup:
	KSI_DataHash_free(rfc3161_outputHash);

	return res;
}


int KSI_VerificationRule_AggregationHashChainConsistency(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	const KSI_AggregationHashChain *prevChain = NULL;
	KSI_DataHash *hsh = NULL;
	int successCount = 0;
	int level = 0;
	size_t i;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;


	/* The aggregation level might not be 0 in case of local aggregation. */
	if (info->docAggrLevel > 0xff) {
		/* Aggregation level can't be larger than 0xff */
		res = KSI_INVALID_FORMAT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	level = (int)info->docAggrLevel;

	KSI_LOG_info(ctx, "Verifying aggregation hash chain consistency.");

	/* Aggregate all the aggregation chains. */
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		const KSI_AggregationHashChain* aggregationChain = NULL;
		KSI_DataHash *tmpHash = NULL;

		CATCH_KSI_ERR(KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain));

		if (aggregationChain == NULL) break;

		if (prevChain != NULL) {
			/* Verify chain index length. */
			if (KSI_IntegerList_length(prevChain->chainIndex) != KSI_IntegerList_length(aggregationChain->chainIndex) + 1) {
				KSI_LOG_debug(ctx, "Unexpected chain index length in aggregation chain.");
				packVerificationErrorResult(result, NA, GEN_2);
				goto cleanup;
			} else {
				unsigned j;
				for (j = 0; j < KSI_IntegerList_length(aggregationChain->chainIndex); j++) {
					KSI_Integer *chainIndex1 = NULL;
					KSI_Integer *chainIndex2 = NULL;

					CATCH_KSI_ERR(KSI_IntegerList_elementAt(prevChain->chainIndex, j, &chainIndex1));

					CATCH_KSI_ERR(KSI_IntegerList_elementAt(aggregationChain->chainIndex, j, &chainIndex2));

					if (!KSI_Integer_equals(chainIndex1, chainIndex2)) {
						KSI_LOG_debug(ctx, "Aggregation chain chain index is not continuation of previous chain index.");
						packVerificationErrorResult(result, NA, GEN_2);
						goto cleanup;
					}
				}
			}
		}

		if (hsh != NULL) {
			/* Validate input hash */
			if (!KSI_DataHash_equals(hsh, aggregationChain->inputHash)) {
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calculated hash :", hsh);
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected hash   :", aggregationChain->inputHash);
				packVerificationErrorResult(result, FAIL, INT_1);
				goto cleanup;
			}
		}

		CATCH_KSI_ERR(KSI_HashChain_aggregate(aggregationChain->ctx, aggregationChain->chain, aggregationChain->inputHash,
											  level, (int)KSI_Integer_getUInt64(aggregationChain->aggrHashId), &level, &tmpHash));

		if (hsh != NULL) {
			KSI_DataHash_free(hsh);
		}
		hsh = tmpHash;
		++successCount;
		prevChain = aggregationChain;
	}

	/* First verify internal calculations. */
	if (successCount != KSI_AggregationHashChainList_length(sig->aggregationChainList)) {
		KSI_LOG_debug(ctx, "Aggregation hash chain calculation failed.");
		packVerificationErrorResult(result, FAIL, INT_1);
		goto cleanup;
	}

	info->aggregationHash = hsh;
	hsh = NULL;

	res = KSI_OK;

cleanup:
	KSI_DataHash_free(hsh);

	return res;
}

int KSI_VerificationRule_AggregationHashChainTimeConsistency(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	const KSI_AggregationHashChain *prevChain = NULL;
	size_t i;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	KSI_LOG_info(ctx, "Verifying aggregation hash chain internal time consistency.");

	/* Aggregate all the aggregation chains. */
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		const KSI_AggregationHashChain* aggregationChain = NULL;

		CATCH_KSI_ERR(KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain));

		if (aggregationChain == NULL) break;

		if (prevChain != NULL) {
			/* Verify aggregation time. */
			if (!KSI_Integer_equals(aggregationChain->aggregationTime, prevChain->aggregationTime)) {
				KSI_LOG_debug(ctx, "Aggregation hash chain's from different aggregation rounds.");
				packVerificationErrorResult(result, FAIL, INT_2);
				goto cleanup;
			}
		}

		prevChain = aggregationChain;
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int aggrHashChain_getOutputHash(KSI_CTX *ctx, KSI_Signature *sig, int level, KSI_DataHash **outputHash) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	KSI_DataHash *tmp = NULL;

	if (ctx == NULL || sig == NULL || outputHash == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* The aggregation level might not be 0 in case of local aggregation. */
	if (level > 0xff) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Aggregation level can't be larger than 0xff.");
		goto cleanup;
	}

	/* Aggregate all the aggregation chains. */
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		const KSI_AggregationHashChain* aggregationChain = NULL;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;

		}
		if (aggregationChain == NULL) break;

		res = KSI_HashChain_aggregate(ctx, aggregationChain->chain, aggregationChain->inputHash,
									  level, (int)KSI_Integer_getUInt64(aggregationChain->aggrHashId), &level, &tmp);
		if (res != KSI_OK){
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	*outputHash = tmp;
	tmp = NULL;

cleanup:

	KSI_DataHash_free(tmp);

	return res;
}

int KSI_VerificationRule_CalendarHashChainInputHashVerification(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *aggrOutputHash = NULL;
	KSI_DataHash *calInputHash = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	if (sig->calendarChain == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verifying calendar hash chain input hash consistency");

	CATCH_KSI_ERR(aggrHashChain_getOutputHash(ctx, sig, (int)info->docAggrLevel, &aggrOutputHash));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getInputHash(sig->calendarChain, &calInputHash));

	if (aggrOutputHash == NULL  || calInputHash == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	if (!KSI_DataHash_equals(aggrOutputHash, calInputHash)) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_LOG_info(ctx, "Calendar hash chain's input hash does not match with aggregation root hash.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Input hash from aggregation :", aggrOutputHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected input hash         :", calInputHash);
		packVerificationErrorResult(result, FAIL, INT_3);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:
	KSI_DataHash_free(aggrOutputHash);

	return res;
}

int KSI_VerificationRule_CalendarHashChainAggregationTime(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationHashChain *aggregationChain = NULL;
	KSI_Integer *calAggrTime = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	if (sig->calendarChain == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verifying calendar aggregation time consistency");

	/* Take the first aggregation hash chain, as all of the chain should have the same value for "aggregation time". */
	CATCH_KSI_ERR(KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggregationChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &calAggrTime));

	if (!KSI_Integer_equals(calAggrTime, aggregationChain->aggregationTime)) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_LOG_info(ctx, "Aggregation time in calendar chain and aggregation chain differ.");
		packVerificationErrorResult(result, FAIL, INT_4);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarHashChainRegistrationTime(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	time_t calculatedAggrTime;
	KSI_Integer *calendarAggrTime = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	if (sig->calendarChain == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verifying calendar hash chain time consistency");

	CATCH_KSI_ERR(KSI_CalendarHashChain_calculateAggregationTime(sig->calendarChain, &calculatedAggrTime));
	CATCH_KSI_ERR(KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &calendarAggrTime));

	if (!KSI_Integer_equalsUInt(calendarAggrTime, (KSI_uint64_t) calculatedAggrTime)) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_LOG_info(ctx, "Calendar chain internally inconsistent.");
		packVerificationErrorResult(result, FAIL, INT_5);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationData *pubData = NULL;
	KSI_DataHash *pubHash = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	if (sig->calendarAuthRec == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(sig->ctx, "Verifying calendar authentication record.");

	/* Calculate the root hash value. */
	CATCH_KSI_ERR(KSI_CalendarHashChain_aggregate(sig->calendarChain, &rootHash));
	/* Get publication data. */
	CATCH_KSI_ERR(KSI_CalendarAuthRec_getPublishedData(sig->calendarAuthRec, &pubData));
	/* Get published hash value. */
	CATCH_KSI_ERR(KSI_PublicationData_getImprint(pubData, &pubHash));

	if (!KSI_DataHash_equals(rootHash, pubHash)) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_LOG_info(sig->ctx, "Calendar chain and authentication record hash mismatch.");
		packVerificationErrorResult(result, FAIL, INT_8);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:
	KSI_DataHash_free(rootHash);

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationData *pubData = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_Integer *calPubTime = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	if (sig->calendarAuthRec == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(sig->ctx, "Verifying calendar authentication record publication time.");

	/* Get the publication time from calendar hash chain. */
	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &calPubTime));
	/* Get publication data. */
	CATCH_KSI_ERR(KSI_CalendarAuthRec_getPublishedData(sig->calendarAuthRec, &pubData));
	/* Get publication time. */
	CATCH_KSI_ERR(KSI_PublicationData_getTime(pubData, &pubTime));

	if (!KSI_Integer_equals(calPubTime, pubTime)) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_LOG_info(sig->ctx, "Calendar chain and authentication record time mismatch.");
		packVerificationErrorResult(result, FAIL, INT_6);
		goto cleanup;
	}


	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_SignaturePublicationRecordPublicationHash(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationData *pubData = NULL;
	KSI_DataHash *publishedHash = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	if (sig->publication == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(sig->ctx, "Verifying calendar chain with publication");

	/* Calculate calendar aggregation root hash value. */
	CATCH_KSI_ERR(KSI_CalendarHashChain_aggregate(sig->calendarChain, &rootHash));
	/* Get publication data from publication record */
	CATCH_KSI_ERR(KSI_PublicationRecord_getPublishedData(sig->publication, &pubData));
	/* Get published hash value. */
	CATCH_KSI_ERR(KSI_PublicationData_getImprint(pubData, &publishedHash));

	if (!KSI_DataHash_equals(rootHash, publishedHash)) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_LOG_info(sig->ctx, "Published hash and calendar hash chain root hash mismatch.");
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Calendar root hash :", rootHash);
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Published hash     :", publishedHash);
		packVerificationErrorResult(result, FAIL, INT_9);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:
	KSI_DataHash_free(rootHash);

	return res;
}

int KSI_VerificationRule_SignaturePublicationRecordPublicationTime(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationData *pubData = NULL;
	KSI_Integer *calPubTime = NULL;
	KSI_Integer *sigPubTime = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	if (sig->publication == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verifying calendar chain publication time consistency.");

	/* Get the publication time from calendar hash chain. */
	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &calPubTime));
	/* Get publication data from publication record */
	CATCH_KSI_ERR(KSI_PublicationRecord_getPublishedData(sig->publication, &pubData));

	CATCH_KSI_ERR(KSI_PublicationData_getTime(pubData, &sigPubTime));

	if (!KSI_Integer_equals(calPubTime, sigPubTime)){
		res = KSI_VERIFICATION_FAILURE;
		KSI_LOG_info(ctx, "Calendar hash chain publication time mismatch.");
		KSI_LOG_debug(ctx, "Calendar hash chain publication time: %i.", KSI_Integer_getUInt64(calPubTime));
		KSI_LOG_debug(ctx, "Published publication time:           %i.", KSI_Integer_getUInt64(sigPubTime));
		packVerificationErrorResult(result, FAIL, INT_7);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_DocumentHashVerification(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	if (!sig->verificationResult.verifyDocumentHash) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(sig->ctx, "Verifying document hash.");
	KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Verifying document hash", sig->verificationResult.documentHash);

	if (sig->rfc3161 != NULL) {
		KSI_LOG_info(sig->ctx, "Document hash is compared with RFC 3161 input hash.");
		CATCH_KSI_ERR(KSI_RFC3161_getInputHash(sig->rfc3161, &hsh));
	} else {
		CATCH_KSI_ERR(KSI_Signature_getDocumentHash(sig, &hsh));
	}

	if (!KSI_DataHash_equals(hsh, sig->verificationResult.documentHash)) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_LOG_info(sig->ctx, "Wrong document.");
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Document hash :", sig->verificationResult.documentHash);
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Signed hash   :", hsh);
		packVerificationErrorResult(result, FAIL, GEN_1);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:
	KSI_nofree(hsh);

	return res;
}

int KSI_VerificationRule_SignatureDoesNotContainPublication(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	if (info->sig->publication != NULL) {
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;


	/* TODO...*/



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_SignaturePublicationRecordExistence(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	if (info->sig->publication == NULL) {
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_DataHash *extRootHash = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	if (sig->calendarChain == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime));

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, pubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_aggregate(sig->calendarChain, &rootHash));

	CATCH_KSI_ERR(KSI_CalendarHashChain_aggregate(extCalHashChain, &extRootHash));

	if (!KSI_DataHash_equals(rootHash, extRootHash)) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_LOG_info(sig->ctx, "Calendar hash chain root hash and extehded calendar hash chain root hash mismatch.");
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Calendar root hash     :", rootHash);
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Ext calendar root hash :", extRootHash);
		packVerificationErrorResult(result, FAIL, CAL_1);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:
	KSI_DataHash_free(rootHash);
	KSI_DataHash_free(extRootHash);

	return res;
}

int KSI_VerificationRule_CalendarHashChainDoesNotExist(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	if (info->sig->calendarChain != NULL) {
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int getExtendedCalendarHashChain(VerificationContext *info, KSI_Integer *pubTime, KSI_CalendarHashChain **extCalHashChain) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (info == NULL || info->ctx == NULL || info->sig == NULL || extCalHashChain == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	/* Check if signature has been already extended */
	if (info->extendedSig == NULL) {
		/* Extend the signature to the publication time as attached calendar chain, or to head if time is NULL */
		res = KSI_Signature_extendTo(sig, ctx, pubTime, &tmp);
		if (res != KSI_OK) {
			goto cleanup;
		}
		if (tmp == NULL) {
			res = KSI_UNKNOWN_ERROR;
			goto cleanup;
		}
		info->extendedSig = tmp;
		tmp = NULL;
	}
	*extCalHashChain = info->extendedSig->calendarChain;

	res = KSI_OK;

cleanup:
	KSI_Signature_free(tmp);

	return res;
}

int KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_DataHash *calInputHash = NULL;
	KSI_DataHash *aggrOutputHash = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	if (sig->calendarChain != NULL) {
		CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime));
	}

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, pubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getInputHash(extCalHashChain, &calInputHash));

	CATCH_KSI_ERR(aggrHashChain_getOutputHash(ctx, sig, (int)info->docAggrLevel, &aggrOutputHash));

	if (!KSI_DataHash_equals(aggrOutputHash, calInputHash)) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_LOG_info(ctx, "Calendar hash chain's input hash does not match with aggregation root hash.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Input hash from aggregation :", aggrOutputHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected input hash         :", calInputHash);
		packVerificationErrorResult(result, FAIL, CAL_2);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(aggrOutputHash);

	return res;
}

int KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	time_t calculatedAggrTime;
	KSI_AggregationHashChain *aggregationChain = NULL;
	KSI_Integer *pubTime = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->sig;

	if (sig->calendarChain != NULL) {
		CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime));
	}

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, pubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_calculateAggregationTime(extCalHashChain, &calculatedAggrTime));
	/* Take the first aggregation hash chain, as all of the chain should have the same value for "aggregation time". */
	CATCH_KSI_ERR(KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggregationChain));

	if (!KSI_Integer_equalsUInt(aggregationChain->aggregationTime, (KSI_uint64_t) calculatedAggrTime)) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_LOG_info(ctx, "Invalid extended signature calendar calendar chain aggregation time.");
		KSI_LOG_debug(ctx, "Calendar hash chain aggregation time: %i.", calculatedAggrTime);
		KSI_LOG_debug(ctx, "Aggregation time:                     %i.", KSI_Integer_getUInt64(aggregationChain->aggregationTime));
		packVerificationErrorResult(result, FAIL, CAL_3);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarHashChainExistence(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	if (info->sig->calendarChain == NULL) {
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

