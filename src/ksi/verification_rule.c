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
#include "publicationsfile_impl.h"
#include "tlv.h"
#include "pkitruststore.h"
#include "net.h"
#include "ctx_impl.h"

#define VERIFICATION_RESULT(vrc, vec) \
	result->resultCode = vrc;         \
	result->errorCode  = vec;         \
	result->ruleName   = __FUNCTION__;\


#define CATCH_KSI_ERR(func) \
	res = func; \
	if (res != KSI_OK) { \
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2); \
		goto cleanup; \
	}


static int rfc3161_preSufHasher(KSI_CTX *ctx, const KSI_OctetString *prefix, const KSI_DataHash *hsh, const KSI_OctetString *suffix, int hsh_id, KSI_DataHash **out);
static int rfc3161_verify(KSI_CTX *ctx, const KSI_Signature *sig);
static int getRfc3161OutputHash(const KSI_Signature *sig, KSI_DataHash **outputHash);
static int getAggrHashChainOutputHash(KSI_CTX *ctx, KSI_Signature *sig, int level, KSI_DataHash **outputHash);
static int getExtendedCalendarHashChain(VerificationContext *info, KSI_Integer *pubTime, KSI_CalendarHashChain **extCalHashChain);
static int initPublicationsFile(VerificationContext *verCtx);
static int initExtendedSignature(VerificationContext *verCtx, KSI_Integer *endTime);
static int initAggregationOutputHash(VerificationContext *verCtx);


static int rfc3161_preSufHasher(KSI_CTX *ctx, const KSI_OctetString *prefix, const KSI_DataHash *hsh, const KSI_OctetString *suffix, int hsh_id, KSI_DataHash **out) {
	int res = KSI_UNKNOWN_ERROR;
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
	int res = KSI_UNKNOWN_ERROR;
	KSI_RFC3161 *rfc3161 = NULL;
	KSI_AggregationHashChain *firstChain = NULL;
	unsigned i;

	if (ctx == NULL || sig == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
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
		KSI_pushError(ctx, res, NULL);
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
				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}

			res = KSI_IntegerList_elementAt(rfc3161->chainIndex, i, &ch2);
			if (res != KSI_OK) {
				KSI_pushError(ctx, res, NULL);
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

static int getRfc3161OutputHash(const KSI_Signature *sig, KSI_DataHash **outputHash) {
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
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Signature_getHashAlgorithm((KSI_Signature *)sig, &algo_id);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_create(ctx, imprint, imprint_len, algo_id, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify aggregation hash input hash.");

	if (sig->rfc3161 != NULL) {
		/* Check of RFC 3161 does belong to this aggregation hash chain.*/
		CATCH_KSI_ERR(rfc3161_verify(ctx, sig));

		KSI_LOG_info(ctx, "Using input hash calculated from RFC 3161 for aggregation.");
		CATCH_KSI_ERR(getRfc3161OutputHash(sig, &rfc3161_outputHash));

		if (sig->aggregationChainList == NULL) {
			KSI_LOG_info(ctx, "Aggregation chain is missing.");
			VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_GEN_2);
			res = KSI_INVALID_SIGNATURE;
			goto cleanup;
		}

		CATCH_KSI_ERR(KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &firstChain));

		if (rfc3161_outputHash != NULL){
			if (!KSI_DataHash_equals(rfc3161_outputHash, firstChain->inputHash)) {
				KSI_pushError(ctx, res, "Aggregation hash chain's input hash does not match with RFC 3161 input hash.");
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Input hash from RFC 3161 :", rfc3161_outputHash);
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected input hash      :", firstChain->inputHash);
				VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_INT_1);
				res = KSI_OK;
				goto cleanup;
			}
		}
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify aggregation hash chain consistency.");

	/* The aggregation level might not be 0 in case of local aggregation. */
	if (info->userData.docAggrLevel > 0xff) {
		/* Aggregation level can't be larger than 0xff */
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}
	level = (int)info->userData.docAggrLevel;

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
				VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
				res = KSI_INVALID_FORMAT;
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
						VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
						res = KSI_INVALID_FORMAT;
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
				VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_INT_1);
				res = KSI_OK;
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
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_INT_1);
		res = KSI_OK;
		goto cleanup;
	}

	if (info->tempData.aggregationOutputHash != NULL) {
		KSI_DataHash_free(info->tempData.aggregationOutputHash);
	}
	info->tempData.aggregationOutputHash = hsh;
	hsh = NULL;

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify aggregation hash chain internal time consistency.");

	/* Aggregate all the aggregation chains. */
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		const KSI_AggregationHashChain* aggregationChain = NULL;

		CATCH_KSI_ERR(KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain));

		if (aggregationChain == NULL) break;

		if (prevChain != NULL) {
			/* Verify aggregation time. */
			if (!KSI_Integer_equals(aggregationChain->aggregationTime, prevChain->aggregationTime)) {
				KSI_LOG_debug(ctx, "Aggregation hash chain's from different aggregation rounds.");
				VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_INT_2);
				res = KSI_OK;
				goto cleanup;
			}
		}

		prevChain = aggregationChain;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

static int getAggrHashChainOutputHash(KSI_CTX *ctx, KSI_Signature *sig, int level, KSI_DataHash **outputHash) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	size_t i;

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
		KSI_DataHash *tmp = NULL;

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

		if (hsh != NULL) {
			KSI_DataHash_free(hsh);
		}
		hsh = tmp;
	}

	*outputHash = hsh;
	hsh = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(hsh);

	return res;
}

static int initAggregationOutputHash(VerificationContext *verCtx) {
	int res = KSI_UNKNOWN_ERROR;

	if (verCtx == NULL || verCtx->ctx == NULL || verCtx->userData.sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (verCtx->tempData.aggregationOutputHash == NULL) {
		getAggrHashChainOutputHash(verCtx->ctx, verCtx->userData.sig, (int)verCtx->userData.docAggrLevel,
									&verCtx->tempData.aggregationOutputHash);
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarHashChainInputHashVerification(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *calInputHash = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify calendar hash chain input hash consistency");

	if (sig->calendarChain == NULL) {
		KSI_LOG_info(ctx, "Signature is missing calendar hash chain");
		VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
		res = KSI_OK;
		goto cleanup;
	}

	CATCH_KSI_ERR(KSI_CalendarHashChain_getInputHash(sig->calendarChain, &calInputHash));

	CATCH_KSI_ERR(initAggregationOutputHash(info));

	if (info->tempData.aggregationOutputHash == NULL  || calInputHash == NULL) {
		KSI_LOG_info(ctx, "Missing aggregation output hash or calendar input hash");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (!KSI_DataHash_equals(info->tempData.aggregationOutputHash, calInputHash)) {
		KSI_LOG_info(ctx, "Calendar hash chain's input hash does not match with aggregation root hash.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Input hash from aggregation :", info->tempData.aggregationOutputHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected input hash         :", calInputHash);
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_INT_3);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify calendar aggregation time consistency");

	if (sig->calendarChain == NULL) {
		KSI_LOG_info(ctx, "Signature is missing calendar hash chain");
		VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
		res = KSI_OK;
		goto cleanup;
	}

	/* Take the first aggregation hash chain, as all of the chain should have the same value for "aggregation time". */
	CATCH_KSI_ERR(KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggregationChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &calAggrTime));

	if (!KSI_Integer_equals(calAggrTime, aggregationChain->aggregationTime)) {
		KSI_LOG_info(ctx, "Aggregation time in calendar chain and aggregation chain differ.");
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_INT_4);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify calendar hash chain time consistency");

	if (sig->calendarChain == NULL) {
		KSI_LOG_info(ctx, "Signature is missing calendar hash chain");
		VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
		res = KSI_OK;
		goto cleanup;
	}

	CATCH_KSI_ERR(KSI_CalendarHashChain_calculateAggregationTime(sig->calendarChain, &calculatedAggrTime));
	CATCH_KSI_ERR(KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &calendarAggrTime));

	if (!KSI_Integer_equalsUInt(calendarAggrTime, (KSI_uint64_t) calculatedAggrTime)) {
		KSI_LOG_info(ctx, "Calendar chain internally inconsistent.");
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_INT_5);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify calendar authentication record.");

	if (sig->calendarAuthRec == NULL) {
		KSI_LOG_info(ctx, "Signature does not contain calendar authentication record.");
		VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
		res = KSI_OK;
		goto cleanup;
	}

	/* Calculate the root hash value. */
	CATCH_KSI_ERR(KSI_CalendarHashChain_aggregate(sig->calendarChain, &rootHash));
	/* Get publication data. */
	CATCH_KSI_ERR(KSI_CalendarAuthRec_getPublishedData(sig->calendarAuthRec, &pubData));
	/* Get published hash value. */
	CATCH_KSI_ERR(KSI_PublicationData_getImprint(pubData, &pubHash));

	if (!KSI_DataHash_equals(rootHash, pubHash)) {
		KSI_LOG_info(ctx, "Calendar chain and authentication record hash mismatch.");
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_INT_8);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify calendar authentication record publication time.");

	if (sig->calendarAuthRec == NULL) {
		KSI_LOG_info(ctx, "Signature does not contain calendar authentication record.");
		VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
		res = KSI_OK;
		goto cleanup;
	}

	/* Get the publication time from calendar hash chain. */
	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &calPubTime));
	/* Get publication data. */
	CATCH_KSI_ERR(KSI_CalendarAuthRec_getPublishedData(sig->calendarAuthRec, &pubData));
	/* Get publication time. */
	CATCH_KSI_ERR(KSI_PublicationData_getTime(pubData, &pubTime));

	if (!KSI_Integer_equals(calPubTime, pubTime)) {
		KSI_LOG_info(ctx, "Calendar chain and authentication record time mismatch.");
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_INT_6);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify calendar chain publication hash consistency.");

	if (sig->publication == NULL) {
		KSI_LOG_info(ctx, "Signature does not contain publication record.");
		VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
		res = KSI_OK;
		goto cleanup;
	}

	/* Calculate calendar aggregation root hash value. */
	CATCH_KSI_ERR(KSI_CalendarHashChain_aggregate(sig->calendarChain, &rootHash));
	/* Get publication data from publication record */
	CATCH_KSI_ERR(KSI_PublicationRecord_getPublishedData(sig->publication, &pubData));
	/* Get published hash value. */
	CATCH_KSI_ERR(KSI_PublicationData_getImprint(pubData, &publishedHash));

	if (!KSI_DataHash_equals(rootHash, publishedHash)) {
		KSI_LOG_info(ctx, "Published hash and calendar hash chain root hash mismatch.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calendar root hash :", rootHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Published hash     :", publishedHash);
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_INT_9);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify calendar chain publication time consistency.");

	if (sig->publication == NULL) {
		KSI_LOG_info(ctx, "Signature does not contain publication record.");
		VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
		res = KSI_OK;
		goto cleanup;
	}

	/* Get the publication time from calendar hash chain. */
	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &calPubTime));
	/* Get publication data from publication record */
	CATCH_KSI_ERR(KSI_PublicationRecord_getPublishedData(sig->publication, &pubData));
	/* Get publication time */
	CATCH_KSI_ERR(KSI_PublicationData_getTime(pubData, &sigPubTime));

	if (!KSI_Integer_equals(calPubTime, sigPubTime)){
		KSI_LOG_info(ctx, "Calendar hash chain publication time mismatch.");
		KSI_LOG_debug(ctx, "Calendar hash chain publication time: %i.", KSI_Integer_getUInt64(calPubTime));
		KSI_LOG_debug(ctx, "Published publication time:           %i.", KSI_Integer_getUInt64(sigPubTime));
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_INT_7);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	if (info->userData.documentHash == NULL) {
		KSI_LOG_info(ctx, "Document hash is not set");
		VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify document hash.");
	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Verifying document hash", info->userData.documentHash);

	if (sig->rfc3161 != NULL) {
		KSI_LOG_info(ctx, "Document hash is compared with RFC 3161 input hash.");
		CATCH_KSI_ERR(KSI_RFC3161_getInputHash(sig->rfc3161, &hsh));
	} else {
		CATCH_KSI_ERR(KSI_Signature_getDocumentHash(sig, &hsh));
	}

	if (!KSI_DataHash_equals(hsh, info->userData.documentHash)) {
		KSI_LOG_info(ctx, "Wrong document.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Document hash :", info->userData.documentHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Signed hash   :", hsh);
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_GEN_1);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying signature does not contain publication record.");

	if (info->userData.sig->publication != NULL) {
		KSI_LOG_info(info->ctx, "Signature contains publication record");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_HashChainLinkList *sigList = NULL;
	KSI_HashChainLinkList *extSigList = NULL;
	size_t sigListSize;
	size_t extSigListSize;
	size_t i;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify aggregation chain right link count and right link hashes");

	CATCH_KSI_ERR(KSI_CalendarHashChain_getHashChain(sig->calendarChain, &sigList));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime));

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, pubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getHashChain(extCalHashChain, &extSigList));


	sigListSize = KSI_HashChainLinkList_length(sigList);
	extSigListSize = KSI_HashChainLinkList_length(extSigList);

	if (sigListSize != extSigListSize) {
		KSI_LOG_info(ctx, "Extended signature aggregation chain links count does not match with initial signature aggregation chain links count.");
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_CAL_4);
		res = KSI_OK;
		goto cleanup;
	}

	for (i = 0; i < extSigListSize; i++) {
		KSI_HashChainLink *extLink = NULL;
		int isLeft;

		CATCH_KSI_ERR(KSI_HashChainLinkList_elementAt(extSigList, i, &extLink));

		CATCH_KSI_ERR(KSI_HashChainLink_getIsLeft(extLink, &isLeft));

		if (!isLeft) {
			KSI_HashChainLink *sigLink = NULL;
			KSI_DataHash *extLinkHash = NULL;
			KSI_DataHash *sigLinkHash = NULL;

			CATCH_KSI_ERR(KSI_HashChainLinkList_elementAt(sigList, i, &sigLink));

			CATCH_KSI_ERR(KSI_HashChainLink_getImprint(sigLink, &sigLinkHash));

			CATCH_KSI_ERR(KSI_HashChainLink_getImprint(extLink, &extLinkHash));

			if (!KSI_DataHash_equals(sigLinkHash, extLinkHash)) {
				KSI_LOG_info(ctx, "Extended signature contains different aggregation hash chain right link");
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Signature right link hash     :", sigLinkHash);
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Ext signature right link hash :", extLinkHash);
				VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_CAL_4);
				res = KSI_OK;
				goto cleanup;
			}
		}
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verify signature publication record existence");

	if (info->userData.sig->publication == NULL) {
		KSI_LOG_info(info->ctx, "Signature publication record is missing");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(info->ctx, "Verify extended signature calendar hash chain root hash");

	if (sig->calendarChain == NULL) {
		KSI_LOG_info(ctx, "Signature calendar hash chain is missing");
		VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
		res = KSI_OK;
		goto cleanup;
	}

	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime));

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, pubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_aggregate(sig->calendarChain, &rootHash));

	CATCH_KSI_ERR(KSI_CalendarHashChain_aggregate(extCalHashChain, &extRootHash));

	if (!KSI_DataHash_equals(rootHash, extRootHash)) {
		KSI_LOG_info(ctx, "Calendar hash chain root hash and extehded calendar hash chain root hash mismatch.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calendar root hash     :", rootHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Ext calendar root hash :", extRootHash);
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_CAL_1);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying calendar hash chain does not exist");

	if (info->userData.sig->calendarChain != NULL) {
		KSI_LOG_info(info->ctx, "Signature calendar hash chain is not missing");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

static int initExtendedSignature(VerificationContext *verCtx, KSI_Integer *endTime) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *startTime = NULL;
	KSI_ExtendReq *req = NULL;
	KSI_RequestHandle *handle = NULL;
	KSI_ExtendResp *resp = NULL;
	KSI_Integer *status = NULL;
	KSI_CalendarHashChain *calChain = NULL;
	KSI_Signature *tmp = NULL;

	if (verCtx == NULL || verCtx->ctx == NULL || verCtx->userData.sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = verCtx->ctx;
	sig = verCtx->userData.sig;

	/* Make a copy of the original signature */
	res = KSI_Signature_clone(sig, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Extract start time */
	res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &startTime);
	if (res != KSI_OK) goto cleanup;

	/* Clone the start time object */
	KSI_Integer_ref(startTime);

	res = KSI_createExtendRequest(ctx, startTime, endTime, &req);
	if (res != KSI_OK) goto cleanup;

	res = KSI_sendExtendRequest(ctx, req, &handle);
	if (res != KSI_OK) goto cleanup;

	res = KSI_RequestHandle_perform(handle);
	if (res != KSI_OK) {
		KSI_pushError(ctx,res, NULL);
		goto cleanup;
	}

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
		res = KSI_VERIFICATION_FAILURE;
		goto cleanup;
	}

	/* Extract the calendar hash chain */
	res = KSI_ExtendResp_getCalendarHashChain(resp, &calChain);
	if (res != KSI_OK) goto cleanup;

	/* Add the hash chain to the signature. */
	res = KSI_Signature_replaceCalendarChain(tmp, calChain);
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

	if (verCtx->tempData.extendedSig != NULL) {
		KSI_Signature_free(verCtx->tempData.extendedSig);
	}
	verCtx->tempData.extendedSig = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:
	KSI_Integer_free(startTime);
	KSI_ExtendReq_free(req);
	KSI_RequestHandle_free(handle);
	KSI_ExtendResp_free(resp);
	KSI_Signature_free(tmp);

	return res;
}

static int getExtendedCalendarHashChain(VerificationContext *info, KSI_Integer *pubTime, KSI_CalendarHashChain **chain) {
	int res = KSI_UNKNOWN_ERROR;

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL || chain == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

#ifdef SHOULD_WE_CHECK_FOR_PUBLICATION_TIME_Q
	/* Delete the extended signature if it is extended to a different publication time */
	if (info->tempData.extendedSig != NULL) {
		KSI_Integer *extSigPubTime = NULL;
		KSI_CalendarHashChain_getPublicationTime(info->tempData.extendedSig->calendarChain, &extSigPubTime);

		if (!KSI_Integer_equals(extSigPubTime, pubTime)) {
			KSI_Signature_free(info->tempData.extendedSig);
		}
	}
#endif

	/* Check if signature has been already extended */
	if (info->tempData.extendedSig == NULL) {
		/* Extend the signature to the publication time as attached calendar chain, or to head if time is NULL */
		res = initExtendedSignature(info, pubTime);
		if (res != KSI_OK) goto cleanup;
	}

	*chain = info->tempData.extendedSig->calendarChain;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_DataHash *calInputHash = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify extended signature calendar hash chain input hash");

	/* If the calendar chain is available, then take the publication from calendar chain. */
	/* Otherwice the extender will extend to head (pubTime == NULL) */
	if (sig->calendarChain != NULL) {
		CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime));
	}

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, pubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getInputHash(extCalHashChain, &calInputHash));

	CATCH_KSI_ERR(initAggregationOutputHash(info));

	if (!KSI_DataHash_equals(info->tempData.aggregationOutputHash, calInputHash)) {
		KSI_LOG_info(ctx, "Calendar hash chain's input hash does not match with aggregation root hash.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Input hash from aggregation :", info->tempData.aggregationOutputHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected input hash         :", calInputHash);
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_CAL_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify extended signature calendar hash chain aggregation time");

	/* If the calendar chain is available, then take the publication from calendar chain. */
	/* Otherwice the extender will extend to head (pubTime == NULL) */
	if (sig->calendarChain != NULL) {
		CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime));
	}

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, pubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_calculateAggregationTime(extCalHashChain, &calculatedAggrTime));
	/* Take the first aggregation hash chain, as all of the chain should have the same value for "aggregation time". */
	CATCH_KSI_ERR(KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggregationChain));

	if (!KSI_Integer_equalsUInt(aggregationChain->aggregationTime, (KSI_uint64_t) calculatedAggrTime)) {
		KSI_LOG_info(ctx, "Invalid extended signature calendar calendar chain aggregation time.");
		KSI_LOG_debug(ctx, "Calendar hash chain aggregation time: %i.", calculatedAggrTime);
		KSI_LOG_debug(ctx, "Signature aggregation time:           %i.", KSI_Integer_getUInt64(aggregationChain->aggregationTime));
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_CAL_3);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
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

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying calendar hash chain existence.");

	if (info->userData.sig->calendarChain == NULL) {
		KSI_LOG_info(info->ctx, "Signature calendar hash chain is missing");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordExistence(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying calendar authentication record existence.");

	if (info->userData.sig->calendarAuthRec == NULL) {
		KSI_LOG_info(info->ctx, "Calendar authentication record does not exist.");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordDoesNotExist(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying calendar authentication record does not exist.");

	if (info->userData.sig->calendarAuthRec != NULL) {
		KSI_LOG_info(info->ctx, "Calendar authentication record is not missing.");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

static int initPublicationsFile(VerificationContext *verCtx) {
	int res = KSI_UNKNOWN_ERROR;

	if (verCtx->tempData.publicationsFile == NULL) {
		if (verCtx->userData.userPublicationsFile != NULL) {
			verCtx->tempData.publicationsFile = verCtx->userData.userPublicationsFile;
		} else {
			bool verifyPubFile = (verCtx->ctx->publicationsFile == NULL);

			res = KSI_receivePublicationsFile(verCtx->ctx, &verCtx->tempData.publicationsFile);
			if (res != KSI_OK) goto cleanup;

			if (verifyPubFile == true) {
				res = KSI_verifyPublicationsFile(verCtx->ctx, verCtx->tempData.publicationsFile);
				if (res != KSI_OK) goto cleanup;
			}
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CertificateExistence(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_OctetString *certId = NULL;
	KSI_PKICertificate *cert = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify calendar authentication record certificate.");

	if (sig->calendarAuthRec == NULL) {
		KSI_LOG_info(info->ctx, "Calendar authentication record does not exist.");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	CATCH_KSI_ERR(KSI_PKISignedData_getCertId(sig->calendarAuthRec->signatureData, &certId));

	if (certId == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	CATCH_KSI_ERR(initPublicationsFile(info));

	CATCH_KSI_ERR(KSI_PublicationsFile_getPKICertificateById(info->tempData.publicationsFile, certId, &cert));

	if (cert == NULL) {
		KSI_LOG_info(ctx, "Certificate not found");
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_KEY_1);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_OctetString *certId = NULL;
	KSI_PKICertificate *cert = NULL;
	KSI_OctetString *signatureValue = NULL;
	const unsigned char *rawSignature = NULL;
	size_t rawSignature_len;
	unsigned char *rawData = NULL;
	size_t rawData_len;
	KSI_Utf8String *sigtype = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify calendar authentication record signature.");

	if (sig->calendarAuthRec == NULL) {
		KSI_LOG_info(info->ctx, "Calendar authentication record does not exist.");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	CATCH_KSI_ERR(KSI_PKISignedData_getCertId(sig->calendarAuthRec->signatureData, &certId));

	if (certId == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	CATCH_KSI_ERR(initPublicationsFile(info));

	CATCH_KSI_ERR(KSI_PublicationsFile_getPKICertificateById(info->tempData.publicationsFile, certId, &cert));

	if (cert == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	CATCH_KSI_ERR(KSI_PKISignedData_getSignatureValue(sig->calendarAuthRec->signatureData, &signatureValue));

	CATCH_KSI_ERR(KSI_OctetString_extract(signatureValue, &rawSignature, &rawSignature_len));

	CATCH_KSI_ERR(KSI_TLV_serialize(sig->calendarAuthRec->pubData->baseTlv, &rawData, &rawData_len));

	CATCH_KSI_ERR(KSI_PKISignedData_getSigType(sig->calendarAuthRec->signatureData, &sigtype));

	res = KSI_PKITruststore_verifyRawSignature(ctx, rawData, rawData_len, KSI_Utf8String_cstr(sigtype),
											   rawSignature, rawSignature_len, cert);
	if (res != KSI_OK) {
		KSI_LOG_info(ctx, "Failed to verify raw signature.");
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_KEY_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:
	KSI_free(rawData);

	return res;
}

int KSI_VerificationRule_PublicationsFileContainsSignaturePublication(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_PublicationRecord *pubRec = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify signature publication record");

	if (sig->publication == NULL) {
		KSI_LOG_info(ctx, "Signature publication record does not exist.");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	CATCH_KSI_ERR(initPublicationsFile(info));

	CATCH_KSI_ERR(KSI_PublicationsFile_findPublication(info->tempData.publicationsFile, sig->publication, &pubRec));
	if (pubRec == NULL) {
		KSI_LOG_info(ctx, "Publication file does not contain signature publication");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_PublicationsFileContainsPublication(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	time_t aggrTime;
	KSI_Integer *tempTime = NULL;
	KSI_PublicationRecord *pubRec = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify publication record existence");

	CATCH_KSI_ERR(KSI_CalendarHashChain_calculateAggregationTime(sig->calendarChain, &aggrTime));

	CATCH_KSI_ERR(KSI_Integer_new(ctx, aggrTime, &tempTime));

	CATCH_KSI_ERR(initPublicationsFile(info));

	CATCH_KSI_ERR(KSI_PublicationsFile_getNearestPublication(info->tempData.publicationsFile, tempTime, &pubRec));
	if (pubRec == NULL) {
		KSI_LOG_info(ctx, "Publication not found");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	KSI_Integer_free(tempTime);

	return res;
}

int KSI_VerificationRule_ExtendingPermittedVerification(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verify extending permitted");

	if (info->userData.extendingAllowed == false) {
		KSI_LOG_info(info->ctx, "Extending not allowed");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_DataHash *extCalRootHash = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_DataHash *pubDataHash = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify publication hash");

	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime));

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, pubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_aggregate(extCalHashChain, &extCalRootHash));

	CATCH_KSI_ERR(initPublicationsFile(info));

	CATCH_KSI_ERR(KSI_PublicationsFile_getPublicationDataByTime(info->tempData.publicationsFile, pubTime, &pubRec));

	if (pubRec == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	CATCH_KSI_ERR(KSI_PublicationData_getImprint(pubRec->publishedData, &pubDataHash));

	if (!KSI_DataHash_equals(extCalRootHash, pubDataHash)) {
		KSI_LOG_info(ctx, "Publications file publication hash does not match with extender response calendar root hash");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Publication hash   :", extCalRootHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calendar root hash :", pubDataHash);
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_PUB_1);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	KSI_DataHash_free(extCalRootHash);

	return res;
}

int KSI_VerificationRule_PublicationsFilePublicationTimeMatchesExtenderResponse(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *sigPubTime = NULL;
	KSI_Integer *pubDataPubTime = NULL;
	KSI_Integer *extPubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_PublicationRecord *pubRec = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify publication time");

	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &sigPubTime));

	CATCH_KSI_ERR(initPublicationsFile(info));

	CATCH_KSI_ERR(KSI_PublicationsFile_getPublicationDataByTime(info->tempData.publicationsFile, sigPubTime, &pubRec));

	if (pubRec == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	CATCH_KSI_ERR(KSI_PublicationData_getTime(pubRec->publishedData, &pubDataPubTime));

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, pubDataPubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(extCalHashChain, &extPubTime));

	if (!KSI_Integer_equals(pubDataPubTime, extPubTime)) {
		KSI_LOG_info(ctx, "Invalid extended signature calendar calendar chain aggregation time.");
		KSI_LOG_debug(ctx, "Publication file publication time:  %i.", KSI_Integer_getUInt64(pubDataPubTime));
		KSI_LOG_debug(ctx, "Extended response publication time: %i.", KSI_Integer_getUInt64(extPubTime));
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_PUB_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_DataHash *calInputHash = NULL;
	KSI_Integer *pubDataPubTime = NULL;
	KSI_Integer *sigPubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_PublicationRecord *pubRec = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify aggregation root hash");

	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &sigPubTime));

	CATCH_KSI_ERR(initPublicationsFile(info));

	CATCH_KSI_ERR(KSI_PublicationsFile_getPublicationDataByTime(info->tempData.publicationsFile, sigPubTime, &pubRec));

	CATCH_KSI_ERR(KSI_PublicationData_getTime(pubRec->publishedData, &pubDataPubTime));

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, pubDataPubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getInputHash(extCalHashChain, &calInputHash));

	CATCH_KSI_ERR(initAggregationOutputHash(info));

	if (!KSI_DataHash_equals(info->tempData.aggregationOutputHash, calInputHash)) {
		KSI_LOG_info(ctx, "Signature aggregation root hash does not match extender response input hash");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Aggr root hash      :", info->tempData.aggregationOutputHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calendar input hash :", calInputHash);
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_PUB_3);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_UserProvidedPublicationExistence(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying user publication existence");

	if (info->userData.userPublication == NULL ||
		info->userData.userPublication->time == NULL || info->userData.userPublication->imprint == NULL) {
		KSI_LOG_info(info->ctx, "User publication data not provided");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_UserProvidedPublicationVerification(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *sigPubTime = NULL;
	KSI_DataHash *sigPubHash = NULL;
	KSI_Integer *usrPubTime = NULL;
	KSI_DataHash *usrPubHash = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL || info->userData.userPublication == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify user publication");

	CATCH_KSI_ERR(KSI_PublicationData_getTime(sig->publication->publishedData, &sigPubTime));
	CATCH_KSI_ERR(KSI_PublicationData_getImprint(sig->publication->publishedData, &sigPubHash));

	CATCH_KSI_ERR(KSI_PublicationData_getTime(info->userData.userPublication, &usrPubTime));
	CATCH_KSI_ERR(KSI_PublicationData_getImprint(info->userData.userPublication, &usrPubHash));

	if (usrPubTime == NULL || usrPubHash == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	if (KSI_Integer_compare(sigPubTime, usrPubTime) != 0) {
		KSI_LOG_debug(ctx, "Publication time from publication record: %i", KSI_Integer_getUInt64(sigPubTime));
		KSI_LOG_debug(ctx, "Publication time from user publication  : %i", KSI_Integer_getUInt64(usrPubTime));
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	if (!KSI_DataHash_equals(sigPubHash, usrPubHash)) {
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Root hash from publication record:", sigPubHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Root hash from user publication  :", usrPubHash);
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		/* Publications with same time but different root hash must be reported as a crypto error! */
		res = KSI_CRYPTO_FAILURE;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}


int KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *sigPubTime = NULL;
	KSI_Integer *usrPubDataTime = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL || info->userData.userPublication == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify that signature is created before user provided publication");

	CATCH_KSI_ERR(KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &sigPubTime));

	CATCH_KSI_ERR(KSI_PublicationData_getTime(info->userData.userPublication, &usrPubDataTime));

	if (usrPubDataTime == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	if (KSI_Integer_compare(sigPubTime, usrPubDataTime) != -1) {
		KSI_LOG_debug(ctx, "Publication time from sig pub data : %i", KSI_Integer_getUInt64(sigPubTime));
		KSI_LOG_debug(ctx, "Publication time from user pub data: %i", KSI_Integer_getUInt64(usrPubDataTime));
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *usrPubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_DataHash *extRootHash = NULL;
	KSI_DataHash *usrPubDataHash = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL || info->userData.userPublication == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify user publication hash with extender response");

	CATCH_KSI_ERR(KSI_PublicationData_getTime(info->userData.userPublication, &usrPubTime));

	if (usrPubTime == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, usrPubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_aggregate(extCalHashChain, &extRootHash));

	CATCH_KSI_ERR(KSI_PublicationData_getImprint(info->userData.userPublication, &usrPubDataHash));

	if (!KSI_DataHash_equals(extRootHash, usrPubDataHash)) {
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Root hash extender response     :", extRootHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Root hash from user publication :", usrPubDataHash);
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_PUB_1);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:
	KSI_DataHash_free(extRootHash);

	return res;
}

int KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *usrPubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_Integer *extPubTime = NULL;
	KSI_Integer *signingTime = NULL;
	KSI_Integer *extAggrTime = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify user publication time with extender response");

	CATCH_KSI_ERR(KSI_PublicationData_getTime(info->userData.userPublication, &usrPubTime));

	if (usrPubTime == NULL) {
		KSI_LOG_info(ctx, "Missing publication time in user publication data");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, usrPubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getPublicationTime(extCalHashChain, &extPubTime));

	if (!KSI_Integer_equals(usrPubTime, extPubTime)) {
		KSI_LOG_info(ctx, "User provided publication time does not match extender response time");
		KSI_LOG_debug(ctx, "Publication time from extender response: %i", KSI_Integer_getUInt64(extPubTime));
		KSI_LOG_debug(ctx, "Publication time from user pub data    : %i", KSI_Integer_getUInt64(usrPubTime));
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_PUB_2);
		res = KSI_OK;
		goto cleanup;
	}

	CATCH_KSI_ERR(KSI_Signature_getSigningTime(sig, &signingTime));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getAggregationTime(extCalHashChain, &extAggrTime));

	if (!KSI_Integer_equals(signingTime, extAggrTime)) {
		KSI_LOG_info(ctx, "Signature aggregation hash chain aggregation time does not math with extender aggregation time");
		KSI_LOG_debug(ctx, "Signing time: %i", KSI_Integer_getUInt64(signingTime));
		KSI_LOG_debug(ctx, "Extender aggregation time: %i", KSI_Integer_getUInt64(extAggrTime));
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_PUB_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash(VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *usrPubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_DataHash *calInputHash = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->userData.sig == NULL) {
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->userData.sig;

	KSI_LOG_info(ctx, "Verify signature aggregation root hash with extender response input hash");

	CATCH_KSI_ERR(KSI_PublicationData_getTime(info->userData.userPublication, &usrPubTime));

	if (usrPubTime == NULL) {
		KSI_LOG_info(ctx, "Missing publication time in user publication data");
		VERIFICATION_RESULT(VER_RES_NA, VER_ERR_GEN_2);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	CATCH_KSI_ERR(getExtendedCalendarHashChain(info, usrPubTime, &extCalHashChain));

	CATCH_KSI_ERR(KSI_CalendarHashChain_getInputHash(extCalHashChain, &calInputHash));

	CATCH_KSI_ERR(initAggregationOutputHash(info));

	if (!KSI_DataHash_equals(info->tempData.aggregationOutputHash, calInputHash)) {
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Signature aggregation root hash :", info->tempData.aggregationOutputHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Extender calendar input hash    :", calInputHash);
		VERIFICATION_RESULT(VER_RES_FAIL, VER_ERR_PUB_3);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(VER_RES_OK, VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

