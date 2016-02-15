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
#include "internal.h"
#include "verification_impl.h"
#include "signature_impl.h"
#include "hashchain.h"

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

/*TODO: check chain index verification*/
static int rfc3161_verify(const KSI_Signature *sig) {
	int res;
	KSI_CTX *ctx = NULL;
	KSI_RFC3161 *rfc3161 = NULL;
	KSI_AggregationHashChainList *aggreChain = NULL;
	KSI_AggregationHashChain *firstChain = NULL;
	unsigned i;


	if (sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = sig->ctx;
	KSI_ERR_clearErrors(ctx);

	rfc3161 = sig->rfc3161;
	if (rfc3161 == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	aggreChain = sig->aggregationChainList;
	if (aggreChain == NULL) {
		KSI_LOG_debug(ctx, "Aggregation chain is missing.");
		goto cleanup;
	}

	res = KSI_AggregationHashChainList_elementAt(aggreChain, 0, &firstChain);
	if (res != KSI_OK) {
		goto cleanup;
	}

	if (KSI_Integer_compare(firstChain->aggregationTime, rfc3161->aggregationTime) != 0) {
		KSI_LOG_debug(ctx, "Aggregation chain and RFC 3161 aggregation time mismatch.");
		KSI_LOG_debug(ctx, "Signatures aggregation time: %i.", KSI_Integer_getUInt64(firstChain->aggregationTime));
		KSI_LOG_debug(ctx, "RFC 3161 aggregation time:   %i.", KSI_Integer_getUInt64(rfc3161->aggregationTime));
		goto cleanup;
	}

	if (KSI_IntegerList_length(firstChain->chainIndex) != KSI_IntegerList_length(rfc3161->chainIndex)) {
		KSI_LOG_debug(ctx, "Aggregation chain and RFC 3161 chain index mismatch.", KSI_IntegerList_length(firstChain->chainIndex));
		KSI_LOG_debug(ctx, "Signatures chain index length: %i.", KSI_IntegerList_length(firstChain->chainIndex));
		KSI_LOG_debug(ctx, "RFC 3161 chain index length:   %i.", KSI_IntegerList_length(rfc3161->chainIndex));
	}else {
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
				KSI_LOG_debug(ctx, "Aggregation chain and RFC 3161 chain index mismatch.", KSI_IntegerList_length(firstChain->chainIndex));
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

int KSI_VerificationRule_AggregationChainInputHashVerification(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *rfc3161_outputHash = NULL;
	KSI_AggregationHashChain* firstChain = NULL;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	KSI_LOG_info(sig->ctx, "Verifying aggregation hash input hash.");

	if (sig->rfc3161 != NULL) {
		res = rfc3161_verify(sig);
		if (res != KSI_OK){
			KSI_pushError(sig->ctx, res, "RFC 3161 does not belong to this aggregation hash chain.");
			packVerificationErrorResult(result, FAIL, GEN_2);
			goto cleanup;
		}

		KSI_LOG_info(sig->ctx, "Using input hash calculated from RFC 3161 for aggregation.");
		res = rfc3161_getOutputHash(sig, &rfc3161_outputHash);
		if (res != KSI_OK) {
			packVerificationErrorResult(result, FAIL, GEN_2);
			goto cleanup;
		}

		if (sig->aggregationChainList == NULL) {
			KSI_pushError(sig->ctx, res = KSI_INVALID_SIGNATURE, "Aggregation chain is missing.");
			packVerificationErrorResult(result, FAIL, GEN_2);
			goto cleanup;
		}

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &firstChain);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			packVerificationErrorResult(result, FAIL, GEN_2);
			goto cleanup;
		}

		if (rfc3161_outputHash != NULL){
			if (!KSI_DataHash_equals(rfc3161_outputHash, firstChain->inputHash)) {
				KSI_pushError(sig->ctx, res, "Aggregation hash chain's input hash does not match with RFC 3161 input hash.");
				KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Input hash from RFC 3161 :", rfc3161_outputHash);
				KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Expected input hash      :", firstChain->inputHash);
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


int KSI_VerificationRule_AggregationHashChainConsistency(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	const KSI_AggregationHashChain *prevChain = NULL;
	KSI_DataHash *hsh = NULL;
	int successCount = 0;
	int level = 0;
	size_t i;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	/* The aggregation level might not be 0 in case of local aggregation. */
	if (sig->verificationResult.docAggrLevel > 0xff) {
		KSI_pushError(sig->ctx, res = KSI_INVALID_FORMAT, "Aggregation level can't be larger than 0xff.");
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	level = (int)sig->verificationResult.docAggrLevel;

	KSI_LOG_info(sig->ctx, "Verifying aggregation hash chain consistency.");

	/* Aggregate all the aggregation chains. */
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		const KSI_AggregationHashChain* aggregationChain = NULL;
		KSI_DataHash *tmpHash = NULL;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain);
		if (res != KSI_OK) {
			KSI_pushError(sig->ctx, res, NULL);
			packVerificationErrorResult(result, NA, GEN_2);
			goto cleanup;

		}
		if (aggregationChain == NULL) break;

		if (prevChain != NULL) {
			/* Verify chain index length. */
			if (KSI_IntegerList_length(prevChain->chainIndex) != KSI_IntegerList_length(aggregationChain->chainIndex) + 1) {
				KSI_LOG_debug(sig->ctx, "Unexpected chain index length in aggregation chain.");
				packVerificationErrorResult(result, NA, GEN_2);
				goto cleanup;
			} else {
				unsigned j;
				for (j = 0; j < KSI_IntegerList_length(aggregationChain->chainIndex); j++) {
					KSI_Integer *chainIndex1 = NULL;
					KSI_Integer *chainIndex2 = NULL;

					res = KSI_IntegerList_elementAt(prevChain->chainIndex, j, &chainIndex1);
					if (res != KSI_OK) {
						packVerificationErrorResult(result, NA, GEN_2);
						goto cleanup;
					}

					res = KSI_IntegerList_elementAt(aggregationChain->chainIndex, j, &chainIndex2);
					if (res != KSI_OK) {
						packVerificationErrorResult(result, NA, GEN_2);
						goto cleanup;
					}

					if (!KSI_Integer_equals(chainIndex1, chainIndex2)) {
						KSI_LOG_debug(sig->ctx, "Aggregation chain chain index is not continuation of previous chain index.");
						packVerificationErrorResult(result, NA, GEN_2);
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

				packVerificationErrorResult(result, FAIL, INT_1);
				goto cleanup;
			}
		}

		res = KSI_HashChain_aggregate(aggregationChain->ctx, aggregationChain->chain, aggregationChain->inputHash,
									  level, (int)KSI_Integer_getUInt64(aggregationChain->aggrHashId), &level, &tmpHash);
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
		KSI_LOG_debug(sig->ctx, "Aggregation hash chain calculation failed.");
		packVerificationErrorResult(result, FAIL, INT_1);
		goto cleanup;
	}

	sig->verificationResult.aggregationHash = hsh;
	hsh = NULL;


	res = KSI_OK;

cleanup:
	KSI_DataHash_free(hsh);

	return res;
}

int KSI_VerificationRule_AggregationHashChainTimeConsistency(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	const KSI_AggregationHashChain *prevChain = NULL;
	size_t i;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		packVerificationErrorResult(result, NA, GEN_2);
		goto cleanup;
	}

	KSI_LOG_info(sig->ctx, "Verifying aggregation hash chain internal time consistency.");

	/* Aggregate all the aggregation chains. */
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		const KSI_AggregationHashChain* aggregationChain = NULL;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain);
		if (res != KSI_OK) {
			packVerificationErrorResult(result, NA, GEN_2);
			goto cleanup;
		}

		if (aggregationChain == NULL) break;

		if (prevChain != NULL) {
			/* Verify aggregation time. */
			if (!KSI_Integer_equals(aggregationChain->aggregationTime, prevChain->aggregationTime)) {
				KSI_LOG_debug(sig->ctx, "Aggregation hash chain's from different aggregation rounds.");
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

int KSI_VerificationRule_CalendarHashChainInputHashVerification(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarHashChainAggregationTime(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarHashChainRegistrationTime(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_SignaturePublicationRecordPublicationHash(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_SignaturePublicationRecordPublicationTime(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_DocumentHashVerification(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_SignatureDoesNotContainPublication(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_SignaturePublicationRecordExistence(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarHashChainDoesNotExist(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarHashChainExistence(KSI_Signature *sig, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}



	res = KSI_OK;

cleanup:

	return res;
}

