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
#include "verification_impl.h"
#include "signature_impl.h"
#include "hashchain.h"
#include "publicationsfile_impl.h"
#include "tlv.h"
#include "pkitruststore.h"
#include "net.h"
#include "ctx_impl.h"
#include "verification.h"
#include "impl/meta_data_element_impl.h"

#define VERIFICATION_RESULT(vrc, vec) \
	result->resultCode = vrc;         \
	result->errorCode  = vec;         \
	result->ruleName   = __FUNCTION__;\

static int rfc3161_preSufHasher(KSI_CTX *ctx, const KSI_OctetString *prefix, const KSI_DataHash *hsh, const KSI_OctetString *suffix, int hsh_id, KSI_DataHash **out);
static int rfc3161_verify(KSI_CTX *ctx, const KSI_Signature *sig);
static int getRfc3161OutputHash(const KSI_Signature *sig, KSI_DataHash **outputHash);
static int getExtendedCalendarHashChain(KSI_VerificationContext *info, KSI_Integer *pubTime, KSI_CalendarHashChain **extCalHashChain);
static int initPublicationsFile(KSI_VerificationContext *info);
static int initAggregationOutputHash(KSI_VerificationContext *info);


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
		KSI_LOG_info(ctx, "Aggregation hash chain is missing.");
		KSI_pushError(ctx, res = KSI_INVALID_SIGNATURE, "Aggregation hash chain is missing.");
		goto cleanup;
	}

	res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &firstChain);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (KSI_Integer_compare(firstChain->aggregationTime, rfc3161->aggregationTime) != 0) {
		KSI_LOG_info(ctx, "Aggregation hash chain and RFC 3161 aggregation time mismatch.");
		KSI_LOG_debug(ctx, "Signatures aggregation time: %i.", KSI_Integer_getUInt64(firstChain->aggregationTime));
		KSI_LOG_debug(ctx, "RFC 3161 aggregation time:   %i.", KSI_Integer_getUInt64(rfc3161->aggregationTime));
		KSI_pushError(ctx, res = KSI_VERIFICATION_FAILURE, "Aggregation hash chain and RFC 3161 aggregation time mismatch.");
		goto cleanup;
	}

	if (KSI_IntegerList_length(firstChain->chainIndex) != KSI_IntegerList_length(rfc3161->chainIndex)) {
		KSI_LOG_info(ctx, "Aggregation hash chain and RFC 3161 chain index mismatch.", KSI_IntegerList_length(firstChain->chainIndex));
		KSI_LOG_debug(ctx, "Signatures chain index length: %i.", KSI_IntegerList_length(firstChain->chainIndex));
		KSI_LOG_debug(ctx, "RFC 3161 chain index length:   %i.", KSI_IntegerList_length(rfc3161->chainIndex));
		KSI_pushError(ctx, res = KSI_VERIFICATION_FAILURE, "Aggregation hash chain and RFC 3161 aggregation index mismatch.");
		goto cleanup;
	}

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
			KSI_LOG_debug(ctx, "Aggregation hash chain and RFC 3161 chain index mismatch.");
			KSI_pushError(ctx, res = KSI_VERIFICATION_FAILURE, "Aggregation hash chain and RFC 3161 aggregation index mismatch.");
			goto cleanup;
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
		KSI_pushError(ctx, res = KSI_UNAVAILABLE_HASH_ALGORITHM, "Hash algorithm can't be larger than 0xff.");
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

int KSI_VerificationRule_AggregationChainInputHashVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *rfc3161_outputHash = NULL;
	KSI_AggregationHashChain* firstChain = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify aggregation hash chain input hash.");

	if (sig->rfc3161 != NULL) {
		/* Check of RFC 3161 does belong to this aggregation hash chain.*/
		res = rfc3161_verify(ctx, sig);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		KSI_LOG_info(ctx, "Using input hash calculated from RFC 3161 for aggregation.");
		res = getRfc3161OutputHash(sig, &rfc3161_outputHash);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (sig->aggregationChainList == NULL) {
			KSI_LOG_info(ctx, "Aggregation hash chain is missing.");
			result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
			VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res = KSI_INVALID_SIGNATURE, "Aggregation hash chain is missing.");
			goto cleanup;
		}

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &firstChain);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (rfc3161_outputHash != NULL){
			if (!KSI_DataHash_equals(rfc3161_outputHash, firstChain->inputHash)) {
				KSI_pushError(ctx, res, "Aggregation hash chain's input hash does not match with RFC 3161 input hash.");
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Input hash from RFC 3161 :", rfc3161_outputHash);
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected input hash      :", firstChain->inputHash);
				result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
				VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_1);
				res = KSI_OK;
				goto cleanup;
			}
		}
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:
	KSI_DataHash_free(rfc3161_outputHash);

	return res;
}

static int metaDataPadding_verify(KSI_CTX *ctx, KSI_TlvElement *el) {
	int res = KSI_UNKNOWN_ERROR;

	if (ctx == NULL || el == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	/* Check that the tag value corresponds to metadata padding. */
	if (el->ftlv.tag != 0x1E) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Metadata padding not the first element in the metadata record.");
		goto cleanup;
	}

	/* Check that the metadata padding is encoded in TLV8. */
	if (el->ptr[0] & KSI_TLV_MASK_TLV16) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Metadata padding not encoded as TLV8.");
		goto cleanup;
	}

	/* Check that the metadata padding has N and F flags set. */
	if (el->ftlv.is_nc == 0 || el->ftlv.is_fwd == 0) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Metadata padding does not have N and F flags set.");
		goto cleanup;
	}

	/* Check that the metadata padding value is either 0x01 or 0x0101. */
	switch (el->ftlv.dat_len) {
		case 2:
			if (el->ptr[el->ftlv.hdr_len + 1] != 0x01) {
				KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Metadata padding has invalid value.");
				goto cleanup;
			}
			/* no break */

		case 1:
			if (el->ptr[el->ftlv.hdr_len] != 0x01) {
				KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Metadata padding has invalid value.");
				goto cleanup;
			}
			break;

		default:
			KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Metadata padding has invalid length.");
			goto cleanup;
			break;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_AggregationChainMetaDataVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	VerificationTempData *tempData = NULL;
	KSI_TlvElement *el = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify aggregation hash chain metadata.");

	/* Loop through all the aggregation chains. */
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		const KSI_AggregationHashChain* aggregationChain = NULL;
		KSI_HashChainLinkList *linkList = NULL;
		size_t j;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (aggregationChain == NULL) break;

		res = KSI_AggregationHashChain_getChain(aggregationChain, &linkList);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		/* Loop through all the links in the aggregation chain. */
		for (j = 0; j < KSI_HashChainLinkList_length(linkList); j++) {
			KSI_HashChainLink *link = NULL;
			KSI_MetaDataElement *metaData = NULL;

			res = KSI_HashChainLinkList_elementAt(linkList, j, &link);
			if (res != KSI_OK) {
				VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}

			res = KSI_HashChainLink_getMetaData(link, &metaData);
			if (res != KSI_OK) {
				VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}

			if (metaData != NULL) {
				/* Check if the metadata padding exists by looking for tag 0x1E. */
				res = KSI_TlvElement_getElement(metaData->impl, 0x1E, &el);
				if (res != KSI_OK) {
					VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
					KSI_pushError(ctx, res, NULL);
					goto cleanup;
				}

				if (el != NULL) {
					KSI_TlvElement *tmp = NULL;

					/* Metadata padding can only be the first element in the metadata record. */
					res = KSI_TlvElementList_elementAt(metaData->impl->subList, 0, &tmp);
					if (res != KSI_OK) {
						VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
						KSI_pushError(ctx, res, NULL);
						goto cleanup;
					}

					/* Check that the first element is a valid metadata padding. */
					res = metaDataPadding_verify(ctx, tmp);
					if (res != KSI_OK) {
						if (res == KSI_INVALID_FORMAT) {
							result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
							VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_11);
							res = KSI_OK;
							goto cleanup;
						} else {
							VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
							KSI_pushError(ctx, res, NULL);
							goto cleanup;
						}
					}

					/* Check that the total length of the metadata record is even. */
					if (metaData->impl->ftlv.dat_len % 2) {
						result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
						VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_11);
						res = KSI_OK;
						goto cleanup;
					}
					KSI_LOG_info(ctx, "Metadata padding successfully verified.");
				} else {
					unsigned int len = KSI_getHashLength(metaData->impl->ptr[metaData->impl->ftlv.hdr_len]);
					/* Check that the metadata record cannot be interpreted as a valid imprint. */
					if (len != 0 && len + 1 == metaData->impl->ftlv.dat_len) {
						KSI_LOG_info(ctx, "Metadata could be interpreted as imprint.");
						result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
						VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_11);
						res = KSI_OK;
						goto cleanup;
					}
				}
				KSI_TlvElement_free(el);
				el = NULL;
			}
		}
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	KSI_TlvElement_free(el);
	return res;
}

int KSI_VerificationRule_AggregationHashChainConsistency(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	size_t successCount = 0;
	int level = 0;
	size_t i;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	VerificationTempData *tempData = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify aggregation hash chain consistency.");

	/* The aggregation level might not be 0 in case of local aggregation. */
	if (info->docAggrLevel > 0xff) {
		/* Aggregation level can't be larger than 0xff. */
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_VERIFICATION_INPUT, "Aggregation level is larger than 0xff.");
		goto cleanup;
	}
	level = (int)info->docAggrLevel;

	/* Aggregate all the aggregation chains. */
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		const KSI_AggregationHashChain* aggregationChain = NULL;
		KSI_DataHash *tmpHash = NULL;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (aggregationChain == NULL) break;

		if (hsh != NULL) {
			/* Validate input hash */
			if (!KSI_DataHash_equals(hsh, aggregationChain->inputHash)) {
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calculated hash :", hsh);
				KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected hash   :", aggregationChain->inputHash);
				result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
				VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_1);
				res = KSI_OK;
				goto cleanup;
			}
		}

		res = KSI_HashChain_aggregate(aggregationChain->ctx, aggregationChain->chain, aggregationChain->inputHash,
									  level, (int)KSI_Integer_getUInt64(aggregationChain->aggrHashId), &level, &tmpHash);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (hsh != NULL) {
			KSI_DataHash_free(hsh);
		}
		hsh = tmpHash;
		++successCount;
	}

	/* First verify internal calculations. */
	if (successCount != KSI_AggregationHashChainList_length(sig->aggregationChainList)) {
		KSI_LOG_debug(ctx, "Aggregation hash chain calculation failed.");
		result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_1);
		res = KSI_OK;
		goto cleanup;
	}

	if (tempData->aggregationOutputHash != NULL) {
		KSI_DataHash_free(tempData->aggregationOutputHash);
	}
	tempData->aggregationOutputHash = hsh;
	hsh = NULL;

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:
	KSI_DataHash_free(hsh);

	return res;
}

int KSI_VerificationRule_AggregationHashChainTimeConsistency(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	const KSI_AggregationHashChain *prevChain = NULL;
	size_t i;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify aggregation hash chain internal time consistency.");

	/* Aggregate all the aggregation chains. */
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		const KSI_AggregationHashChain* aggregationChain = NULL;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (aggregationChain == NULL) break;

		if (prevChain != NULL) {
			/* Verify aggregation time. */
			if (!KSI_Integer_equals(aggregationChain->aggregationTime, prevChain->aggregationTime)) {
				KSI_LOG_debug(ctx, "Aggregation hash chain's from different aggregation rounds.");
				result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
				VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_2);
				res = KSI_OK;
				goto cleanup;
			}
		}

		prevChain = aggregationChain;
	}

	result->stepsSuccessful |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_AggregationHashChainIndexConsistency(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	const KSI_AggregationHashChain *prevChain = NULL;
	size_t i;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify aggregation hash chain chain index consistency.");

	/* Aggregate all the aggregation chains. */
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		KSI_AggregationHashChain* aggregationChain = NULL;
		KSI_Integer *chainIndexCurr = NULL;
		KSI_uint64_t chainIndexCalc = 0;

		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, (KSI_AggregationHashChain **)&aggregationChain);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			goto cleanup;
		}

		if (aggregationChain == NULL) break;

		/* Verify shape of the aggregation hash chain. */
		if (KSI_IntegerList_length(aggregationChain->chainIndex) > 0) {
			res = KSI_AggregationHashChain_calculateShape(aggregationChain, &chainIndexCalc);
			if (res != KSI_OK) {
				VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}

			res = KSI_IntegerList_elementAt(aggregationChain->chainIndex, KSI_IntegerList_length(aggregationChain->chainIndex) - 1, &chainIndexCurr);
			if (res != KSI_OK) {
				VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}

			if (chainIndexCurr == NULL) {
				KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Aggregation hash chain index is missing.");
				VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
				goto cleanup;
			}

			if (KSI_Integer_getUInt64(chainIndexCurr) != chainIndexCalc) {
				KSI_LOG_debug(ctx, "Aggregation hash chain index does not match with aggregation hash chain shape.");
				VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_10);
				result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
				res = KSI_OK;
				goto cleanup;
			}
		}

		/* Verify chain indeces */
		if (prevChain != NULL) {
			/* Verify chain index length. */
			if (KSI_IntegerList_length(prevChain->chainIndex) != KSI_IntegerList_length(aggregationChain->chainIndex) + 1) {
				KSI_LOG_debug(ctx, "Unexpected chain index length in aggregation hash chain.");
				VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_10);
				result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
				res = KSI_OK;
				goto cleanup;
			} else {
				size_t j;
				for (j = 0; j < KSI_IntegerList_length(aggregationChain->chainIndex); j++) {
					KSI_Integer *chainIndex1 = NULL;
					KSI_Integer *chainIndex2 = NULL;

					res = KSI_IntegerList_elementAt(prevChain->chainIndex, j, &chainIndex1);
					if (res != KSI_OK) {
						VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
						KSI_pushError(ctx, res, NULL);
						goto cleanup;
					}

					res = KSI_IntegerList_elementAt(aggregationChain->chainIndex, j, &chainIndex2);
					if (res != KSI_OK) {
						VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
						KSI_pushError(ctx, res, NULL);
						goto cleanup;
					}

					if (!KSI_Integer_equals(chainIndex1, chainIndex2)) {
						KSI_LOG_debug(ctx, "Aggregation hash chain index is not continuation of previous chain index.");
						VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_10);
						result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_INTERNALLY;
						res = KSI_OK;
						goto cleanup;
					}
				}
			}
		}
		prevChain = aggregationChain;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

static int initAggregationOutputHash(KSI_VerificationContext *info) {
	int res = KSI_UNKNOWN_ERROR;
	VerificationTempData *tempData = NULL;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tempData = info->tempData;
	if (tempData == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	if (tempData->aggregationOutputHash == NULL) {
		KSI_AggregationHashChainList_aggregate(info->signature->aggregationChainList, info->ctx,
											   (int)info->docAggrLevel, &tempData->aggregationOutputHash);
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarHashChainInputHashVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *calInputHash = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	VerificationTempData *tempData = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify calendar hash chain input hash consistency.");

	res = KSI_CalendarHashChain_getInputHash(sig->calendarChain, &calInputHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = initAggregationOutputHash(info);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (tempData->aggregationOutputHash == NULL  || calInputHash == NULL) {
		static const char *msg = "Missing aggregation output hash or calendar input hash.";
		KSI_LOG_info(ctx, (char *)msg);
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, msg);
		goto cleanup;
	}

	if (!KSI_DataHash_equals(tempData->aggregationOutputHash, calInputHash)) {
		KSI_LOG_info(ctx, "Calendar hash chain's input hash does not match with aggregation root hash.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Input hash from aggregation :", tempData->aggregationOutputHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected input hash         :", calInputHash);
		result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_3);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarHashChainAggregationTime(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationHashChain *aggregationChain = NULL;
	KSI_Integer *calAggrTime = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify calendar hash chain aggregation time consistency.");

	/* Take the first aggregation hash chain, as all of the chain should have the same value for "aggregation time". */
	res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggregationChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &calAggrTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_Integer_equals(calAggrTime, aggregationChain->aggregationTime)) {
		KSI_LOG_info(ctx, "Aggregation time in calendar hash chain and aggregation hash chain differ.");
		result->stepsFailed |= KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_4);
		res = KSI_OK;
		goto cleanup;
	}

	result->stepsSuccessful |= KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarHashChainRegistrationTime(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	time_t calculatedAggrTime;
	KSI_Integer *calendarAggrTime = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_CALCHAIN_INTERNALLY;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify calendar hash chain time consistency.");

	res = KSI_CalendarHashChain_calculateAggregationTime(sig->calendarChain, &calculatedAggrTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &calendarAggrTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_Integer_equalsUInt(calendarAggrTime, (KSI_uint64_t) calculatedAggrTime)) {
		KSI_LOG_info(ctx, "Calendar hash chain internally inconsistent.");
		result->stepsFailed |= KSI_VERIFY_CALCHAIN_INTERNALLY;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_5);
		res = KSI_OK;
		goto cleanup;
	}

	result->stepsSuccessful |= KSI_VERIFY_CALCHAIN_INTERNALLY;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
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

	result->stepsPerformed |= KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify calendar hash chain authentication record.");

	/* Calculate the root hash value. */
	res = KSI_CalendarHashChain_aggregate(sig->calendarChain, &rootHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	/* Get publication data. */
	res = KSI_CalendarAuthRec_getPublishedData(sig->calendarAuthRec, &pubData);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	/* Get published hash value. */
	res = KSI_PublicationData_getImprint(pubData, &pubHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_DataHash_equals(rootHash, pubHash)) {
		KSI_LOG_info(ctx, "Calendar hash chain and authentication record hash mismatch.");
		result->stepsFailed |= KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_8);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:
	KSI_DataHash_free(rootHash);

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
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

	result->stepsPerformed |= KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify calendar hash chain authentication record publication time.");

	/* Get the publication time from calendar hash chain. */
	res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &calPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	/* Get publication data. */
	res = KSI_CalendarAuthRec_getPublishedData(sig->calendarAuthRec, &pubData);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	/* Get publication time. */
	res = KSI_PublicationData_getTime(pubData, &pubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_Integer_equals(calPubTime, pubTime)) {
		KSI_LOG_info(ctx, "Calendar hash chain and authentication record time mismatch.");
		result->stepsFailed |= KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_6);
		res = KSI_OK;
		goto cleanup;
	}

	result->stepsSuccessful |= KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_SignaturePublicationRecordPublicationHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
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

	result->stepsPerformed |= KSI_VERIFY_CALCHAIN_WITH_PUBLICATION;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify calendar hash chain publication hash consistency.");

	/* Calculate calendar aggregation root hash value. */
	res = KSI_CalendarHashChain_aggregate(sig->calendarChain, &rootHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	/* Get publication data from publication record */
	res = KSI_PublicationRecord_getPublishedData(sig->publication, &pubData);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	/* Get published hash value. */
	res = KSI_PublicationData_getImprint(pubData, &publishedHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_DataHash_equals(rootHash, publishedHash)) {
		KSI_LOG_info(ctx, "Published hash and calendar hash chain root hash mismatch.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calendar root hash :", rootHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Published hash     :", publishedHash);
		result->stepsFailed |= KSI_VERIFY_CALCHAIN_WITH_PUBLICATION;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_9);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:
	KSI_DataHash_free(rootHash);

	return res;
}

int KSI_VerificationRule_SignaturePublicationRecordPublicationTime(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
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

	result->stepsPerformed |= KSI_VERIFY_CALCHAIN_WITH_PUBLICATION;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify calendar hash chain publication time consistency.");

	/* Get the publication time from calendar hash chain. */
	res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &calPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	/* Get publication data from publication record */
	res = KSI_PublicationRecord_getPublishedData(sig->publication, &pubData);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	/* Get publication time */
	res = KSI_PublicationData_getTime(pubData, &sigPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_Integer_equals(calPubTime, sigPubTime)){
		KSI_LOG_info(ctx, "Calendar hash chain publication time mismatch.");
		KSI_LOG_debug(ctx, "Calendar hash chain publication time: %i.", KSI_Integer_getUInt64(calPubTime));
		KSI_LOG_debug(ctx, "Published publication time:           %i.", KSI_Integer_getUInt64(sigPubTime));
		result->stepsFailed |= KSI_VERIFY_CALCHAIN_WITH_PUBLICATION;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_7);
		res = KSI_OK;
		goto cleanup;
	}

	result->stepsSuccessful |= KSI_VERIFY_CALCHAIN_WITH_PUBLICATION;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_DocumentHashDoesNotExist(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying document hash does not exist.");

	if (info->documentHash != NULL) {
		KSI_LOG_info(info->ctx, "Document hash exists.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_DocumentHashExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verify document hash existence.");

	if (info->documentHash == NULL) {
		KSI_LOG_info(info->ctx, "Document hash is missing.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_DocumentHashVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_DOCUMENT;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify document hash.");
	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Document hash: ", info->documentHash);

	if (sig->rfc3161 != NULL) {
		KSI_LOG_info(ctx, "Document hash is compared with RFC 3161 input hash.");
		res = KSI_RFC3161_getInputHash(sig->rfc3161, &hsh);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	} else {
		res = KSI_Signature_getDocumentHash(sig, &hsh);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	if (!KSI_DataHash_equals(hsh, info->documentHash)) {
		KSI_LOG_info(ctx, "Wrong document.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Document hash :", info->documentHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Signed hash   :", hsh);
		result->stepsFailed |= KSI_VERIFY_DOCUMENT;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_GEN_1);
		res = KSI_OK;
		goto cleanup;
	}

	result->stepsSuccessful |= KSI_VERIFY_DOCUMENT;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:
	KSI_nofree(hsh);

	return res;
}

int KSI_VerificationRule_SignatureDoesNotContainPublication(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying signature does not contain publication record.");

	if (info->signature->publication != NULL) {
		KSI_LOG_info(info->ctx, "Signature contains publication record.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

static int getNextRightLink(KSI_HashChainLinkList *list, size_t *pos, KSI_HashChainLink **link) {
	int res = KSI_UNKNOWN_ERROR;

	if (list == NULL || pos == NULL || link == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	while (*pos < KSI_HashChainLinkList_length(list)) {
		int isLeft;
		res = KSI_HashChainLinkList_elementAt(list, *pos, link);
		if (res != KSI_OK) {
			goto cleanup;
		}
		res = KSI_HashChainLink_getIsLeft(*link, &isLeft);
		if (res != KSI_OK) {
			goto cleanup;
		}
		if (!isLeft) {
			res = KSI_OK;
			goto cleanup;
		}
		++*pos;
	}

	*link = NULL;
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureCalendarChainRightLinksMatch(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_HashChainLinkList *sigList = NULL;
	KSI_HashChainLinkList *extSigList = NULL;
	size_t sigListPos = 0;
	size_t extSigListPos = 0;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_CALCHAIN_ONLINE;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify calendar hash chain right link count and right link hashes.");

	res = KSI_CalendarHashChain_getHashChain(sig->calendarChain, &sigList);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = getExtendedCalendarHashChain(info, pubTime, &extCalHashChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getHashChain(extCalHashChain, &extSigList);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	for ( ; ; ) {
		KSI_HashChainLink *sigRightLink = NULL;
		KSI_HashChainLink *extSigRightLink = NULL;
		KSI_DataHash *sigRightLinkHash = NULL;
		KSI_DataHash *extSigRightLinkHash = NULL;

		res = getNextRightLink(sigList, &sigListPos, &sigRightLink);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
		res = getNextRightLink(extSigList, &extSigListPos, &extSigRightLink);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (sigRightLink == NULL && extSigRightLink == NULL) {
			/* Match: both chains over at same time. */
			VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
			res = KSI_OK;
			goto cleanup;
		}

		if (sigRightLink == NULL || extSigRightLink == NULL) {
			/* Mismatch: one chain over before the other. */
			KSI_LOG_info(ctx, "Different number of right links in calendar hash chains");
			result->stepsFailed |= KSI_VERIFY_CALCHAIN_ONLINE;
			VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_CAL_4);
			res = KSI_OK;
			goto cleanup;
		}

		res = KSI_HashChainLink_getImprint(sigRightLink, &sigRightLinkHash);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
		res = KSI_HashChainLink_getImprint(extSigRightLink, &extSigRightLinkHash);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (!KSI_DataHash_equals(sigRightLinkHash, extSigRightLinkHash)) {
			/* Mismatch: different hash values. */
			KSI_LOG_info(ctx, "Different sibling hashes in right links in calendar hash chains");
			KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Signature right link hash     :", sigRightLinkHash);
			KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Ext signature right link hash :", extSigRightLinkHash);
			result->stepsFailed |= KSI_VERIFY_CALCHAIN_ONLINE;
			VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_CAL_4);
			res = KSI_OK;
			goto cleanup;
		}

		/* Current links match, advance in both chains. */
		++sigListPos;
		++extSigListPos;
	}

cleanup:

	return res;
}

int KSI_VerificationRule_SignaturePublicationRecordExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verify signature publication record existence.");

	if (info->signature->publication == NULL) {
		KSI_LOG_info(info->ctx, "Signature publication record is missing.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
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

	result->stepsPerformed |= KSI_VERIFY_CALCHAIN_ONLINE;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(info->ctx, "Verify extended signature calendar hash chain root hash.");

	res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = getExtendedCalendarHashChain(info, pubTime, &extCalHashChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_aggregate(sig->calendarChain, &rootHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_aggregate(extCalHashChain, &extRootHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_DataHash_equals(rootHash, extRootHash)) {
		KSI_LOG_info(ctx, "Calendar hash chain root hash and extehded calendar hash chain root hash mismatch.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calendar root hash     :", rootHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Ext calendar root hash :", extRootHash);
		result->stepsFailed |= KSI_VERIFY_CALCHAIN_ONLINE;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_CAL_1);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:
	KSI_DataHash_free(rootHash);
	KSI_DataHash_free(extRootHash);

	return res;
}

int KSI_VerificationRule_CalendarHashChainDoesNotExist(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying calendar hash chain does not exist.");

	if (info->signature->calendarChain != NULL) {
		KSI_LOG_info(info->ctx, "Signature calendar hash chain is present.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

static int initExtendedCalendarHashChain(KSI_VerificationContext *info, KSI_Integer *endTime) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *startTime = NULL;
	KSI_ExtendReq *req = NULL;
	KSI_RequestHandle *handle = NULL;
	KSI_ExtendResp *resp = NULL;
	KSI_Integer *status = NULL;
	KSI_CalendarHashChain *tmp = NULL;
	KSI_AggregationHashChain *aggr = NULL;
	VerificationTempData *tempData = NULL;
	KSI_Integer *respReqId = NULL;
	KSI_Integer *reqReqId = NULL;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}


	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	/* Extract start time. */
	if (sig->calendarChain != NULL) {
		res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &startTime);
		if (res != KSI_OK) {
			KSI_pushError(ctx,res, NULL);
			goto cleanup;
		}
	} else {
		/* Take the first aggregation hash chain, as all of the chain should have the same value for "aggregation time". */
		res = (KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggr));
		if (res != KSI_OK) goto cleanup;

		res = KSI_AggregationHashChain_getAggregationTime(aggr, &startTime);
		if (res != KSI_OK) {
			KSI_pushError(ctx,res, NULL);
			goto cleanup;
		}
	}

	/* Clone the start time object. */
	KSI_Integer_ref(startTime);

	res = KSI_createExtendRequest(ctx, startTime, endTime, &req);
	if (res != KSI_OK) {
		KSI_pushError(ctx,res, NULL);
		goto cleanup;
	}

	res = KSI_sendExtendRequest(ctx, req, &handle);
	if (res != KSI_OK) {
		KSI_pushError(ctx,res, NULL);
		goto cleanup;
	}

	res = KSI_RequestHandle_perform(handle);
	if (res != KSI_OK) {
		KSI_pushError(ctx,res, NULL);
		goto cleanup;
	}

	res = KSI_RequestHandle_getExtendResponse(handle, &resp);
	if (res != KSI_OK) goto cleanup;

	/* Verify status. */
	res = KSI_ExtendResp_getStatus(resp, &status);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	if (status != NULL && !KSI_Integer_equalsUInt(status, 0)) {
		char msg[1024];
		KSI_snprintf(msg, sizeof(msg), "Extender returned error %llu.", (unsigned long long)KSI_Integer_getUInt64(status));
		KSI_pushError(ctx, res = KSI_convertExtenderStatusCode(status), msg);
		goto cleanup;
	}

	/* Verify request id. */
	res = KSI_ExtendResp_getRequestId(resp, &respReqId);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	res = KSI_ExtendReq_getRequestId(req, &reqReqId);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	if (!KSI_Integer_equals(respReqId, reqReqId)) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Request id's mismatch.");
		goto cleanup;
	}

	/* Extract the calendar hash chain. */
	res = KSI_ExtendResp_getCalendarHashChain(resp, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx,res, NULL);
		goto cleanup;
	}

	/* Remove the chain from the structure, as it will be freed when this function finishes. */
	res = KSI_ExtendResp_setCalendarHashChain(resp, NULL);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (tempData->calendarChain != NULL) {
		KSI_CalendarHashChain_free(tempData->calendarChain);
	}
	tempData->calendarChain = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:
	KSI_Integer_free(startTime);
	KSI_ExtendReq_free(req);
	KSI_RequestHandle_free(handle);
	KSI_ExtendResp_free(resp);
	KSI_CalendarHashChain_free(tmp);

	return res;
}

static int getExtendedCalendarHashChain(KSI_VerificationContext *info, KSI_Integer *pubTime, KSI_CalendarHashChain **chain) {
	int res = KSI_UNKNOWN_ERROR;
	VerificationTempData *tempData = NULL;

	if (info == NULL || info->ctx == NULL || info->signature == NULL || chain == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(info->ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	/* Check if signature has been already extended */
	if (tempData->calendarChain == NULL) {
		/* Extend the signature to the publication time as attached calendar chain, or to head if time is NULL */
		res = initExtendedCalendarHashChain(info, pubTime);
		if (res != KSI_OK) goto cleanup;
	}

	*chain = tempData->calendarChain;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_DataHash *calInputHash = NULL;
	VerificationTempData *tempData = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_CALCHAIN_ONLINE;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify extended signature calendar hash chain input hash.");

	/* If the calendar chain is available, then take the publication from calendar chain. */
	/* Otherwice the extender will extend to head (pubTime == NULL) */
	if (sig->calendarChain != NULL) {
		res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	res = getExtendedCalendarHashChain(info, pubTime, &extCalHashChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getInputHash(extCalHashChain, &calInputHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = initAggregationOutputHash(info);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_DataHash_equals(tempData->aggregationOutputHash, calInputHash)) {
		KSI_LOG_info(ctx, "Calendar hash chain's input hash does not match with aggregation root hash.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Input hash from aggregation :", tempData->aggregationOutputHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected input hash         :", calInputHash);
		result->stepsFailed |= KSI_VERIFY_CALCHAIN_ONLINE;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_CAL_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
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

	result->stepsPerformed |= KSI_VERIFY_CALCHAIN_ONLINE;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify extended signature calendar hash chain aggregation time.");

	/* If the calendar chain is available, then take the publication from calendar chain. */
	/* Otherwice the extender will extend to head (pubTime == NULL) */
	if (sig->calendarChain != NULL) {
		res = KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &pubTime);
		if (res != KSI_OK) {
			VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	res = getExtendedCalendarHashChain(info, pubTime, &extCalHashChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_calculateAggregationTime(extCalHashChain, &calculatedAggrTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	/* Take the first aggregation hash chain, as all of the chain should have the same value for "aggregation time". */
	res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggregationChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_Integer_equalsUInt(aggregationChain->aggregationTime, (KSI_uint64_t) calculatedAggrTime)) {
		KSI_LOG_info(ctx, "Invalid extended signature calendar calendar chain aggregation time.");
		KSI_LOG_debug(ctx, "Calendar hash chain aggregation time: %i.", calculatedAggrTime);
		KSI_LOG_debug(ctx, "Signature aggregation time:           %i.", KSI_Integer_getUInt64(aggregationChain->aggregationTime));
		result->stepsFailed |= KSI_VERIFY_CALCHAIN_ONLINE;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_CAL_3);
		res = KSI_OK;
		goto cleanup;
	}

	result->stepsSuccessful |= KSI_VERIFY_CALCHAIN_ONLINE;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarHashChainExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying calendar hash chain existence.");

	if (info->signature->calendarChain == NULL) {
		KSI_LOG_info(info->ctx, "Signature calendar hash chain is missing.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying calendar authentication record existence.");

	if (info->signature->calendarAuthRec == NULL) {
		KSI_LOG_info(info->ctx, "Calendar authentication record is missing.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordDoesNotExist(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying calendar hash chain authentication record does not exist.");

	if (info->signature->calendarAuthRec != NULL) {
		KSI_LOG_info(info->ctx, "Calendar hash chain authentication record is present.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

static int initPublicationsFile(KSI_VerificationContext *info) {
	int res = KSI_UNKNOWN_ERROR;
	VerificationTempData *tempData = NULL;
	KSI_PublicationsFile *tmp = NULL;

	if (info == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(info->ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	if (tempData->publicationsFile == NULL) {
		if (info->userPublicationsFile != NULL) {
			tmp = KSI_PublicationsFile_ref(info->userPublicationsFile);
		} else {
			bool verifyPubFile = (info->ctx->publicationsFile == NULL);

			res = KSI_receivePublicationsFile(info->ctx, &tmp);
			if (res != KSI_OK) goto cleanup;

			if (verifyPubFile == true) {
				KSI_LOG_info(info->ctx, "Verifying implicitly publications file.");

				res = KSI_verifyPublicationsFile(info->ctx, tmp);
				if (res != KSI_OK) goto cleanup;


			}
		}

		tempData->publicationsFile = tmp;
		tmp = NULL;
	}

	res = KSI_OK;

cleanup:

	KSI_PublicationsFile_free(tmp);

	return res;
}

int KSI_VerificationRule_CertificateExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_OctetString *certId = NULL;
	KSI_PKICertificate *cert = NULL;
	VerificationTempData *tempData = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		res = KSI_INVALID_ARGUMENT;
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		goto cleanup;
	}

	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify calendar hash chain authentication record certificate.");

	if (sig->calendarAuthRec == NULL) {
		const char *msg = "Calendar hash chain authentication record does not exist.";
		KSI_LOG_info(info->ctx, (char *)msg);
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, msg);
		goto cleanup;
	}

	res = KSI_PKISignedData_getCertId(sig->calendarAuthRec->signatureData, &certId);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (certId == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Missing PKI sertificate ID in calendar authentication record.");
		goto cleanup;
	}

	res = initPublicationsFile(info);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationsFile_getPKICertificateById(tempData->publicationsFile, certId, &cert);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (cert == NULL) {
		KSI_LOG_info(ctx, "Certificate not found.");
		result->stepsFailed |= KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_KEY_1);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
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
	VerificationTempData *tempData = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify calendar hash chain authentication record signature.");

	if (sig->calendarAuthRec == NULL) {
		const char *msg = "Calendar authentication record does not exist.";
		KSI_LOG_info(info->ctx, (char *)msg);
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, msg);
		goto cleanup;
	}

	res = KSI_PKISignedData_getCertId(sig->calendarAuthRec->signatureData, &certId);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (certId == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Missing PKI certificate ID in calendar authentication record.");
		goto cleanup;
	}

	res = initPublicationsFile(info);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationsFile_getPKICertificateById(tempData->publicationsFile, certId, &cert);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (cert == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Suitable PKI certificate not found in publications file.");
		goto cleanup;
	}

	res = KSI_PKISignedData_getSignatureValue(sig->calendarAuthRec->signatureData, &signatureValue);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OctetString_extract(signatureValue, &rawSignature, &rawSignature_len);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_serialize(sig->calendarAuthRec->pubData->baseTlv, &rawData, &rawData_len);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PKISignedData_getSigType(sig->calendarAuthRec->signatureData, &sigtype);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PKITruststore_verifyRawSignature(ctx, rawData, rawData_len, KSI_Utf8String_cstr(sigtype),
											   rawSignature, rawSignature_len, cert);
	if (res != KSI_OK) {
		KSI_LOG_info(ctx, "Failed to verify raw signature.");
		result->stepsFailed |= KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_KEY_2);
		res = KSI_OK;
		goto cleanup;
	}

	result->stepsSuccessful |= KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:
	KSI_free(rawData);

	return res;
}

int KSI_VerificationRule_PublicationsFileContainsSignaturePublication(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	VerificationTempData *tempData = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_PUBLICATION_WITH_PUBFILE;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify signature publication record.");

	if (sig->publication == NULL) {
		const char *msg = "Signature does not contain publication record.";
		KSI_LOG_info(ctx, (char *)msg);
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, msg);
		goto cleanup;
	}

	res = initPublicationsFile(info);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationsFile_findPublication(tempData->publicationsFile, sig->publication, &pubRec);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	if (pubRec == NULL) {
		KSI_LOG_info(ctx, "Publications file does not contain signature publication.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	result->stepsSuccessful |= KSI_VERIFY_PUBLICATION_WITH_PUBFILE;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	KSI_PublicationRecord_free(pubRec);
	return res;
}

int KSI_VerificationRule_PublicationsFileContainsPublication(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	time_t aggrTime;
	KSI_Integer *tempTime = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	VerificationTempData *tempData = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_PUBLICATION_WITH_PUBFILE;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify publication record existence.");

	if (sig->calendarChain == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	res = KSI_CalendarHashChain_calculateAggregationTime(sig->calendarChain, &aggrTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Integer_new(ctx, aggrTime, &tempTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = initPublicationsFile(info);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationsFile_getNearestPublication(tempData->publicationsFile, tempTime, &pubRec);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	if (pubRec == NULL) {
		KSI_LOG_info(ctx, "Publication not found.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	KSI_PublicationRecord_free(pubRec);
	KSI_Integer_free(tempTime);

	return res;
}

int KSI_VerificationRule_ExtendingPermittedVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verify extending permitted.");

	if (info->extendingAllowed == 0) {
		KSI_LOG_info(info->ctx, "Extending not allowed.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	time_t aggrTime;
	KSI_Integer *sigPubTime = NULL;
	KSI_Integer *pubDataPubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_DataHash *extCalRootHash = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_DataHash *pubDataHash = NULL;
	VerificationTempData *tempData = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_PUBLICATION_WITH_PUBFILE;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify publication hash.");

	res = KSI_CalendarHashChain_calculateAggregationTime(sig->calendarChain, &aggrTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Integer_new(ctx, aggrTime, &sigPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = initPublicationsFile(info);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationsFile_getNearestPublication(tempData->publicationsFile, sigPubTime, &pubRec);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	if (pubRec == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "No available publications.");
		goto cleanup;
	}
	res = KSI_PublicationData_getImprint(pubRec->publishedData, &pubDataHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationData_getTime(pubRec->publishedData, &pubDataPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = getExtendedCalendarHashChain(info, pubDataPubTime, &extCalHashChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_aggregate(extCalHashChain, &extCalRootHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_DataHash_equals(extCalRootHash, pubDataHash)) {
		KSI_LOG_info(ctx, "Publications file publication hash does not match with extender response calendar hash chain root hash.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Publication hash   :", pubDataHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calendar root hash :", extCalRootHash);
		result->stepsFailed |= KSI_VERIFY_PUBLICATION_WITH_PUBFILE;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_PUB_1);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	KSI_PublicationRecord_free(pubRec);
	KSI_Integer_free(sigPubTime);
	KSI_DataHash_free(extCalRootHash);

	return res;
}

int KSI_VerificationRule_PublicationsFilePublicationTimeMatchesExtenderResponse(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	time_t aggrTime;
	KSI_Integer *sigPubTime = NULL;
	KSI_Integer *pubDataPubTime = NULL;
	KSI_Integer *extPubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	VerificationTempData *tempData = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_PUBLICATION_WITH_PUBFILE;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}


	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify publication time.");

	res = KSI_CalendarHashChain_calculateAggregationTime(sig->calendarChain, &aggrTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Integer_new(ctx, aggrTime, &sigPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = initPublicationsFile(info);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationsFile_getNearestPublication(tempData->publicationsFile, sigPubTime, &pubRec);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	if (pubRec == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "No available publications.");
		goto cleanup;
	}

	res = KSI_PublicationData_getTime(pubRec->publishedData, &pubDataPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = getExtendedCalendarHashChain(info, pubDataPubTime, &extCalHashChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getPublicationTime(extCalHashChain, &extPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_Integer_equals(pubDataPubTime, extPubTime)) {
		KSI_LOG_info(ctx, "Invalid extended signature calendar hash chain aggregation time.");
		KSI_LOG_debug(ctx, "Publications file publication time: %i.", KSI_Integer_getUInt64(pubDataPubTime));
		KSI_LOG_debug(ctx, "Extended response publication time: %i.", KSI_Integer_getUInt64(extPubTime));
		result->stepsFailed |= KSI_VERIFY_PUBLICATION_WITH_PUBFILE;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_PUB_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	KSI_PublicationRecord_free(pubRec);
	KSI_Integer_free(sigPubTime);

	return res;
}

int KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	time_t aggrTime;
	KSI_DataHash *calInputHash = NULL;
	KSI_Integer *pubDataPubTime = NULL;
	KSI_Integer *sigPubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	VerificationTempData *tempData = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_PUBLICATION_WITH_PUBFILE;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify aggregation root hash.");

	res = KSI_CalendarHashChain_calculateAggregationTime(sig->calendarChain, &aggrTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Integer_new(ctx, aggrTime, &sigPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = initPublicationsFile(info);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationsFile_getNearestPublication(tempData->publicationsFile, sigPubTime, &pubRec);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	if (pubRec == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "No available publications.");
		goto cleanup;
	}

	res = KSI_PublicationData_getTime(pubRec->publishedData, &pubDataPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = getExtendedCalendarHashChain(info, pubDataPubTime, &extCalHashChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getInputHash(extCalHashChain, &calInputHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = initAggregationOutputHash(info);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_DataHash_equals(tempData->aggregationOutputHash, calInputHash)) {
		KSI_LOG_info(ctx, "Signature aggregation root hash does not match extender response input hash.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Aggr root hash      :", tempData->aggregationOutputHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calendar input hash :", calInputHash);
		result->stepsFailed |= KSI_VERIFY_PUBLICATION_WITH_PUBFILE;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_PUB_3);
		res = KSI_OK;
		goto cleanup;
	}

	result->stepsSuccessful |= KSI_VERIFY_PUBLICATION_WITH_PUBFILE;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	KSI_PublicationRecord_free(pubRec);
	KSI_Integer_free(sigPubTime);

	return res;
}

int KSI_VerificationRule_UserProvidedPublicationExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying user publication existence.");

	if (info->userPublication == NULL ||
			info->userPublication->time == NULL || info->userPublication->imprint == NULL) {
		KSI_LOG_info(info->ctx, "User publication data not provided.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_RequireNoUserProvidedPublication(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_info(info->ctx, "Verifying user publication is not provided.");

	if (info->userPublication != NULL) {
		KSI_LOG_info(info->ctx, "User publication data provided.");
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_UserProvidedPublicationVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
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

	result->stepsPerformed |= KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;

	if (info == NULL || info->ctx == NULL || info->signature == NULL || info->userPublication == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify user publication.");

	res = KSI_PublicationData_getTime(sig->publication->publishedData, &sigPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	res = KSI_PublicationData_getImprint(sig->publication->publishedData, &sigPubHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (sigPubTime == NULL || sigPubHash == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Missing publication time or hash in signature publication data.");
		goto cleanup;
	}

	res = KSI_PublicationData_getTime(info->userPublication, &usrPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	res = KSI_PublicationData_getImprint(info->userPublication, &usrPubHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (usrPubTime == NULL || usrPubHash == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_VERIFICATION_INPUT, "Missing publication time or hash in user publication data.");
		goto cleanup;
	}

	if (KSI_Integer_compare(sigPubTime, usrPubTime) != 0) {
		KSI_LOG_debug(ctx, "Publication time from signature publication: %i", KSI_Integer_getUInt64(sigPubTime));
		KSI_LOG_debug(ctx, "Publication time from user publication     : %i", KSI_Integer_getUInt64(usrPubTime));
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	if (!KSI_DataHash_equals(sigPubHash, usrPubHash)) {
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Root hash from signature publication:", sigPubHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Root hash from user publication     :", usrPubHash);
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_INT_9);
		res = KSI_OK;
		goto cleanup;
	}

	result->stepsSuccessful |= KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}


int KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *sigPubTime = NULL;
	KSI_Integer *usrPubDataTime = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;

	if (info == NULL || info->ctx == NULL || info->signature == NULL || info->userPublication == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify that signature is created before user provided publication.");

	res = KSI_CalendarHashChain_getAggregationTime(sig->calendarChain, &sigPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationData_getTime(info->userPublication, &usrPubDataTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (usrPubDataTime == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_VERIFICATION_INPUT, "Missing publication time in user publication data.");
		goto cleanup;
	}

	if (KSI_Integer_compare(sigPubTime, usrPubDataTime) != -1) {
		KSI_LOG_debug(ctx, "Publication time from sig pub data : %i", KSI_Integer_getUInt64(sigPubTime));
		KSI_LOG_debug(ctx, "Publication time from user pub data: %i", KSI_Integer_getUInt64(usrPubDataTime));
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Integer *usrPubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_DataHash *extRootHash = NULL;
	KSI_DataHash *usrPubDataHash = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;

	if (info == NULL || info->ctx == NULL || info->signature == NULL || info->userPublication == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify user publication hash with extender response.");

	res = KSI_PublicationData_getTime(info->userPublication, &usrPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (usrPubTime == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_VERIFICATION_INPUT, "Missing publication time in user publication data.");
		goto cleanup;
	}

	res = getExtendedCalendarHashChain(info, usrPubTime, &extCalHashChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_aggregate(extCalHashChain, &extRootHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationData_getImprint(info->userPublication, &usrPubDataHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_DataHash_equals(extRootHash, usrPubDataHash)) {
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Root hash from extender response:", extRootHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Root hash from user publication :", usrPubDataHash);
		result->stepsFailed |= KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_PUB_1);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:
	KSI_DataHash_free(extRootHash);

	return res;
}

int KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
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

	result->stepsPerformed |= KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	sig = info->signature;
	KSI_ERR_clearErrors(ctx);

	KSI_LOG_info(ctx, "Verify user publication time with extender response.");

	res = KSI_PublicationData_getTime(info->userPublication, &usrPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (usrPubTime == NULL) {
		const char *msg = "Missing publication time in user publication data.";
		KSI_LOG_info(ctx, (char *)msg);
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_VERIFICATION_INPUT, msg);
		goto cleanup;
	}

	res = getExtendedCalendarHashChain(info, usrPubTime, &extCalHashChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getPublicationTime(extCalHashChain, &extPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_Integer_equals(usrPubTime, extPubTime)) {
		KSI_LOG_info(ctx, "User provided publication time does not match extender response time.");
		KSI_LOG_debug(ctx, "Publication time from extender response: %i", KSI_Integer_getUInt64(extPubTime));
		KSI_LOG_debug(ctx, "Publication time from user pub data    : %i", KSI_Integer_getUInt64(usrPubTime));
		result->stepsFailed |= KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_PUB_2);
		res = KSI_OK;
		goto cleanup;
	}

	res = KSI_Signature_getSigningTime(sig, &signingTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getAggregationTime(extCalHashChain, &extAggrTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_Integer_equals(signingTime, extAggrTime)) {
		KSI_LOG_info(ctx, "Signature aggregation hash chain aggregation time does not math with extender aggregation time.");
		KSI_LOG_debug(ctx, "Signing time: %i", KSI_Integer_getUInt64(signingTime));
		KSI_LOG_debug(ctx, "Extender aggregation time: %i", KSI_Integer_getUInt64(extAggrTime));
		result->stepsFailed |= KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_PUB_2);
		res = KSI_OK;
		goto cleanup;
	}

	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Integer *usrPubTime = NULL;
	KSI_CalendarHashChain *extCalHashChain = NULL;
	KSI_DataHash *calInputHash = NULL;
	VerificationTempData *tempData = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->stepsPerformed |= KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;

	if (info == NULL || info->ctx == NULL || info->signature == NULL) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = info->ctx;
	KSI_ERR_clearErrors(ctx);

	tempData = info->tempData;
	if (tempData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Verification context not properly initialized.");
		goto cleanup;
	}

	KSI_LOG_info(ctx, "Verify signature aggregation root hash with extender response input hash.");

	res = KSI_PublicationData_getTime(info->userPublication, &usrPubTime);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (usrPubTime == NULL) {
		const char *msg = "Missing publication time in user publication data.";
		KSI_LOG_info(ctx, (char *)msg);
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res = KSI_INVALID_VERIFICATION_INPUT, msg);
		goto cleanup;
	}

	res = getExtendedCalendarHashChain(info, usrPubTime, &extCalHashChain);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_CalendarHashChain_getInputHash(extCalHashChain, &calInputHash);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = initAggregationOutputHash(info);
	if (res != KSI_OK) {
		VERIFICATION_RESULT(KSI_VER_RES_NA, KSI_VER_ERR_GEN_2);
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_DataHash_equals(tempData->aggregationOutputHash, calInputHash)) {
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Signature aggregation root hash :", tempData->aggregationOutputHash);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Extender calendar input hash    :", calInputHash);
		result->stepsFailed |= KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;
		VERIFICATION_RESULT(KSI_VER_RES_FAIL, KSI_VER_ERR_PUB_3);
		res = KSI_OK;
		goto cleanup;
	}

	result->stepsSuccessful |= KSI_VERIFY_PUBLICATION_WITH_PUBSTRING;
	VERIFICATION_RESULT(KSI_VER_RES_OK, KSI_VER_ERR_NONE);
	res = KSI_OK;

cleanup:

	return res;
}

