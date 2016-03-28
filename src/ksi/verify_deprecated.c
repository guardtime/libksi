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

#include "internal.h"
#include "verification_impl.h"
#include "signature_impl.h"
#include "publicationsfile_impl.h"
#include "tlv.h"
#include "hashchain.h"
#include "net.h"
#include "pkitruststore.h"
#include "ctx_impl.h"

int createExtendRequest(KSI_CTX *ctx, KSI_Integer *start, KSI_Integer *end, KSI_ExtendReq **request);

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
	KSI_Integer *aggreTime = NULL;
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
		KSI_pushError(ctx, res = KSI_INVALID_SIGNATURE, "Aggregation chain is missing.");
		goto cleanup;
	}

	res = KSI_AggregationHashChainList_elementAt(aggreChain, 0, &firstChain);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (KSI_Integer_compare(firstChain->aggregationTime, rfc3161->aggregationTime) != 0) {
		KSI_LOG_debug(ctx, "Signatures aggregation time: %i.", KSI_Integer_getUInt64(firstChain->aggregationTime));
		KSI_LOG_debug(ctx, "RFC 3161 aggregation time:   %i.", KSI_Integer_getUInt64(rfc3161->aggregationTime));
		KSI_pushError(ctx, res = KSI_VERIFICATION_FAILURE, "Aggregation chain and RFC 3161 aggregation time mismatch.");
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
				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}

			res = KSI_IntegerList_elementAt(rfc3161->chainIndex, i, &ch2);
			if (res != KSI_OK) {
				KSI_pushError(ctx, res, NULL);
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

static int rfc3161_getInputToAggreChain(const KSI_Signature *sig, KSI_DataHash **inputToAggre) {
	int res;
	KSI_CTX *ctx = NULL;
	KSI_DataHash *hsh_tstInfo = NULL;
	KSI_DataHash *hsh_sigAttr = NULL;
	KSI_DataHash *tmp = NULL;
	KSI_DataHasher *hsr = NULL;
	KSI_RFC3161 *rfc = NULL;
	const unsigned char *imprint = NULL;
	size_t imprint_len = 0;
	KSI_HashAlgorithm algo_id = -1;
	KSI_HashAlgorithm tstInfoAlgoId;
	KSI_HashAlgorithm sigAttrAlgoId;

	if (sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = sig->ctx;
	KSI_ERR_clearErrors(ctx);


	if (inputToAggre == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	rfc = sig->rfc3161;
	if (rfc == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}



	if (KSI_Integer_getUInt64(rfc->tstInfoAlgo) > 0xff || KSI_Integer_getUInt64(rfc->sigAttrAlgo) > 0xff) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Hash algorithm can't be larger than 0xff.");
		goto cleanup;
	} else {
		tstInfoAlgoId = (int)KSI_Integer_getUInt64(rfc->tstInfoAlgo);
		sigAttrAlgoId = (int)KSI_Integer_getUInt64(rfc->sigAttrAlgo);
	}

	res = rfc3161_preSufHasher(ctx, rfc->tstInfoPrefix, rfc->inputHash, rfc->tstInfoSuffix, tstInfoAlgoId, &hsh_tstInfo);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = rfc3161_preSufHasher(ctx, rfc->sigAttrPrefix, hsh_tstInfo, rfc->sigAttrSuffix, sigAttrAlgoId, &hsh_sigAttr);
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

	*inputToAggre = tmp;
	tmp = NULL;

cleanup:

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh_tstInfo);
	KSI_DataHash_free(hsh_sigAttr);
	KSI_DataHash_free(tmp);

	return res;
}

int KSI_Signature_verifyDocument(KSI_Signature *sig, KSI_CTX *ctx, void *doc, size_t doc_len) {
	int res;
	KSI_DataHash *hsh = NULL;

	KSI_HashAlgorithm algo_id = -1;

	KSI_ERR_clearErrors(ctx);
	if (sig == NULL || ctx == NULL || doc == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_Signature_getHashAlgorithm(sig, &algo_id);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_create(ctx, doc, doc_len, algo_id, &hsh);
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

static int initPublicationsFile(KSI_VerificationResult *info, KSI_CTX *ctx) {
	int res = KSI_UNKNOWN_ERROR;

	if (info->publicationsFile == NULL) {
		bool verifyPubFile = (ctx->publicationsFile == NULL);

		res = KSI_receivePublicationsFile(ctx, &info->publicationsFile);
		if (res != KSI_OK) goto cleanup;

		if (verifyPubFile == true) {
			res = KSI_verifyPublicationsFile(ctx, info->publicationsFile);
			if (res != KSI_OK) goto cleanup;
		}
	}

	res = KSI_OK;
cleanup:

	return res;
}

static int verifyInternallyAggregationChain(KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_DataHash *inputHash = NULL;
	int level;
	size_t i;
	int successCount = 0;
	KSI_VerificationStep step = KSI_VERIFY_AGGRCHAIN_INTERNALLY;
	KSI_VerificationResult *info = &sig->verificationResult;
	const KSI_AggregationHashChain *prevChain = NULL;

	/* Aggregate aggregation chains. */
	hsh = NULL;

	/* The aggregation level might not be 0 in case of local aggregation. */
	if (sig->verificationResult.docAggrLevel > 0xff) {
		KSI_pushError(sig->ctx, res = KSI_INVALID_FORMAT, "Aggregation level can't be larger than 0xff.");
		goto cleanup;
	}

	level = (int)sig->verificationResult.docAggrLevel;

	KSI_LOG_info(sig->ctx, "Verifying aggregation hash chain internal consistency.");

	if (sig->rfc3161 != NULL) {
		KSI_LOG_info(sig->ctx, "Using input hash calculated from RFC 3161 for aggregation.");
		res = rfc3161_getInputToAggreChain(sig, &inputHash);
		if (res != KSI_OK) goto cleanup;

		res = rfc3161_verify(sig);
		if (res != KSI_OK){
			res = KSI_VerificationResult_addFailure(info, step, "RFC 3161 does not belong to this aggregation hash chain.");
			goto cleanup;
		}
	}

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

		if (i == 0 && inputHash != NULL){
			if (!KSI_DataHash_equals(inputHash, aggregationChain->inputHash)) {
				KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Input hash from RFC 3161 :", inputHash);
				KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Expected input hash      :", aggregationChain->inputHash);
				res = KSI_VerificationResult_addFailure(info, step, "Aggregation hash chain's input hash does not match with RFC 3161 input hash.");
				goto cleanup;
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
	KSI_DataHash_free(inputHash);

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
	size_t rawSignature_len;
	unsigned char *rawData = NULL;
	size_t rawData_len;
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
		res = KSI_VerificationResult_addFailure(info, step, "Certificate not found.");
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
	bool verifyPubFile = (ctx->publicationsFile == NULL);

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

	if (verifyPubFile == true) {
		res = KSI_verifyPublicationsFile(ctx, pubFile);
		if (res != KSI_OK) goto cleanup;
	}

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
	KSI_DataHash *hsh = NULL;
	KSI_VerificationStep step = KSI_VERIFY_DOCUMENT;
	KSI_VerificationResult *info = &sig->verificationResult;

	if (!sig->verificationResult.verifyDocumentHash) {
		res = KSI_OK;
		goto cleanup;
	}

	KSI_LOG_info(sig->ctx, "Verifying document hash.");
	KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Verifying document hash", sig->verificationResult.documentHash);

	if (sig->rfc3161 != NULL) {
		KSI_LOG_info(sig->ctx, "Document hash is compared with RFC 3161 input hash.");
		res = KSI_RFC3161_getInputHash(sig->rfc3161, &hsh);
		if (res != KSI_OK) goto cleanup;
	} else {
		res = KSI_Signature_getDocumentHash(sig, &hsh);
		if (res != KSI_OK) goto cleanup;
	}


	if (!KSI_DataHash_equals(hsh, sig->verificationResult.documentHash)) {
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Document hash", sig->verificationResult.documentHash);
		KSI_LOG_logDataHash(sig->ctx, KSI_LOG_DEBUG, "Signed   hash", hsh);

		res = KSI_VerificationResult_addFailure(info, step, "Wrong document.");
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
	res = KSI_createExtendRequest(sig->ctx, start, end, &req);
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

int KSI_Signature_verifyInternally(KSI_Signature *sig, KSI_CTX *ctx) {
	return KSI_Signature_verifyPolicy(sig, KSI_VP_INTERNAL, ctx);
}

int KSI_Signature_verifyOffline(KSI_Signature *sig, KSI_CTX *ctx) {
	return KSI_Signature_verifyPolicy(sig, KSI_VP_OFFLINE, ctx);
}

int KSI_Signature_verifyAggregated(KSI_Signature *sig, KSI_CTX *ctx, KSI_uint64_t level) {
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

int KSI_Signature_verifyAggregatedHash(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *rootHash, KSI_uint64_t rootLevel) {
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
	sig->verificationResult.documentHash = KSI_DataHash_ref(rootHash);
	sig->verificationResult.docAggrLevel = rootLevel;
	sig->verificationResult.verifyDocumentHash = true;

	res = KSI_Signature_verifyPolicy(sig, KSI_VP_DOCUMENT, useCtx);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Signature_verifyDataHash(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *docHash) {
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
