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

#include "ksi.h"

#include "internal.h"

#include "impl/signature_impl.h"

int KSI_Signature_getHashAlgorithm(const KSI_Signature *sig, KSI_HashAlgorithm *algo_id) {
	KSI_DataHash *hsh = NULL;
	int res;
	KSI_HashAlgorithm tmp = KSI_HASHALG_INVALID_VALUE;

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

	*algo_id = tmp;

	res = KSI_OK;

cleanup:

	KSI_nofree(hsh);

	return res;
}

int KSI_Signature_createDataHasher(const KSI_Signature *sig, KSI_DataHasher **hsr) {
	int res;
	KSI_DataHasher *tmp = NULL;
	KSI_HashAlgorithm algo_id = KSI_HASHALG_INVALID_VALUE;

	if (sig == NULL || hsr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	res = KSI_Signature_getHashAlgorithm(sig, &algo_id);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_open(sig->ctx, algo_id, &tmp);
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

int KSI_Signature_verifyWithPolicy(KSI_Signature *sig, const KSI_DataHash *docHsh, KSI_uint64_t rootLevel,
		const KSI_Policy *policy, KSI_VerificationContext *verificationContext) {
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;

	if (sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(sig->ctx);

	if (!KSI_IS_VALID_TREE_LEVEL(rootLevel)) {
		KSI_pushError(sig->ctx, res = KSI_INVALID_FORMAT, "Aggregation level can't be larger than 0xff.");
		goto cleanup;
	}

	res = KSI_VerificationContext_init(&context, sig->ctx);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, NULL);
		goto cleanup;
	}

	if (verificationContext == NULL) {
		context.documentHash = docHsh;
		context.docAggrLevel = rootLevel;
	} else {
		context = *verificationContext;
	}
	context.signature = sig;

	res = KSI_SignatureVerifier_verify(policy, &context, &result);
	if (res != KSI_OK) {
		KSI_pushError(sig->ctx, res, "Verification of signature aborted due to an error.");
		goto cleanup;
	}

	if (result->finalResult.resultCode != KSI_VER_RES_OK) {
		res = KSI_VERIFICATION_FAILURE;
		KSI_pushError(sig->ctx, res, "Verification of signature failed.");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_PolicyVerificationResult_free(result);

	return res;
}

int KSI_Signature_verifyDocument(KSI_Signature *sig, KSI_CTX *ctx, const void *doc, size_t doc_len) {
	int res;
	KSI_DataHash *hsh = NULL;
	KSI_HashAlgorithm algo_id = KSI_HASHALG_INVALID_VALUE;

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

	res = KSI_Signature_verifyWithPolicy(sig, hsh, 0, KSI_VERIFICATION_POLICY_GENERAL, NULL);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:
	KSI_DataHash_free(hsh);

	return res;
}

int KSI_Signature_fromFileWithPolicy(KSI_CTX *ctx, const char *fileName, const KSI_Policy *policy, KSI_VerificationContext *context, KSI_Signature **sig) {
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

	res = KSI_Signature_parseWithPolicy(ctx, raw, (unsigned)raw_len, policy, context, &tmp);
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

int KSI_Signature_createAggregated(KSI_CTX *ctx, KSI_DataHash *rootHash, KSI_uint64_t rootLevel, KSI_Signature **signature) {
	return KSI_Signature_signAggregated(ctx, rootHash, rootLevel, signature);
}


int KSI_Signature_signWithPolicy(KSI_CTX *ctx, KSI_DataHash *hsh, const KSI_Policy *policy, KSI_VerificationContext *context, KSI_Signature **signature) {
	return KSI_Signature_signAggregatedWithPolicy(ctx, hsh, 0, policy, context, signature);
}

int KSI_Signature_create(KSI_CTX *ctx, KSI_DataHash *hsh, KSI_Signature **signature) {
	return KSI_Signature_sign(ctx, hsh, signature);
}
