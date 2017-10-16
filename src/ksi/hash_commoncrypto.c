/*
 * Copyright 2013-2017 Guardtime, Inc.
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
#include "hash_impl.h"
#include "hash.h"

#if KSI_HASH_IMPL == KSI_IMPL_COMMONCRYPTO

#include <CommonCrypto/CommonCrypto.h>

#define CC_SHA384_CTX CC_SHA512_CTX

#define CC_IMPL(algo) { sizeof(CC_##algo##_CTX), CC_##algo##_DIGEST_LENGTH, (int (*)(void *))CC_##algo##_Init, (int (*)(void *, const void *, CC_LONG))CC_##algo##_Update, (int (*)(unsigned char *, void *))CC_##algo##_Final }
#define CC_IMPL_NA {0, 0, NULL, NULL, NULL}

static const struct {
	size_t ctx_size;
	size_t digest_len;
	int (*init)(void *);
	int (*update)(void *, const void *, CC_LONG);
	int (*final)(unsigned char *, void *);
} cc[] = {
		/** The SHA-1 algorithm. */
		CC_IMPL(SHA1),
		/** The SHA-256 algorithm. */
		CC_IMPL(SHA256),
		/** The RIPEMD-160 algorithm. */
		CC_IMPL_NA,
		/* Deprecated algorithm - do not reuse. */
		CC_IMPL_NA,
		/** The SHA-384 algorithm. */
		CC_IMPL(SHA384),
		/** The SHA-512 algorithm. */
		CC_IMPL(SHA512),
		/* Deprecated algorithm - do not reuse. */
		CC_IMPL_NA,
		/** The SHA3-244 algorithm. */
		CC_IMPL_NA,
		/** The SHA3-256 algorithm. */
		CC_IMPL_NA,
		/** The SHA3-384 algorithm. */
		CC_IMPL_NA,
		/** The SHA3-512 algorithm */
		CC_IMPL_NA,
		/** The SM3 algorithm.*/
		CC_IMPL_NA
};


static int closeExisting(KSI_DataHasher *hasher, KSI_DataHash *data_hash) {
	int res = KSI_UNKNOWN_ERROR;
	size_t hash_length;

	if (hasher == NULL || data_hash == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	/* Make sure the algorithm is supported. */
	if (!KSI_isHashAlgorithmSupported(hasher->algorithm)) {
		KSI_pushError(hasher->ctx, res = KSI_INVALID_ARGUMENT, "Algorithm ID not supported.");
		goto cleanup;
	}

	hash_length = KSI_getHashLength(hasher->algorithm);
	if (hash_length == 0) {
		KSI_pushError(hasher->ctx, res = KSI_UNKNOWN_ERROR, "Error finding digest length.");
		goto cleanup;
	}

	/* Make sure the hash length is the same. */
	if (hash_length != cc[hasher->algorithm].digest_len) {
		KSI_pushError(hasher->ctx, res = KSI_UNKNOWN_ERROR, "Internal hash lengths mismatch.");
		goto cleanup;
	}

	cc[hasher->algorithm].final(data_hash->imprint + 1, hasher->hashContext);

	data_hash->imprint[0] = (0xff & hasher->algorithm);
	data_hash->imprint_length = hash_length + 1;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_isHashAlgorithmSupported(KSI_HashAlgorithm algo_id) {
	return algo_id >= 0 && algo_id < KSI_NUMBER_OF_KNOWN_HASHALGS && cc[algo_id].ctx_size != 0;
}

static void ksi_DataHasher_cleanup(KSI_DataHasher *hasher) {
	if (hasher != NULL) {
		KSI_free(hasher->hashContext);
	}
}

static int ksi_DataHasher_reset(KSI_DataHasher *hasher) {
	int res = KSI_UNKNOWN_ERROR;
	void *context = NULL;

	if (hasher == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	context = hasher->hashContext;
	if (context == NULL) {
		context = KSI_malloc(cc[hasher->algorithm].ctx_size);
		if (context == NULL) {
			KSI_pushError(hasher->ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		hasher->hashContext = context;
	}

	cc[hasher->algorithm].init((void *)context);

	res = KSI_OK;

cleanup:

	return res;
}

static int ksi_DataHasher_add(KSI_DataHasher *hasher, const void *data, size_t data_length) {
	int res = KSI_UNKNOWN_ERROR;

	if (hasher == NULL || data == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	if (data_length > 0) {
		cc[hasher->algorithm].update(hasher->hashContext, data, (CC_LONG)data_length);
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_DataHasher_open(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, KSI_DataHasher **hasher) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHasher *tmp_hasher = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || hasher == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (!KSI_isHashAlgorithmSupported(algo_id)) {
		KSI_pushError(ctx, res = KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	tmp_hasher = KSI_new(KSI_DataHasher);
	if (tmp_hasher == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp_hasher->hashContext = NULL;
	tmp_hasher->ctx = ctx;
	tmp_hasher->algorithm = algo_id;
	tmp_hasher->closeExisting = closeExisting;
	tmp_hasher->isOpen = false;
	tmp_hasher->reset = ksi_DataHasher_reset;
	tmp_hasher->add = ksi_DataHasher_add;
	tmp_hasher->cleanup = ksi_DataHasher_cleanup;

	res = KSI_DataHasher_reset(tmp_hasher);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hasher = tmp_hasher;
	tmp_hasher = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHasher_free(tmp_hasher);

	return res;
}

#endif
