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

#include "internal.h"
#include "hash_impl.h"
#include "hash.h"

#if KSI_HASH_IMPL == KSI_IMPL_OPENSSL

#include <openssl/evp.h>

/**
 * Converts hash function ID from hash chain to OpenSSL identifier
 */
static const EVP_MD *hashAlgorithmToEVP(KSI_HashAlgorithm hash_id)
{
	switch (hash_id) {
#ifndef OPENSSL_NO_SHA
		case KSI_HASHALG_SHA1:
			return EVP_sha1();
#endif
#ifndef OPENSSL_NO_RIPEMD
		case KSI_HASHALG_RIPEMD160:
			return EVP_ripemd160();
#endif
		case KSI_HASHALG_SHA2_224:
			return EVP_sha224();
		case KSI_HASHALG_SHA2_256:
			return EVP_sha256();
#ifndef OPENSSL_NO_SHA512
		case KSI_HASHALG_SHA2_384:
			return EVP_sha384();
		case KSI_HASHALG_SHA2_512:
			return EVP_sha512();
#endif
		default:
			return NULL;
	}
}

static int closeExisting(KSI_DataHasher *hasher, KSI_DataHash *data_hash) {
	int res = KSI_UNKNOWN_ERROR;
	size_t hash_length;
	unsigned tmp;

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


	EVP_DigestFinal(hasher->hashContext, data_hash->imprint + 1, &tmp);

	/* Make sure the hash length is the same. */
	if (hash_length != tmp) {
		KSI_pushError(hasher->ctx, res = KSI_UNKNOWN_ERROR, "Internal hash lengths mismatch.");
		goto cleanup;
	}

	data_hash->imprint[0] = (0xff & hasher->algorithm);
	data_hash->imprint_length = hash_length + 1;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_isHashAlgorithmSupported(KSI_HashAlgorithm algo_id) {
	return hashAlgorithmToEVP(algo_id) != NULL;
}

void KSI_DataHasher_free(KSI_DataHasher *hasher) {
	if (hasher != NULL) {
		KSI_free(hasher->hashContext);
		KSI_free(hasher);
	}
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


int KSI_DataHasher_reset(KSI_DataHasher *hasher) {
	int res = KSI_UNKNOWN_ERROR;
	const EVP_MD *evp_md = NULL;
	void *context = NULL;

	if (hasher == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	evp_md = hashAlgorithmToEVP(hasher->algorithm);
	if (evp_md == NULL) {
		KSI_pushError(hasher->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	context = hasher->hashContext;
	if (context == NULL) {
		context = KSI_new(EVP_MD_CTX);
		if (context == NULL) {
			KSI_pushError(hasher->ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		hasher->hashContext = context;
	} else {
		EVP_MD_CTX_cleanup(context);
	}

	if (!EVP_DigestInit(context, evp_md)) {
		KSI_pushError(hasher->ctx, res = KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_DataHasher_add(KSI_DataHasher *hasher, const void *data, size_t data_length) {
	int res = KSI_UNKNOWN_ERROR;

	if (hasher == NULL || data == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	if (data_length > 0) {
		EVP_DigestUpdate(hasher->hashContext, data, data_length);
	}

	res = KSI_OK;

cleanup:

	return res;
}

#endif
