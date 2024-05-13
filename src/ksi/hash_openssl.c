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

#if KSI_HASH_IMPL == KSI_IMPL_OPENSSL

#include <openssl/evp.h>

#include "impl/hash_impl.h"
#include "hash.h"

#include "openssl_compatibility.h"

static const EVP_MD *hashAlgorithmToEVP(KSI_HashAlgorithm hash_id) {
	switch (hash_id) {
#ifndef OPENSSL_NO_SHA
		case KSI_HASHALG_SHA1:
			return EVP_sha1();
#endif
#ifndef OPENSSL_NO_RMD160
#ifndef OPENSSL_NO_RIPEMD
		case KSI_HASHALG_RIPEMD160:
			return EVP_ripemd160();
#endif
#endif
		case KSI_HASHALG_SHA2_256:
			return EVP_sha256();
#ifndef OPENSSL_NO_SHA512
		case KSI_HASHALG_SHA2_384:
			return EVP_sha384();
		case KSI_HASHALG_SHA2_512:
			return EVP_sha512();
#endif
#ifdef HAVE_EVP_SHA3_256
		case KSI_HASHALG_SHA3_256:
			return EVP_sha3_256();
#endif
#ifdef HAVE_EVP_SHA3_384
		case KSI_HASHALG_SHA3_384:
			return EVP_sha3_384();
#endif
#ifdef HAVE_EVP_SHA3_512
		case KSI_HASHALG_SHA3_512:
			return EVP_sha3_512();
#endif
#ifdef HAVE_EVP_SM3
		case KSI_HASHALG_SM3:
			return EVP_sm3();
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


	EVP_DigestFinal_ex(hasher->hashContext, data_hash->imprint + 1, &tmp);

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

static void ksi_DataHasher_cleanup(KSI_DataHasher *hasher) {
	if (hasher != NULL) {
		if (hasher->hashContext != NULL) {
			KSI_EVP_MD_CTX_cleanup(hasher->hashContext);
		}
		KSI_EVP_MD_CTX_destroy(hasher->hashContext);
		hasher->hashContext = NULL;
	}
}

static int ksi_DataHasher_reset(KSI_DataHasher *hasher) {
	int res = KSI_UNKNOWN_ERROR;
	const EVP_MD *evp_md = NULL;
	EVP_MD_CTX *context = NULL;

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
		context = KSI_EVP_MD_CTX_create();
		if (context == NULL) {
			KSI_pushError(hasher->ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		EVP_MD_CTX_init(context);

		hasher->hashContext = context;
	}

	if (!EVP_DigestInit_ex(context, evp_md, NULL)) {
		KSI_pushError(hasher->ctx, res = KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

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
		EVP_DigestUpdate(hasher->hashContext, data, data_length);
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_DataHasher_open(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, KSI_DataHasher **hasher) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHasher *tmp_hasher = NULL;

	KSI_ERR_clearErrors(ctx);
	if (hasher == NULL) {
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

#ifdef KSI_NATIVE_HMAC

#include <string.h>
#include <openssl/hmac.h>

#include "hmac.h"

/**
* The maximum block size of an algorithm.
*/
#define MAX_BUF_LEN 256

struct KSI_HmacHasher_st {
	/** KSI context. */
	KSI_CTX *ctx;

	/** OpenSSL HMAC context. */
	void* openssl_ctx;

	/** Hash algorithm id for reset. */
	KSI_HashAlgorithm hash_id;

	/** HMAC key for reset. */
	char *key;
};

int KSI_HMAC_create(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, const char *key, const unsigned char *data, size_t data_len, KSI_DataHash **hmac) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HmacHasher *hasher = NULL;
	KSI_DataHash *tmp_hmac = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || hmac == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_HmacHasher_open(ctx, algo_id, key, &hasher);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_HmacHasher_add(hasher, data, data_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_HmacHasher_close(hasher, &tmp_hmac);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hmac = tmp_hmac;
	tmp_hmac = NULL;
	res = KSI_OK;

cleanup:

	KSI_DataHash_free(tmp_hmac);
	KSI_HmacHasher_free(hasher);

	return res;
}

int KSI_HmacHasher_open(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, const char *key, KSI_HmacHasher **hasher) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HmacHasher *tmp_hasher = NULL;

	unsigned int key_len = 0;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || key == NULL || hasher == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	key_len = strlen(key);
	if (key_len == 0 || key_len > 0xffff) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Invalid key length.");
		goto cleanup;
	}

	tmp_hasher = KSI_new(KSI_HmacHasher);
	if (tmp_hasher == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	memset(tmp_hasher, 0, sizeof(KSI_HmacHasher));
	tmp_hasher->ctx = ctx;
	tmp_hasher->openssl_ctx = NULL;
	tmp_hasher->key = NULL;

	tmp_hasher->openssl_ctx = openssl_compatibility_functions.mac_ctx_new();
	if (tmp_hasher->openssl_ctx == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, "Unable to create HMAC context.");
		goto cleanup;
	}

	res = KSI_strdup(key, &tmp_hasher->key);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp_hasher->hash_id = algo_id;
	if (!KSI_isHashAlgorithmSupported(algo_id)) {
		KSI_pushError(ctx, res = KSI_UNKNOWN_HASH_ALGORITHM_ID, "Unsupported hash algorithm");
		goto cleanup;
	}

	res = KSI_HmacHasher_reset(tmp_hasher);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hasher = tmp_hasher;
	tmp_hasher = NULL;
	res = KSI_OK;

cleanup:

	KSI_HmacHasher_free(tmp_hasher);

	return res;
}

int KSI_HmacHasher_reset(KSI_HmacHasher *hasher) {
	int res = KSI_UNKNOWN_ERROR;

	if (hasher == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	if (!openssl_compatibility_functions.mac_ctx_reset(hasher->openssl_ctx, (const unsigned char*)hasher->key, strlen(hasher->key), hashAlgorithmToEVP(hasher->hash_id))) {
		KSI_pushError(hasher->ctx, res = KSI_UNKNOWN_ERROR, "Unable to reset OpenSSL HMAC");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_HmacHasher_add(KSI_HmacHasher *hasher, const void *data, size_t data_length) {
	int res = KSI_UNKNOWN_ERROR;

	if (hasher == NULL || data == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);


	if (!openssl_compatibility_functions.mac_ctx_update(hasher->openssl_ctx, data, data_length)) {
		KSI_pushError(hasher->ctx, res = KSI_UNKNOWN_ERROR, "Unable to update OpenSSL HMAC");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_HmacHasher_close(KSI_HmacHasher *hasher, KSI_DataHash **hmac) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *tmp = NULL;

	unsigned char digest[64];
	size_t digest_len = 0;

	if (hasher == NULL || hmac == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	if (!openssl_compatibility_functions.mac_ctx_final(hasher->openssl_ctx, digest, sizeof(digest), &digest_len)) {
		KSI_pushError(hasher->ctx, res = KSI_UNKNOWN_ERROR, "Unable to finalize OpenSSL HMAC");
		goto cleanup;
	}

	res = KSI_DataHash_fromDigest(hasher->ctx, hasher->hash_id, digest, digest_len, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}


	*hmac = KSI_DataHash_ref(tmp);

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(tmp);

	return res;
}

void KSI_HmacHasher_free(KSI_HmacHasher *hasher) {
	if (hasher != NULL) {
		if (hasher->openssl_ctx != NULL) openssl_compatibility_functions.mac_ctx_free(hasher->openssl_ctx);
		if (hasher->key != NULL) KSI_free(hasher->key);
		KSI_free(hasher);
	}
}


#endif

#endif
