/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#include "internal.h"
#include "hash_impl.h"

#if KSI_HASH_IMPL == KSI_IMPL_OPENSSL

#include <openssl/evp.h>

/**
 * Converts hash function ID from hash chain to OpenSSL identifier
 */
static const EVP_MD *hashAlgorithmToEVP(int hash_id)
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
	KSI_ERR err;
	unsigned int hash_length;

	KSI_PRE(&err, hasher != NULL) goto cleanup;
	KSI_PRE(&err, data_hash != NULL) goto cleanup;
	KSI_BEGIN(hasher->ctx, &err);
	
	if (hasher->algorithm > 0xff) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Algorithm ID too large.");
		goto cleanup;
	}

	hash_length = KSI_getHashLength(hasher->algorithm);
	if (hash_length == 0) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Error finding digest length.");
		goto cleanup;
	}


	EVP_DigestFinal(hasher->hashContext, data_hash->imprint + 1, &data_hash->imprint_length);

	/* Make sure the hash length is the same. */
	if (hash_length != data_hash->imprint_length) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Internal hash lengths mismatch.");
		goto cleanup;
	}

	data_hash->imprint[0] = (0xff & hasher->algorithm);
	data_hash->imprint_length++;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_isHashAlgorithmSupported(int hash_id) {
	return hashAlgorithmToEVP(hash_id) != NULL;
}

void KSI_DataHasher_free(KSI_DataHasher *hasher) {
	if (hasher != NULL) {
		KSI_free(hasher->hashContext);
		KSI_free(hasher);
	}
}

int KSI_DataHasher_open(KSI_CTX *ctx, int hash_id, KSI_DataHasher **hasher) {
	KSI_ERR err;
	int res;
	KSI_DataHasher *tmp_hasher = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, hasher != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (!KSI_isHashAlgorithmSupported(hash_id)) {
		KSI_FAIL(&err, KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	tmp_hasher = KSI_new(KSI_DataHasher);
	if (tmp_hasher == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp_hasher->hashContext = NULL;
	tmp_hasher->ctx = ctx;
	tmp_hasher->algorithm = hash_id;
	tmp_hasher->closeExisting = closeExisting;

	res = KSI_DataHasher_reset(tmp_hasher);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	*hasher = tmp_hasher;
	tmp_hasher = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHasher_free(tmp_hasher);

	return KSI_RETURN(&err);
}


int KSI_DataHasher_reset(KSI_DataHasher *hasher) {
	KSI_ERR err;
	const EVP_MD *evp_md = NULL;
	void *context = NULL;

	KSI_PRE(&err, hasher != NULL) goto cleanup;
	KSI_BEGIN(hasher->ctx, &err);

	evp_md = hashAlgorithmToEVP(hasher->algorithm);
	if (evp_md == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	context = hasher->hashContext;
	if (context == NULL) {
		context = KSI_new(EVP_MD_CTX);
		if (context == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		hasher->hashContext = context;
	} else {
		EVP_MD_CTX_cleanup(context);
	}

	if (!EVP_DigestInit(context, evp_md)) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_DataHasher_add(KSI_DataHasher *hasher, const void *data, size_t data_length) {
	KSI_ERR err;

	KSI_PRE(&err, hasher != NULL) goto cleanup;
	KSI_PRE(&err, data != NULL || data_length == 0) goto cleanup;
	KSI_BEGIN(hasher->ctx, &err);

	if (data_length > 0) {
		EVP_DigestUpdate(hasher->hashContext, data, data_length);
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

#endif
