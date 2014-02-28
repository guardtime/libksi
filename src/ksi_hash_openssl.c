#include <openssl/evp.h>

#include "ksi_internal.h"
#include "ksi_hash.h"

/**
 * Converts hash function ID from hash chain to OpenSSL identifier
 */
static const EVP_MD *hashAlgorithmToEVP(int hash_id)
{
	switch (KSI_fixHashAlgorithm(hash_id)) {
#ifndef OPENSSL_NO_SHA
		case KSI_HASHALG_SHA1:
			return EVP_sha1();
#endif
#ifndef OPENSSL_NO_RIPEMD
		case KSI_HASHALG_RIPEMD160:
			return EVP_ripemd160();
#endif
		case KSI_HASHALG_SHA224:
			return EVP_sha224();
		case KSI_HASHALG_SHA256:
			return EVP_sha256();
#ifndef OPENSSL_NO_SHA512
		case KSI_HASHALG_SHA384:
			return EVP_sha384();
		case KSI_HASHALG_SHA512:
			return EVP_sha512();
#endif
		default:
			return NULL;
	}
}

int KSI_DataHasher_reset(KSI_DataHasher *hasher) {
	KSI_ERR err;

	const EVP_MD *evp_md = NULL;
	void *context = NULL;
	int digest_length;

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
	}

	digest_length = EVP_MD_size(evp_md);

	if (!EVP_DigestInit(context, evp_md)) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	hasher->hashContext = context;
	hasher->digest_length = digest_length;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_DataHasher_open(KSI_CTX *ctx, int hash_algorithm, KSI_DataHasher **hasher) {
	KSI_ERR err;
	int res;

	KSI_BEGIN(ctx, &err);

	KSI_DataHasher *tmp_hasher = NULL;

	if (hasher == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (!KSI_isSupportedHashAlgorithm(hash_algorithm)) {
		KSI_FAIL(&err, KSI_UNTRUSTED_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	tmp_hasher = KSI_new(KSI_DataHasher);
	if (tmp_hasher == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	tmp_hasher->hashContext = NULL;
	tmp_hasher->ctx = ctx;
	tmp_hasher->algorithm = hash_algorithm;

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

int KSI_DataHasher_add(KSI_DataHasher *hasher, const unsigned char* data, size_t data_length) {
	KSI_ERR err;

	KSI_BEGIN(hasher->ctx, &err);

	if (hasher == NULL || hasher->hashContext == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}
	if (data == NULL && data_length != 0) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	EVP_DigestUpdate(hasher->hashContext, data, data_length);

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_DataHasher_close(KSI_DataHasher *hasher, KSI_DataHash **data_hash) {
	KSI_ERR err;
	KSI_DataHash *tmp_data_hash = NULL;
	unsigned char* tmp_hash = NULL;
	unsigned int digest_length;

	KSI_BEGIN(hasher->ctx, &err);

	if (hasher == NULL || hasher->hashContext == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp_hash = KSI_malloc(hasher->digest_length);
	if (tmp_hash == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	EVP_DigestFinal(hasher->hashContext, tmp_hash, &digest_length);

	/* Create a data hash object */
	tmp_data_hash = KSI_new(KSI_DataHash);
	if (tmp_data_hash == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp_data_hash->algorithm = hasher->algorithm;
	tmp_data_hash->digest_length = digest_length;
	tmp_data_hash->digest = tmp_hash;

	tmp_hash = NULL;

	KSI_free(hasher->hashContext);
	hasher->hashContext = NULL;

	*data_hash = tmp_data_hash;
	tmp_data_hash = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(tmp_data_hash);

	return KSI_RETURN(&err);
}

