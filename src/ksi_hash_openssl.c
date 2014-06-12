#include <openssl/evp.h>

#include "ksi_internal.h"

struct KSI_DataHasher_st {
	/* KSI context */
	KSI_CTX *ctx;

	void *hashContext;
	int algorithm;
};

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

void KSI_DataHasher_free(KSI_DataHasher *hasher) {
	if (hasher != NULL) {
		KSI_free(hasher->hashContext);
		KSI_free(hasher);
	}
}

int KSI_DataHasher_open(KSI_CTX *ctx, int hash_id, KSI_DataHasher **hasher) {
	KSI_ERR err;
	int res;

	KSI_BEGIN(ctx, &err);

	KSI_DataHasher *tmp_hasher = NULL;

	if (hasher == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

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
	int res;

	const EVP_MD *evp_md = NULL;
	void *context = NULL;
	int digest_length;

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

	digest_length = EVP_MD_size(evp_md);

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

int KSI_DataHasher_close(KSI_DataHasher *hasher, KSI_DataHash **data_hash) {
	KSI_ERR err;
	int res;
	KSI_DataHash *hsh = NULL;
	unsigned char *digest = NULL;
	unsigned int digest_length;

	KSI_PRE(&err, hasher != NULL) goto cleanup;
	KSI_PRE(&err, data_hash != NULL) goto cleanup;
	KSI_BEGIN(hasher->ctx, &err);

	digest = KSI_malloc(KSI_getHashLength(hasher->algorithm)); // FIXME! This should handle errors.
	if (digest == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	EVP_DigestFinal(hasher->hashContext, digest, &digest_length);

	res = KSI_DataHash_fromDigest(hasher->ctx, hasher->algorithm, digest, digest_length, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_free(hasher->hashContext);
	hasher->hashContext = NULL;

	*data_hash = hsh;
	hsh = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(digest);
	KSI_DataHash_free(hsh);

	return KSI_RETURN(&err);
}
