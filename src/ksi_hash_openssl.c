#include <openssl/evp.h>

#include "ksi_internal.h"

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

int KSI_DataHasher_reset(KSI_DataHasher *hasher) {
	KSI_ERR err;
	int res;

	const EVP_MD *evp_md = NULL;
	void *context = NULL;
	int digest_length;

	KSI_PRE(&err, hasher != NULL) goto cleanup;
	KSI_BEGIN(KSI_DataHasher_getCtx(hasher), &err);

	evp_md = hashAlgorithmToEVP(KSI_DataHasher_getAlgorithm(hasher));
	if (evp_md == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	context = KSI_DataHasher_getHahshContext(hasher);
	if (context == NULL) {
		context = KSI_new(EVP_MD_CTX);
		if (context == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		res = KSI_DataHasher_setHashContext(hasher, context);
		KSI_CATCH(&err, res) goto cleanup;

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
	KSI_BEGIN(KSI_DataHasher_getCtx(hasher), &err);

	if (hasher == NULL || KSI_DataHasher_getHahshContext(hasher) == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (data == NULL && data_length != 0) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	EVP_DigestUpdate(KSI_DataHasher_getHahshContext(hasher), data, data_length);

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
	KSI_BEGIN(KSI_DataHasher_getCtx(hasher), &err);

	if (hasher == NULL || KSI_DataHasher_getHahshContext(hasher) == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	digest = KSI_malloc(KSI_getHashLength(KSI_DataHasher_getAlgorithm(hasher))); // FIXME! This should handle errors.
	if (digest == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	EVP_DigestFinal(KSI_DataHasher_getHahshContext(hasher), digest, &digest_length);

	res = KSI_DataHash_fromDigest(KSI_DataHasher_getCtx(hasher), KSI_DataHasher_getAlgorithm(hasher), digest, digest_length, &hsh);

	KSI_free(KSI_DataHasher_getHahshContext(hasher));
	res = KSI_DataHasher_setHashContext(hasher, NULL);
	KSI_CATCH(&err, res) goto cleanup;

	*data_hash = hsh;
	hsh = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(digest);
	KSI_DataHash_free(hsh);

	return KSI_RETURN(&err);
}
