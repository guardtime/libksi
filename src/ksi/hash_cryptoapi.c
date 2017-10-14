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

#if KSI_HASH_IMPL == KSI_IMPL_CRYPTOAPI

#include <windows.h>
#include <Wincrypt.h>

typedef struct CRYPTO_HASH_CTX_st {
	HCRYPTPROV pt_CSP;		/**< Crypto Service Provider. */
	HCRYPTHASH pt_hHash;	/**< Hasher object. */
} CRYPTO_HASH_CTX;

static void CRYPTO_HASH_CTX_free(CRYPTO_HASH_CTX *cryptoCtxt){
	if (cryptoCtxt != NULL){
		/* All hash objects that have been created by using a specific CSP must be  destroyed before that CSP
		 * handle is released with the CryptReleaseContext function. */
		if (cryptoCtxt->pt_hHash) CryptDestroyHash(cryptoCtxt->pt_hHash);
		if (cryptoCtxt->pt_CSP) CryptReleaseContext(cryptoCtxt->pt_CSP, 0);
		KSI_free(cryptoCtxt);
	}
}

static int CRYPTO_HASH_CTX_new(CRYPTO_HASH_CTX **cryptoCTX){
	CRYPTO_HASH_CTX *tmp_crypto_ctx = NULL;
	int res = KSI_UNKNOWN_ERROR;

	tmp_crypto_ctx = KSI_new(CRYPTO_HASH_CTX);
	if (tmp_crypto_ctx == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
		}

	tmp_crypto_ctx->pt_CSP = 0;
	tmp_crypto_ctx->pt_hHash = 0;
	*cryptoCTX = tmp_crypto_ctx;
	tmp_crypto_ctx = NULL;
	res = KSI_OK;

cleanup:

	CRYPTO_HASH_CTX_free(tmp_crypto_ctx);
	return res;
}

/**
 * Converts hash function ID from hash chain to crypto api identifier
 */
static const ALG_ID hashAlgorithmToALG_ID(KSI_HashAlgorithm algo_id)
{
	switch (algo_id) {
		case KSI_HASHALG_SHA1:
			return CALG_SHA1;
		case KSI_HASHALG_SHA2_256:
			return CALG_SHA_256;
		case KSI_HASHALG_SHA2_384:
			return CALG_SHA_384;
		case KSI_HASHALG_SHA2_512:
			return CALG_SHA_512;
		default:
			return 0;
	}
}

static int closeExisting(KSI_DataHasher *hasher, KSI_DataHash *data_hash) {
	int res = KSI_UNKNOWN_ERROR;
	DWORD digest_length = 0;

	/* The size of digest_length variable. */
	DWORD digestLenSize = 0;
	DWORD hash_length = 0;

	/* Crypto helper structure. */
	CRYPTO_HASH_CTX * pCryptoCTX = NULL;

	/* Hash object. */
	HCRYPTHASH pHash = 0;

	if (hasher == NULL || data_hash == NULL){
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	pCryptoCTX = (CRYPTO_HASH_CTX*)hasher->hashContext;
	pHash = pCryptoCTX->pt_hHash;

	hash_length = KSI_getHashLength(hasher->algorithm);
	if (hash_length == 0) {
		KSI_pushError(hasher->ctx, res = KSI_UNKNOWN_ERROR, "Error finding digest length.");
		goto cleanup;
	}

	digestLenSize = sizeof(digest_length);
	CryptGetHashParam(pHash, HP_HASHSIZE, (BYTE*)&digest_length, &digestLenSize,0);

	/* Make sure the hash length is the same. */
	if (hash_length != digest_length) {
		KSI_pushError(hasher->ctx, res = KSI_UNKNOWN_ERROR, "Internal hash lengths mismatch.");
		goto cleanup;
	}

	/* After final call pHash is can not be used further. */
	CryptGetHashParam(pHash, HP_HASHVAL, data_hash->imprint + 1, &digest_length, 0);

	if (hasher->algorithm > 0xff) {
		KSI_pushError(hasher->ctx, res = KSI_INVALID_FORMAT, "Hash algorithm ID is larger than one byte.");
		goto cleanup;
	}

	data_hash->imprint[0] = (unsigned char) hasher->algorithm;
	data_hash->imprint_length = digest_length + 1;

	res = KSI_OK;

cleanup:

	return res;
}


int KSI_isHashAlgorithmSupported(KSI_HashAlgorithm algo_id) {
	return hashAlgorithmToALG_ID(algo_id) != 0;
}


static void ksi_DataHasher_cleanup(KSI_DataHasher *hasher) {
	if (hasher != NULL) {
		CRYPTO_HASH_CTX_free((CRYPTO_HASH_CTX*)hasher->hashContext);
	}
}

static int ksi_DataHasher_reset(KSI_DataHasher *hasher) {
	int res = KSI_UNKNOWN_ERROR;
	ALG_ID msHashAlg = 0;

	/* Crypto helper struct. */
	CRYPTO_HASH_CTX * pCryptoCTX = NULL;

	/* Crypto service porvider. */
	HCRYPTPROV pCSP = 0;

	/* Hash object. */
	HCRYPTHASH pTmp_hash = 0;

	if (hasher == NULL){
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(hasher->ctx);

	/* Shortcuts for pointers. */
	pCryptoCTX = (CRYPTO_HASH_CTX*)hasher->hashContext;
	pCSP = pCryptoCTX->pt_CSP;

	/* Convert hash algorithm into crypto api style. */
	msHashAlg = hashAlgorithmToALG_ID(hasher->algorithm);
	if (msHashAlg == 0) {
		KSI_pushError(hasher->ctx, res = KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	/* If hash object already exists, destroy it. */
	if (pCryptoCTX->pt_hHash != 0){
		CryptDestroyHash(pCryptoCTX->pt_hHash);
		pCryptoCTX->pt_hHash = 0;
	}

	/* Create new hasher object. */
	if (!CryptCreateHash(pCSP, msHashAlg, 0,0,&pTmp_hash)) {
		DWORD error = GetLastError();
		KSI_LOG_debug(hasher->ctx, "Cryptoapi: Create hash error %i\n", error);
		KSI_pushError(hasher->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	pCryptoCTX->pt_hHash = pTmp_hash;
	pTmp_hash = 0;

	res = KSI_OK;

cleanup:

	if (pTmp_hash) CryptDestroyHash(pTmp_hash);

	return res;
}

static int ksi_DataHasher_add(KSI_DataHasher *hasher, const void *data, size_t data_length) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;

	/* Crypto helper struct. */
	CRYPTO_HASH_CTX * pCryptoCTX = NULL;

	/* Hash object. */
	HCRYPTHASH pHash = 0;

	if (hasher == NULL || data == NULL){
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = hasher->ctx;
	KSI_ERR_clearErrors(ctx);

	pCryptoCTX = (CRYPTO_HASH_CTX*)hasher->hashContext;
	pHash = pCryptoCTX->pt_hHash;

	if(data_length > UINT_MAX){
		KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Cryptoapi: Unable to add mote than UINT_MAX data to the hasher.");
		goto cleanup;
	}

	if (!CryptHashData(pHash, data, (DWORD)data_length, 0)){
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "Cryptoapi: HashData error %i\n", error);
		KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Cryptoapi: Unable to add data to the hash");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_DataHasher_open(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, KSI_DataHasher **hasher) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHasher *tmp_hasher = NULL;
	CRYPTO_HASH_CTX *tmp_cryptoCTX = NULL;
	HCRYPTPROV tmp_CSP = 0;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || hasher == NULL){
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Test if the hash algorithm is valid. */
	if (!KSI_isHashAlgorithmSupported(algo_id)) {
		KSI_pushError(ctx, res = KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	/* Create new abstract data hasher object. */
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

	/* Create new helper context for crypto api. */
	res = CRYPTO_HASH_CTX_new(&tmp_cryptoCTX);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Create new crypto service provider (CSP). */
	if (!CryptAcquireContext(&tmp_CSP, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
		char errm[1024];
		KSI_snprintf(errm, sizeof(errm), "Wincrypt Error (%d)", GetLastError());
		KSI_pushError(ctx, res = KSI_CRYPTO_FAILURE, errm);
		goto cleanup;
	}

	/* Set CSP in helper struct. */
	tmp_cryptoCTX->pt_CSP = tmp_CSP;

	/* Set helper struct in abstract struct. */
	tmp_hasher->hashContext = tmp_cryptoCTX;

	res = KSI_DataHasher_reset(tmp_hasher);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hasher = tmp_hasher;
	tmp_hasher = NULL;
	tmp_cryptoCTX = NULL;
	tmp_CSP = 0;

	res = KSI_OK;

cleanup:

	KSI_DataHasher_free(tmp_hasher);
	if (tmp_CSP) CryptReleaseContext(tmp_CSP, 0);
	CRYPTO_HASH_CTX_free(tmp_cryptoCTX);

	return res;
}

#endif
