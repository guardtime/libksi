#include "internal.h"

#if KSI_HASH_IMPL == KSI_IMPL_WINAPI

#include <windows.h>
#include <Wincrypt.h>



typedef struct CRYPTO_HASH_CTX_st {
	HCRYPTPROV pt_CSP;		//Crypto Service Provider
	HCRYPTHASH pt_hHash;	//hasher object
	} CRYPTO_HASH_CTX;

struct KSI_DataHasher_st {
	/* KSI context */
	KSI_CTX *ctx;
	
	void *hashContext;	//Mis iganes hasher obj
	int algorithm;
};





static void CRYPTO_HASH_CTX_free(CRYPTO_HASH_CTX *cryptoCtxt){
	if(cryptoCtxt != NULL){
		if(cryptoCtxt->pt_CSP) CryptReleaseContext(cryptoCtxt->pt_CSP, 0);
		if(cryptoCtxt->pt_hHash) CryptDestroyHash(cryptoCtxt->pt_hHash);
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
static const ALG_ID hashAlgorithmToALG_ID(int hash_id)
{
	switch (hash_id) {
		case KSI_HASHALG_SHA1:
			return CALG_SHA1;
		case KSI_HASHALG_SHA2_256:
			return CALG_SHA_256;
		case KSI_HASHALG_SHA2_384:
			return CALG_SHA_384;
		case KSI_HASHALG_SHA2_512:
			return CALG_SHA_512;
		default:
			return -1;
	}
}

int KSI_isHashAlgorithmSupported(int hash_id) {
	return hashAlgorithmToALG_ID(hash_id) != -1;
}


void KSI_DataHasher_free(KSI_DataHasher *hasher) {
	if (hasher != NULL) {
		CRYPTO_HASH_CTX_free((CRYPTO_HASH_CTX*)hasher->hashContext);
		KSI_free(hasher);
	}
}

//Teeb uue hasher obj, kontrollib, kas algoritm on ok ja restardib hasheri.
int KSI_DataHasher_open(KSI_CTX *ctx, int hash_id, KSI_DataHasher **hasher) {
	KSI_ERR err;
	int res;
	KSI_DataHasher *tmp_hasher = NULL;			//Abstract hasher object
	CRYPTO_HASH_CTX *tmp_cryptoCTX = NULL;		//Hasher object helper struct
	HCRYPTPROV tmp_CSP = 0;							//Crypto service provider
	
	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, hasher != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);
	
	/*Test if hash algorithm is valid*/
	if (!KSI_isHashAlgorithmSupported(hash_id)) {
		KSI_FAIL(&err, KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	/*Create new abstract data hasher object*/
	tmp_hasher = KSI_new(KSI_DataHasher);
	if (tmp_hasher == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp_hasher->hashContext = NULL;
	tmp_hasher->ctx = ctx;
	tmp_hasher->algorithm = hash_id;

	/*Create new helper context for crypto api*/
	res = CRYPTO_HASH_CTX_new(&tmp_cryptoCTX);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}
		
	/*Create new crypto service provider (CSP)*/
	if(!CryptAcquireContext(&tmp_CSP, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)){
		char errm[1024];
		snprintf(errm, sizeof(errm), "Wincrypt Error (%d)", GetLastError());
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, errm);
		goto cleanup;
		}
	
	/*Set CSP in helper struct*/
	tmp_cryptoCTX->pt_CSP = tmp_CSP;
	/*Set helper struct in abstract struct*/
	tmp_hasher->hashContext = tmp_cryptoCTX;
	
	res = KSI_DataHasher_reset(tmp_hasher);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}
	
	*hasher = tmp_hasher;
	tmp_hasher = NULL;
	tmp_cryptoCTX = NULL;
	tmp_CSP = 0;
	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHasher_free(tmp_hasher);
	if(tmp_CSP) CryptReleaseContext(tmp_CSP, 0);
	CRYPTO_HASH_CTX_free(tmp_cryptoCTX);
	return KSI_RETURN(&err);
}

int KSI_DataHasher_reset(KSI_DataHasher *hasher) {
	KSI_ERR err;
	ALG_ID msHashAlg = 0;
	CRYPTO_HASH_CTX * pCryptoCTX = NULL;	//Crypto helper struct
	HCRYPTPROV pCSP = 0;					//Crypto service provider
	HCRYPTHASH pTmp_hash = 0;			//Hash object

	KSI_PRE(&err, hasher != NULL) goto cleanup;
	KSI_BEGIN(hasher->ctx, &err);

	/*Shortcuts for pointers*/
	pCryptoCTX = (CRYPTO_HASH_CTX*)hasher->hashContext;
	pCSP = pCryptoCTX->pt_CSP;

	/*Convert hash algorithm into crypto api style*/
	msHashAlg = hashAlgorithmToALG_ID(hasher->algorithm);
	if (msHashAlg == -1) {
		KSI_FAIL(&err, KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	/*If hasher object already exists, destroy one*/
	if(pTmp_hash != 0){
		CryptDestroyHash(pTmp_hash);
		}
	
	/*Create new hasher object*/
	if (!CryptCreateHash(pCSP, msHashAlg, 0,0,&pTmp_hash)) {
		DWORD error = GetLastError();
		printf("Error %i \n", error);
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

	pCryptoCTX->pt_hHash = pTmp_hash;

	pTmp_hash = 0;
	
	KSI_SUCCESS(&err);

cleanup:

	if(pTmp_hash) CryptDestroyHash(pTmp_hash);
	return KSI_RETURN(&err);
}

int KSI_DataHasher_add(KSI_DataHasher *hasher, const void *data, size_t data_length) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	CRYPTO_HASH_CTX * pCryptoCTX = NULL;	//Crypto helper struct
	HCRYPTHASH pHash = 0;			//Hash object
	
	KSI_PRE(&err, hasher != NULL) goto cleanup;
	KSI_PRE(&err, data != NULL || data_length == 0) goto cleanup;
	KSI_BEGIN(hasher->ctx, &err);

	ctx = hasher->ctx;
	
	pCryptoCTX = (CRYPTO_HASH_CTX*)hasher->hashContext;
	pHash = pCryptoCTX->pt_hHash;
	
	if (data_length > 0) {
		if(!CryptHashData(pHash, data, data_length, 0)){
			DWORD error = GetLastError();
			KSI_LOG_debug(ctx, "Cryptoapi: HashData error %i\n", error);
			KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Cryptoapi: Unable to add data to the hash");
			goto cleanup;
			}
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
	DWORD digest_length = 0;
	DWORD digestLenSize = 0;	//The size of digest_length variable
	DWORD hash_length = 0;
	CRYPTO_HASH_CTX * pCryptoCTX = NULL;	//Crypto helper struct
	HCRYPTHASH pHash = 0;				//Hash object

	
	KSI_PRE(&err, hasher != NULL) goto cleanup;
	KSI_PRE(&err, data_hash != NULL) goto cleanup;
	KSI_BEGIN(hasher->ctx, &err);

	pCryptoCTX = (CRYPTO_HASH_CTX*)hasher->hashContext;
	pHash = pCryptoCTX->pt_hHash;
	
	hash_length = KSI_getHashLength(hasher->algorithm);
	if (hash_length == 0) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Error finding digest length.");
		goto cleanup;
	}
	
	digestLenSize = sizeof(digest_length);
	CryptGetHashParam(pHash, HP_HASHSIZE, (BYTE*)&digest_length, &digestLenSize,0);

	/* Make sure the hash length is the same. */
	if (hash_length != digest_length) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Internal hash lengths mismatch.");
		goto cleanup;
	}
	
	digest = KSI_malloc(hash_length);
	if (digest == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	
	/*After final call pHash is can not be used further*/
	CryptGetHashParam(pHash, HP_HASHVAL, digest, &digest_length,0);
	

	res = KSI_DataHash_fromDigest(hasher->ctx, hasher->algorithm, digest, digest_length, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	

	*data_hash = hsh;
	hsh = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(digest);
	KSI_DataHash_free(hsh);
	return KSI_RETURN(&err);
}

#endif
