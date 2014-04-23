#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "ksi_internal.h"

struct KSI_PKICertificate_st {
	KSI_CTX *ctx;
	X509 *x509;
};

struct KSI_PKITruststore_st {

};

static int KSI_MD2hashAlg(EVP_MD *hash_alg) {
	if (hash_alg == EVP_sha224())
		return KSI_HASHALG_SHA2_224;
	if (hash_alg == EVP_sha256())
		return KSI_HASHALG_SHA2_256;
#ifndef OPENSSL_NO_SHA
	if (hash_alg == EVP_sha1())
		return KSI_HASHALG_SHA1;
#endif
#ifndef OPENSSL_NO_RIPEMD
	if (hash_alg == EVP_ripemd160())
		return KSI_HASHALG_RIPEMD160;
#endif
#ifndef OPENSSL_NO_SHA512
	if (hash_alg == EVP_sha384())
		return KSI_HASHALG_SHA2_384;
	if (hash_alg == EVP_sha512())
		return KSI_HASHALG_SHA2_512;
#endif
	return -1;
}

/**/
void KSI_PKICertificate_free(KSI_PKICertificate *cert) {
	if (cert != NULL) {
		if (cert->x509 != NULL) X509_free(cert->x509);
		KSI_free(cert);
	}
}

/**/
int KSI_PKICertificate_new(KSI_CTX *ctx, const void *der, int der_len, KSI_PKICertificate **cert) {
	KSI_ERR err;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	KSI_PKICertificate *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, der != NULL) goto cleanup;
	KSI_PRE(&err, der_len > 0) goto cleanup;
	KSI_PRE(&err, cert != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	bio = BIO_new_mem_buf((void *)der, der_len);
	if (bio == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	x509 = d2i_X509_bio(bio, NULL);
	if (x509 == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Invalid certificate.");
		goto cleanup;
	}

	tmp = KSI_new(KSI_PKICertificate);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	tmp->ctx = ctx;
	tmp->x509 = x509;
	x509 = NULL;

	*cert = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	if (bio != NULL) BIO_free(bio);
	if (x509 != NULL) X509_free(x509);

	return KSI_RETURN(&err);
}

int KSI_PKICertificate_find(KSI_CTX *ctx, const unsigned char *certId, int certId_len, const KSI_PKICertificate **cert) {
	// TODO!
	return KSI_UNKNOWN_ERROR;
}

int KSI_PKITruststore_validateSignature(unsigned char *data, unsigned int data_len, const char *algoOid, unsigned char *signature, unsigned int signature_len, const KSI_PKICertificate *cert) {
	KSI_ERR err;
	int res;
	ASN1_OBJECT* algorithm = NULL;
    EVP_MD_CTX md_ctx;

	const EVP_MD *evp_md;

	EVP_PKEY *pubKey = NULL;

	KSI_PRE(&err, data != NULL && data_len > 0) goto cleanup;
	KSI_PRE(&err, algoOid != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL && signature_len > 0) goto cleanup;
	KSI_PRE(&err, cert != NULL) goto cleanup;
	KSI_BEGIN(cert->ctx, &err);

	KSI_LOG_debug(cert->ctx, "Verifying PKI signature.");

	algorithm = OBJ_txt2obj(algoOid, 1);
	if (algorithm == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Unknown hash algorithm.");
		goto cleanup;
	}

	evp_md = EVP_get_digestbyobj(algorithm);
	if (evp_md == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Unsupported algorithm.");
		goto cleanup;
	}

	if (KSI_MD2hashAlg((EVP_MD *)evp_md) < 0) {
		KSI_FAIL(&err, KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	pubKey = X509_get_pubkey(cert->x509);
	if (pubKey == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Failed to read public key.");
		goto cleanup;
	}


    EVP_MD_CTX_init(&md_ctx);

    if (!EVP_VerifyInit(&md_ctx, evp_md)) {
    	printf("Error\n");
    	goto cleanup;
    }

    if (!EVP_VerifyUpdate(&md_ctx, data, data_len)) {
    	printf("Error\n");
    	goto cleanup;
    }

    res = EVP_VerifyFinal(&md_ctx, signature, signature_len, pubKey);
    if (res < 0) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
    }
    if (res == 0) {
		KSI_FAIL(&err, KSI_INVALID_PKI_SIGNATURE, NULL);
		goto cleanup;
    }

	KSI_LOG_debug(cert->ctx, "PKI signature verified successfully.");

	KSI_SUCCESS(&err);

cleanup:

	EVP_MD_CTX_cleanup(&md_ctx);
	if (algorithm != NULL) ASN1_OBJECT_free(algorithm);
	if (pubKey != NULL) EVP_PKEY_free(pubKey);

	return KSI_RETURN(&err);
}

int KSI_PKITruststore_global_init() {
	OpenSSL_add_all_digests();

	return KSI_OK;
}

