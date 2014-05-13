#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "ksi_internal.h"

/* Hide the following line to deactivate. */
#define MAGIC_EMAIL "publications@guardtime.com"

struct KSI_PKITruststore_st {
	KSI_CTX *ctx;
	X509_STORE *store;
};

struct KSI_PKICertificate_st {
	KSI_CTX *ctx;
	X509 *x509;
};

struct KSI_PKISignature_st {
	KSI_CTX *ctx;
	PKCS7 *pkcs7;
};

struct KSI_PKISignatureValidator_st {
	EVP_MD_CTX md_ctx;
	const EVP_MD *evp_md;

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

static int isMallocFailure() {
	/* Check if the earliest reason was malloc failure. */
	if (ERR_GET_REASON(ERR_peek_error()) == ERR_R_MALLOC_FAILURE) {
		return 1;
	}

	/* The following statement is not strictly necessary because main reason
	 * is the earliest one and there are usually nested fake reasons like
	 * ERR_R_NESTED_ASN1_ERROR added later (for traceback). However, it can
	 * be useful if error stack was not properly cleared before failed
	 * operation and there are no abovementioned fake reason codes present. */
	if (ERR_GET_REASON(ERR_peek_last_error()) == ERR_R_MALLOC_FAILURE) {
		return 1;
	}

	return 0;
}

void KSI_PKITruststore_free(KSI_PKITruststore *trust) {
	if (trust != NULL) {
		if (trust->store != NULL) X509_STORE_free(trust->store);
		KSI_free(trust);
	}
}

int KSI_PKITruststore_addLookupFile(KSI_PKITruststore *trust, const char *path) {
	KSI_ERR err;
	int res;
	X509_LOOKUP *lookup = NULL;

	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_PRE(&err, path != NULL) goto cleanup;
	KSI_BEGIN(trust->ctx, &err);

	lookup = X509_STORE_add_lookup(trust->store, X509_LOOKUP_file());
	if (lookup == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if (!X509_LOOKUP_load_file(lookup, path, X509_FILETYPE_PEM)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int GTTruststore_addLookupDir(KSI_PKITruststore *trust, const char *path) {
	KSI_ERR err;
	int res;
	X509_LOOKUP *lookup = NULL;

	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_PRE(&err, path != NULL) goto cleanup;
	KSI_BEGIN(trust->ctx, &err);

	lookup = X509_STORE_add_lookup(trust->store, X509_LOOKUP_hash_dir());
	if (lookup == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if (!X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_PEM)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_PKITruststore_new(KSI_CTX *ctx, int setDefaults, KSI_PKITruststore **trust) {
	KSI_ERR err;
	int res;
	KSI_PKITruststore *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_PKITruststore);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->store = X509_STORE_new();
	if (tmp->store == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if (setDefaults) {
		/* Set system default paths. */
		if (!X509_STORE_set_default_paths(tmp->store)) {
			KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
			goto cleanup;
		}

		/* Set lookup file for trusted CA certificates if specified. */
#ifdef OPENSSL_CA_FILE
		res = GTTruststore_addLookupFile(OPENSSL_CA_FILE);
		if (res != GT_OK) {
			goto cleanup;
		}
#endif

	/* Set lookup directory for trusted CA certificates if specified. */
#ifdef OPENSSL_CA_DIR
		res = GTTruststore_addLookupDir(OPENSSL_CA_DIR);
		if (res != GT_OK) {
			goto cleanup;
		}
#endif
	}

	*trust = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_PKITruststore_free(tmp);

	return KSI_RETURN(&err);
}

/**/
void KSI_PKICertificate_free(KSI_PKICertificate *cert) {
	if (cert != NULL) {
		if (cert->x509 != NULL) X509_free(cert->x509);
		KSI_free(cert);
	}
}

void KSI_PKISignature_free(KSI_PKISignature *sig) {
	if (sig != NULL) {
		if (sig->pkcs7 != NULL) PKCS7_free(sig->pkcs7);
		KSI_free(sig);
	}
}

int KSI_PKISignature_new(KSI_CTX *ctx, const void *raw, int raw_len, KSI_PKISignature **signature) {
	KSI_ERR err;
	KSI_PKISignature *tmp = NULL;
	PKCS7 *pkcs7 = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len > 0) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_PKISignature);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	tmp->ctx = ctx;
	tmp->pkcs7 = NULL;

	pkcs7 = d2i_PKCS7(NULL, &raw, raw_len);
	if (pkcs7 == NULL) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	tmp->pkcs7 = pkcs7;

	*signature = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_PKISignature_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKICertificate_fromSignature(KSI_PKISignature *sig, KSI_PKICertificate **cert) {
	KSI_ERR err;
	int res;
	KSI_PKICertificate *tmp = NULL;

	X509 *signing_cert = NULL;
	STACK_OF(X509) *certs = NULL;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	certs = PKCS7_get0_signers(sig->pkcs7, NULL, 0);
	if (certs == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Unable to get signers from signature.");
		goto cleanup;
	}

	if (sk_X509_num(certs) != 1) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Too many signing certs.");
		goto cleanup;
	}

	signing_cert = sk_X509_delete(certs, 0);

	tmp = KSI_new(KSI_PKICertificate);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = sig->ctx;
	tmp->x509 = signing_cert;
	signing_cert = NULL;

	*cert = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	if (signing_cert != NULL) X509_free(signing_cert);
	if (certs != NULL) sk_X509_free(certs);
	KSI_PKICertificate_free(tmp);

	return KSI_RETURN(&err);
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
	KSI_PKICertificate_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKICertificate_find(KSI_CTX *ctx, const unsigned char *certId, int certId_len, const KSI_PKICertificate **cert) {
	// TODO!
	return KSI_UNKNOWN_ERROR;
}

static int extractCertificate(const unsigned char *data, unsigned int data_len, X509 **cert) {
	int res = KSI_UNKNOWN_ERROR;
	PKCS7 *signature = NULL;
	X509 *signing_cert = NULL;
	STACK_OF(X509) *certs = NULL;

	if (data == NULL || cert == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	signature = d2i_PKCS7(NULL, &data, data_len);
	if (signature == NULL) {
		res = KSI_INVALID_PKI_SIGNATURE;
		goto cleanup;
	}

	certs = PKCS7_get0_signers(signature, NULL, 0);
	if (certs == NULL) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	if (sk_X509_num(certs) != 1) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	signing_cert = sk_X509_delete(certs, 0);

	*cert = signing_cert;
	signing_cert = NULL;

	res = KSI_OK;

cleanup:

	if (certs != NULL) sk_X509_free(certs);
	X509_free(signing_cert);
	PKCS7_free(signature);

	return res;
}

int KSI_PKITruststore_validateSignatureCertificate(KSI_CTX *ctx, KSI_PKISignature *signature) {
	KSI_ERR err;
	int res;
	X509 *cert = NULL;
	X509_NAME *subj = NULL;
	ASN1_OBJECT *oid = NULL;
	X509_STORE_CTX *store_ctx = NULL;
	char tmp[256];

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

#ifdef MAGIC_EMAIL
//	subj = X509_get_subject_name(certt->x509);
	if (subj == NULL) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to get subject name from certificate.");
		goto cleanup;
	}
	oid = OBJ_txt2obj("1.2.840.113549.1.9.1", 1);
	if (oid == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	res = X509_NAME_get_text_by_OBJ(subj, oid, tmp, sizeof(tmp));
	if (res < 0) {
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, NULL);
		goto cleanup;
	}
	if (!strcmp(tmp) != 0) {
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, "Wrong subject name.");
		goto cleanup;
	}
#endif

	store_ctx = X509_STORE_CTX_new();
	if (store_ctx == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

/*	if (!X509_STORE_CTX_init(store_ctx, global_truststore, certt->x509,
			certt->chain)) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}*/

	res = X509_verify_cert(store_ctx);
	if (res < 0) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}
	if (res != 1) {
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, NULL);
		goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_PKITruststore_validateSignature(KSI_CTX *ctx, const unsigned char *data, unsigned int data_len, const KSI_PKISignature *signature) {
	KSI_ERR err;
	int res;
	BIO *bio = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, data != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);


	bio = BIO_new_mem_buf((void *)data, data_len);
	if (bio == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = PKCS7_verify(signature->pkcs7, NULL, NULL, bio, NULL, PKCS7_NOVERIFY);
	if (res < 0) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to verify signature.");
		goto cleanup;
	}
	if (res != 1) {
		KSI_FAIL(&err, KSI_INVALID_PKI_SIGNATURE, "PKI Signature not verified.");
		goto cleanup;
	}

	// TODO! Validate certificate
//	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);



cleanup:

	BIO_free(bio);

	return KSI_RETURN(&err);
}

int KSI_PKITruststore_validateSignatureWithCert(KSI_CTX *ctx, unsigned char *data, unsigned int data_len, const char *algoOid, unsigned char *signature, unsigned int signature_len, const KSI_PKICertificate *certificate) {
	KSI_ERR err;
	int res;
	ASN1_OBJECT* algorithm = NULL;
    EVP_MD_CTX md_ctx;
    X509 *x509 = NULL;

	const EVP_MD *evp_md;

	EVP_PKEY *pubKey = NULL;

	KSI_PRE(&err, data != NULL && data_len > 0) goto cleanup;
	KSI_PRE(&err, signature != NULL && signature_len > 0) goto cleanup;
	KSI_PRE(&err, algoOid != NULL) goto cleanup;
	KSI_PRE(&err, certificate != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	KSI_LOG_debug(ctx, "Verifying PKI signature.");
    EVP_MD_CTX_init(&md_ctx);

	x509 = certificate->x509;

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

	pubKey = X509_get_pubkey(x509);
	if (pubKey == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Failed to read public key.");
		goto cleanup;
	}



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

	KSI_LOG_debug(certificate->ctx, "PKI signature verified successfully.");

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

