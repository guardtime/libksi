#include "internal.h"

#if KSI_PKI_TRUSTSTORE_IMPL == KSI_IMPL_OPENSSL

#include <string.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/* Hide the following line to deactivate. */
#define MAGIC_EMAIL "publications@guardtime.com"

static const char *defaultCaFile =
#ifdef OPENSSL_CA_FILE
	OPENSSL_CA_FILE;
#else
	NULL;
#endif

static const char *defaultCaDir =
#ifdef OPENSSL_CA_DIR
	 OPENSSL_CA_DIR;
#else
	NULL;
#endif


static int KSI_PKITruststore_global_initCount = 0;

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

static int openSslGlobal_init(void) {
	if (KSI_PKITruststore_global_initCount++ > 0) {
		/* Nothing to do */
	} else {
		OpenSSL_add_all_digests();
	}

	return KSI_OK;
}

static void openSslGlobal_cleanup(void) {
	if (--KSI_PKITruststore_global_initCount > 0) {
		/* Nothing to do */
	} else {
		EVP_cleanup();
	}
}


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

static int isMallocFailure(void) {
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

int KSI_PKICertificate_fromTlv(KSI_TLV *tlv, KSI_PKICertificate **cert) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;

	KSI_PKICertificate *tmp = NULL;
	const unsigned char *raw = NULL;
	unsigned int raw_len = 0;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, cert != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKICertificate_new(ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*cert = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(raw);

	KSI_PKICertificate_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKICertificate_toTlv(KSI_CTX *ctx, KSI_PKICertificate *cert, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;
	unsigned char *raw = NULL;
	unsigned raw_len = 0;

	KSI_PRE(&err, cert != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKICertificate_serialize(cert, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_setRawValue(tmp, raw, raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(raw);
	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKITruststore_addLookupFile(KSI_PKITruststore *trust, const char *path) {
	KSI_ERR err;
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

int KSI_PKITruststore_addLookupDir(KSI_PKITruststore *trust, const char *path) {
	KSI_ERR err;
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
	KSI_PKITruststore *tmp = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_CTX_registerGlobals(ctx, openSslGlobal_init, openSslGlobal_cleanup);
	KSI_CATCH(&err, res) goto cleanup;

	tmp = KSI_new(KSI_PKITruststore);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->store = NULL;

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
		if (defaultCaFile != NULL) {
			res = KSI_PKITruststore_addLookupFile(tmp, defaultCaFile);
			KSI_CATCH(&err, res) goto cleanup;
		}
		/* Set lookup directory for trusted CA certificates if specified. */
		if (defaultCaDir != NULL) {
			res = KSI_PKITruststore_addLookupDir(tmp, defaultCaDir);
			KSI_CATCH(&err, res) goto cleanup;
		}
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

int KSI_PKISignature_serialize(KSI_PKISignature *sig, unsigned char **raw, unsigned *raw_len) {
	KSI_ERR err;
	unsigned char *tmpOssl = NULL;
	unsigned char *tmp = NULL;
	int len = 0;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	len = i2d_PKCS7(sig->pkcs7, NULL);
	if (len < 0) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	tmp = KSI_calloc((unsigned)len, 1);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmpOssl = tmp;
	i2d_PKCS7(sig->pkcs7, &tmpOssl);

	*raw = tmp;
	*raw_len = (unsigned)len;

	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKISignature_fromTlv(KSI_TLV *tlv, KSI_PKISignature **sig) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;

	KSI_PKISignature *tmp = NULL;
	const unsigned char *raw = NULL;
	unsigned int raw_len = 0;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKISignature_new(ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*sig = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(raw);

	KSI_PKISignature_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKISignature_toTlv(KSI_CTX *ctx, KSI_PKISignature *sig, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;
	unsigned char *raw = NULL;
	unsigned raw_len = 0;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKISignature_serialize(sig, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_setRawValue(tmp, raw, raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(raw);
	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PKISignature_new(KSI_CTX *ctx, const void *raw, unsigned raw_len, KSI_PKISignature **signature) {
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

	if (raw_len > INT_MAX) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Length is greater than INT_MAX");
		goto cleanup;
	}

	pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&raw, (int)raw_len);
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

/**/
int KSI_PKICertificate_new(KSI_CTX *ctx, const void *der, size_t der_len, KSI_PKICertificate **cert) {
	KSI_ERR err;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	KSI_PKICertificate *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, der != NULL) goto cleanup;
	KSI_PRE(&err, der_len > 0) goto cleanup;
	KSI_PRE(&err, cert != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	if (der_len > INT_MAX) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Length is more than MAX_INT");
		goto cleanup;
	}
	bio = BIO_new_mem_buf((void *)der, (int)der_len);
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

int KSI_PKICertificate_serialize(KSI_PKICertificate *cert, unsigned char **raw, unsigned *raw_len) {
	KSI_ERR err;
	unsigned char *tmp_ossl = NULL;
	unsigned char *tmp = NULL;
	int len = 0;

	KSI_PRE(&err, cert != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len != NULL) goto cleanup;
	KSI_BEGIN(cert->ctx, &err);

	len = i2d_X509(cert->x509, NULL);
	if (len < 0) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Unable to serialize certificate.");
		goto cleanup;
	}

	tmp_ossl = OPENSSL_malloc(len);
	if (tmp_ossl == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp = tmp_ossl;
	i2d_X509(cert->x509, &tmp);

	tmp = KSI_calloc((unsigned)len, 1);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	memcpy(tmp, tmp_ossl, (unsigned)len);

	*raw = tmp;
	*raw_len = (unsigned)len;

	tmp = NULL;
	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp);
	if (tmp_ossl != NULL) OPENSSL_free(tmp_ossl);

	return KSI_RETURN(&err);
}

static int extractCertificate(const KSI_PKISignature *signature, X509 **cert) {
	int res = KSI_UNKNOWN_ERROR;
	X509 *signing_cert = NULL;
	STACK_OF(X509) *certs = NULL;

	if (signature == NULL || cert == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	certs = PKCS7_get0_signers(signature->pkcs7, NULL, 0);
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

	return res;
}

static int KSI_PKITruststore_verifySignatureCertificate(const KSI_PKITruststore *pki, const KSI_PKISignature *signature) {
	KSI_ERR err;
	int res;
	X509 *cert = NULL;
	X509_NAME *subj = NULL;
	ASN1_OBJECT *oid = NULL;
	X509_STORE_CTX *storeCtx = NULL;
	char tmp[256];
	const char *magicEmail = NULL;

	KSI_PRE(&err, pki != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_BEGIN(pki->ctx, &err);

	res = extractCertificate(signature, &cert);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_debug(pki->ctx, "Verifying PKI signature certificate.");

	res = KSI_getPublicationCertEmail(pki->ctx, &magicEmail);
	KSI_CATCH(&err, res) goto cleanup;

	if (magicEmail != NULL) {
		KSI_LOG_debug(pki->ctx, "Verifying PKI signature certificate with e-mail address '%s'", magicEmail);

		subj = X509_get_subject_name(cert);
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
		if (strcmp(tmp, magicEmail)) {
			KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, "Wrong subject name.");
			goto cleanup;
		}
	}

	storeCtx = X509_STORE_CTX_new();
	if (storeCtx == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if (!X509_STORE_CTX_init(storeCtx, pki->store, cert,
			signature->pkcs7->d.sign->cert)) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = X509_verify_cert(storeCtx);
	if (res < 0) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}
	if (res != 1) {
		KSI_FAIL(&err, KSI_PKI_CERTIFICATE_NOT_TRUSTED, NULL);
		goto cleanup;
	}

	KSI_LOG_debug(pki->ctx, "PKI signature certificate verified.");

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(magicEmail);

	if (storeCtx != NULL) X509_STORE_CTX_free(storeCtx);
	if (oid != NULL) ASN1_OBJECT_free(oid);

	return KSI_RETURN(&err);
}

int KSI_PKITruststore_verifySignature(KSI_PKITruststore *pki, const unsigned char *data, size_t data_len, const KSI_PKISignature *signature) {
	KSI_ERR err;
	int res;
	BIO *bio = NULL;

	KSI_PRE(&err, pki != NULL) goto cleanup;
	KSI_PRE(&err, data != NULL) goto cleanup;
	KSI_PRE(&err, signature != NULL) goto cleanup;
	KSI_BEGIN(pki->ctx, &err);

	KSI_LOG_debug(pki->ctx, "Starting to verify publications file signature.");

	if (data_len > INT_MAX) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Data too long (more than MAX_INT).");
		goto cleanup;
	}

	bio = BIO_new_mem_buf((void *)data, (int)data_len);
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

	KSI_LOG_debug(pki->ctx, "Signature verified.");

	res = KSI_PKITruststore_verifySignatureCertificate(pki, signature);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	BIO_free(bio);

	return KSI_RETURN(&err);
}

int KSI_PKITruststore_verifyRawSignature(KSI_CTX *ctx, const unsigned char *data, unsigned data_len, const char *algoOid, const unsigned char *signature, unsigned signature_len, const KSI_PKICertificate *certificate) {
	KSI_ERR err;
	int res;
	ASN1_OBJECT* algorithm = NULL;
    EVP_MD_CTX md_ctx;
    X509 *x509 = NULL;
	const EVP_MD *evp_md;
	EVP_PKEY *pubKey = NULL;

	/* Needs to be initialized before jumping to cleanup. */
    EVP_MD_CTX_init(&md_ctx);

    KSI_PRE(&err, data != NULL && data_len > 0) goto cleanup;
	KSI_PRE(&err, signature != NULL && signature_len > 0) goto cleanup;
	KSI_PRE(&err, signature_len < UINT_MAX) goto cleanup;
	KSI_PRE(&err, algoOid != NULL) goto cleanup;
	KSI_PRE(&err, certificate != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	KSI_LOG_debug(ctx, "Verifying PKI signature.");

	x509 = certificate->x509;

	algorithm = OBJ_txt2obj(algoOid, 1);

	if (algorithm == NULL) {
		KSI_LOG_debug(ctx, "Unknown hash algorithm '%s'.", algoOid);
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
    	KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
    	goto cleanup;
    }

    if (!EVP_VerifyUpdate(&md_ctx, (unsigned char *)data, data_len)) {
    	KSI_FAIL(&err, KSI_CRYPTO_FAILURE, NULL);
    	goto cleanup;
    }

    res = EVP_VerifyFinal(&md_ctx, (unsigned char *)signature, signature_len, pubKey);
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

#endif
