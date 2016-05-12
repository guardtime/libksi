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

#if KSI_PKI_TRUSTSTORE_IMPL == KSI_IMPL_OPENSSL

#include <string.h>
#include <limits.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/pkcs7.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "pkitruststore.h"
#include "ctx_impl.h"
#include "compatibility.h"
#include "crc32.h"


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

int KSI_PKITruststore_addLookupFile(KSI_PKITruststore *trust, const char *path) {
	int res;
	X509_LOOKUP *lookup = NULL;

	if (trust == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(trust->ctx);

	if (path == NULL) {
		KSI_pushError(trust->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	lookup = X509_STORE_add_lookup(trust->store, X509_LOOKUP_file());
	if (lookup == NULL) {
		KSI_pushError(trust->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}


	if (!X509_LOOKUP_load_file(lookup, path, X509_FILETYPE_PEM)) {
		KSI_pushError(trust->ctx, res = KSI_INVALID_FORMAT, "Unable to add PKI Truststore lookup file.");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_PKITruststore_addLookupDir(KSI_PKITruststore *trust, const char *path) {
	int res = KSI_INVALID_ARGUMENT;
	X509_LOOKUP *lookup = NULL;

	if (trust == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(trust->ctx);

	if (path == NULL) {
		KSI_pushError(trust->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	lookup = X509_STORE_add_lookup(trust->store, X509_LOOKUP_hash_dir());
	if (lookup == NULL) {
		KSI_pushError(trust->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if (!X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_PEM)) {
		KSI_pushError(trust->ctx, res = KSI_INVALID_FORMAT, "Unable to add PKI Truststore lookup directory.");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_PKITruststore_registerGlobals(KSI_CTX *ctx) {
	return KSI_CTX_registerGlobals(ctx, openSslGlobal_init, openSslGlobal_cleanup);
}

int KSI_PKITruststore_new(KSI_CTX *ctx, int setDefaults, KSI_PKITruststore **trust) {
	KSI_PKITruststore *tmp = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || trust == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_PKITruststore_registerGlobals(ctx);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_PKITruststore);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->store = NULL;

	tmp->store = X509_STORE_new();
	if (tmp->store == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if (setDefaults) {
		/* Set system default paths. */
		if (!X509_STORE_set_default_paths(tmp->store)) {
			KSI_pushError(ctx, res = KSI_CRYPTO_FAILURE, "Unable to set PKI Truststore default paths.");
			goto cleanup;
		}

		/* Set lookup file for trusted CA certificates if specified. */
		if (defaultCaFile != NULL) {
			res = KSI_PKITruststore_addLookupFile(tmp, defaultCaFile);
			if (res != KSI_OK) {
				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}
		}

		/* Set lookup directory for trusted CA certificates if specified. */
		if (defaultCaDir != NULL) {
			res = KSI_PKITruststore_addLookupDir(tmp, defaultCaDir);
			if (res != KSI_OK) {
				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}
		}
	}

	*trust = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_PKITruststore_free(tmp);

	return res;
}

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

int KSI_PKISignature_serialize(KSI_PKISignature *sig, unsigned char **raw, size_t *raw_len) {
	int res;
	unsigned char *tmpOssl = NULL;
	unsigned char *tmp = NULL;
	int len = 0;

	if (sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(sig->ctx);

	if (raw == NULL || raw_len == NULL) {
		KSI_pushError(sig->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	len = i2d_PKCS7(sig->pkcs7, NULL);
	if (len < 0) {
		KSI_pushError(sig->ctx, res = KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	tmp = KSI_calloc((size_t) len, 1);
	if (tmp == NULL) {
		KSI_pushError(sig->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmpOssl = tmp;
	i2d_PKCS7(sig->pkcs7, &tmpOssl);

	*raw = tmp;
	*raw_len = (size_t) len;

	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);

	return res;
}

int KSI_PKISignature_new(KSI_CTX *ctx, const void *raw, size_t raw_len, KSI_PKISignature **signature) {
	int res;
	KSI_PKISignature *tmp = NULL;
	PKCS7 *pkcs7 = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || raw == NULL || raw_len == 0 || signature == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_PKISignature);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	tmp->ctx = ctx;
	tmp->pkcs7 = NULL;

	if (raw_len > INT_MAX) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Length is greater than INT_MAX.");
		goto cleanup;
	}

	pkcs7 = d2i_PKCS7(NULL, (const unsigned char **)&raw, (int)raw_len);
	if (pkcs7 == NULL) {
		KSI_pushError(ctx, res = KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	tmp->pkcs7 = pkcs7;

	*signature = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_PKISignature_free(tmp);

	return res;
}

/**/
int KSI_PKICertificate_new(KSI_CTX *ctx, const void *der, size_t der_len, KSI_PKICertificate **cert) {
	int res;
	X509 *x509 = NULL;
	BIO *bio = NULL;
	KSI_PKICertificate *tmp = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || der == NULL || der_len == 0 || cert == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	if (der_len > INT_MAX) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Length is more than MAX_INT.");
		goto cleanup;
	}
	bio = BIO_new_mem_buf((void *)der, (int)der_len);
	if (bio == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	x509 = d2i_X509_bio(bio, NULL);
	if (x509 == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Invalid certificate.");
		goto cleanup;
	}

	tmp = KSI_new(KSI_PKICertificate);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	tmp->ctx = ctx;
	tmp->x509 = x509;
	x509 = NULL;

	*cert = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	if (bio != NULL) BIO_free(bio);
	if (x509 != NULL) X509_free(x509);
	KSI_PKICertificate_free(tmp);

	return res;
}

int KSI_PKICertificate_serialize(KSI_PKICertificate *cert, unsigned char **raw, size_t *raw_len) {
	int res;
	unsigned char *tmp_ossl = NULL;
	unsigned char *tmp = NULL;
	int len = 0;

	if (cert == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(cert->ctx);

	if (raw == NULL || raw_len == 0) {
		KSI_pushError(cert->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	len = i2d_X509(cert->x509, NULL);
	if (len < 0) {
		KSI_pushError(cert->ctx, res = KSI_CRYPTO_FAILURE, "Unable to serialize certificate.");
		goto cleanup;
	}

	tmp_ossl = OPENSSL_malloc(len);
	if (tmp_ossl == NULL) {
		KSI_pushError(cert->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp = tmp_ossl;
	i2d_X509(cert->x509, &tmp);

	tmp = KSI_calloc((size_t) len, 1);
	if (tmp == NULL) {
		KSI_pushError(cert->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	memcpy(tmp, tmp_ossl, (size_t) len);

	*raw = tmp;
	*raw_len = (size_t) len;

	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_free(tmp);
	if (tmp_ossl != NULL) OPENSSL_free(tmp_ossl);

	return res;
}

static time_t ASN1_GetTimeT(ASN1_TIME* time){
	struct tm t;
	const char* str = (const char*) time->data;
	size_t i = 0;

	if (time == NULL) return 0;
	memset(&t, 0, sizeof(t));

	if (time->type == V_ASN1_UTCTIME) {/* two digit year */
		t.tm_year = (str[i++] - '0') * 10;
		t.tm_year += (str[i++] - '0');
		if (t.tm_year < 70)
			t.tm_year += 100;
	} else if (time->type == V_ASN1_GENERALIZEDTIME) {/* four digit year */
		t.tm_year = (str[i++] - '0') * 1000;
		t.tm_year+= (str[i++] - '0') * 100;
		t.tm_year+= (str[i++] - '0') * 10;
		t.tm_year+= (str[i++] - '0');
		t.tm_year -= 1900;
	}
	t.tm_mon  = (str[i++] - '0') * 10;
	t.tm_mon += (str[i++] - '0') - 1; // -1 since January is 0 not 1.
	t.tm_mday = (str[i++] - '0') * 10;
	t.tm_mday+= (str[i++] - '0');
	t.tm_hour = (str[i++] - '0') * 10;
	t.tm_hour+= (str[i++] - '0');
	t.tm_min  = (str[i++] - '0') * 10;
	t.tm_min += (str[i++] - '0');
	t.tm_sec  = (str[i++] - '0') * 10;
	t.tm_sec += (str[i++] - '0');

	/* Note: we did not adjust the time based on time zone information */
	return KSI_CalendarTimeToUnixTime(&t);
}

#define NOT_AFTER 0
#define NOT_BEFORE 1
#define ISSUER 0
#define SUBJECT 1

static int pki_certificate_getValidityTime(const KSI_PKICertificate *cert, int type, KSI_uint64_t *time) {
	int res;
	ASN1_TIME *t = NULL;


	if (cert == NULL || cert->x509 == NULL  || time == NULL){
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (type == NOT_AFTER) {
		t = X509_get_notAfter(cert->x509);
	} else {
		t = X509_get_notBefore(cert->x509);
	}

	*time = ASN1_GetTimeT(t);

	res = KSI_OK;

cleanup:

	return res;
}

static int pki_certificate_getValidityNotBefore(const KSI_PKICertificate *cert, KSI_uint64_t *time) {
	return pki_certificate_getValidityTime(cert, NOT_BEFORE, time);
}

static int pki_certificate_getValidityNotAfter(const KSI_PKICertificate *cert, KSI_uint64_t *time) {
	return pki_certificate_getValidityTime(cert, NOT_AFTER, time);
}

static int pki_certificate_getValidityState(const KSI_PKICertificate *cert, int *isExpired) {
	int res;
	KSI_uint64_t cert_time_notBefore = 0;
	KSI_uint64_t cert_time_notAfter = 0;
	KSI_uint64_t current_time = 0;
	time_t timer = 0;
	int state = 0;

	if (cert == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	timer = time(NULL);
	if (timer == -1) {
		res = KSI_UNKNOWN_ERROR;
		goto cleanup;
	}

	current_time = timer;


	res = pki_certificate_getValidityNotBefore(cert, &cert_time_notBefore);
	if (res != KSI_OK) goto cleanup;

	res = pki_certificate_getValidityNotAfter(cert, &cert_time_notAfter);
	if (res != KSI_OK) goto cleanup;

	if (current_time < cert_time_notBefore) {
		state = -1;
	} else if (current_time >= cert_time_notBefore && current_time <= cert_time_notAfter) {
		state = 0;
	} else {
		state = 1;
	}

	*isExpired = state;
	res = KSI_OK;

cleanup:

	return res;
}

static char* ksi_pki_certificate_getString_by_oid(KSI_PKICertificate *cert, int type, const char *OID, char *buf, size_t buf_len) {
	char *ret = NULL;
	ASN1_OBJECT *oid = NULL;
	X509_NAME *name = NULL;

	if(cert == NULL || cert->x509 == NULL || OID == NULL || buf == NULL || buf_len == 0) {
		goto cleanup;
	}

	oid = OBJ_txt2obj(OID, 1);

	if (type == ISSUER) {
		name = X509_get_issuer_name(cert->x509);
	} else {
		name = X509_get_subject_name(cert->x509);
	}

	if (name == NULL) {
		goto cleanup;
	}

	if (X509_NAME_get_text_by_OBJ(name, oid, buf, (int)buf_len) < 0) {
		goto cleanup;
	}

	ret = buf;

cleanup:

	if (oid != NULL) ASN1_OBJECT_free(oid);

return ret;
}

static char* pki_certificate_issuerOIDToString(KSI_PKICertificate *cert, const char *OID, char *buf, size_t buf_len) {
	return ksi_pki_certificate_getString_by_oid(cert, ISSUER, OID ,buf, buf_len);
}

static char* pki_certificate_subjectOIDToString(KSI_PKICertificate *cert, const char *OID, char *buf, size_t buf_len) {
	return ksi_pki_certificate_getString_by_oid(cert, SUBJECT, OID ,buf, buf_len);
}

static int pki_certificate_getSerialNumber(const KSI_PKICertificate *cert, KSI_OctetString **serial_number) {
	int res;
	ASN1_INTEGER *integer = NULL;
	KSI_OctetString *tmp;

	if (cert == NULL || cert->x509 == NULL  || serial_number == NULL){
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	integer = X509_get_serialNumber(cert->x509);
	if (integer == NULL) {
		res = KSI_UNKNOWN_ERROR;
		KSI_pushError(cert->ctx, res, "Unable to extract PKI certificate serial number.");
	}

	res = KSI_OctetString_new(cert->ctx, integer->data, integer->length, &tmp);
	if (res != KSI_OK) goto cleanup;

	*serial_number = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_OctetString_free(tmp);

	return res;
}

int KSI_PKISignature_extractCertificate(const KSI_PKISignature *signature, KSI_PKICertificate **cert) {
	int res = KSI_UNKNOWN_ERROR;
	X509 *signing_cert = NULL;
	X509 *copy_of_signing_cert = NULL;
	STACK_OF(X509) *certs = NULL;
	KSI_PKICertificate *tmp = NULL;

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
	copy_of_signing_cert = X509_dup(signing_cert);
	if (copy_of_signing_cert == NULL) {
		res = KSI_CRYPTO_FAILURE;
		goto cleanup;
	}

	tmp = KSI_new(KSI_PKICertificate);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = signature->ctx;
	tmp->x509 = copy_of_signing_cert;
	*cert = tmp;

	tmp = NULL;
	copy_of_signing_cert = NULL;
	res = KSI_OK;

cleanup:

	if (certs != NULL) sk_X509_free(certs);
	X509_free(copy_of_signing_cert);
	KSI_PKICertificate_free(tmp);

	return res;
}

static int KSI_PKITruststore_verifySignatureCertificate(const KSI_PKITruststore *pki, const KSI_PKISignature *signature) {
	int res;
	X509 *cert = NULL;
	X509_STORE_CTX *storeCtx = NULL;
	KSI_PKICertificate *ksi_pki_cert = NULL;

	if (pki == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(pki->ctx);

	if (signature == NULL) {
		KSI_pushError(pki->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_PKISignature_extractCertificate(signature, &ksi_pki_cert);
	if (res != KSI_OK) {
		KSI_pushError(pki->ctx, res, NULL);
		goto cleanup;
	}

	cert = ksi_pki_cert->x509;

	KSI_LOG_debug(pki->ctx, "Verifying PKI signature certificate.");

	storeCtx = X509_STORE_CTX_new();
	if (storeCtx == NULL) {
		KSI_pushError(pki->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if (!X509_STORE_CTX_init(storeCtx, pki->store, cert,
			signature->pkcs7->d.sign->cert)) {
		KSI_pushError(pki->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = X509_verify_cert(storeCtx);
	if (res < 0) {
		KSI_pushError(pki->ctx, res = KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}
	if (res != 1) {
		char msg[1024];
		int x509_err = X509_STORE_CTX_get_error(storeCtx);
		KSI_snprintf(msg, sizeof(msg), "Unable to verify certificate: (error = %d) %s", x509_err, X509_verify_cert_error_string(x509_err));
		KSI_pushError(pki->ctx, res = KSI_PKI_CERTIFICATE_NOT_TRUSTED, msg);
		goto cleanup;
	}

	KSI_LOG_debug(pki->ctx, "PKI signature certificate verified.");

	res = KSI_OK;

cleanup:

	KSI_PKICertificate_free(ksi_pki_cert);
	if (storeCtx != NULL) X509_STORE_CTX_free(storeCtx);

	return res;
}

static int pki_truststore_verifyCertificateConstraints(const KSI_PKITruststore *pki, const KSI_PKISignature *signature, KSI_CertConstraint *certConstraints) {
	size_t i;
	int res;
	KSI_PKICertificate *ksi_pki_cert = NULL;
	X509 *cert = NULL;
	X509_NAME *subj = NULL;
	ASN1_OBJECT *oid = NULL;
	char tmp[256];

	if (pki == NULL || pki->ctx == NULL || signature == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(pki->ctx);

	/* If publications file does not have certificate constraints configured, use context based constraints. */
	if (certConstraints == NULL) {
		certConstraints = pki->ctx->certConstraints;
	}

	/* Make sure the publications file verification constraints are configured. */
	if (certConstraints == NULL || certConstraints[0].oid == NULL) {
		KSI_pushError(pki->ctx, res = KSI_PUBFILE_VERIFICATION_NOT_CONFIGURED, NULL);
		goto cleanup;
	}

	res = KSI_PKISignature_extractCertificate(signature, &ksi_pki_cert);
	if (res != KSI_OK) {
		KSI_pushError(pki->ctx, res, NULL);
		goto cleanup;
	}

	cert = ksi_pki_cert->x509;

	KSI_LOG_debug(pki->ctx, "Verifying PKI signature certificate constraints.");

	subj = X509_get_subject_name(cert);
	if (subj == NULL) {
		KSI_pushError(pki->ctx, res = KSI_CRYPTO_FAILURE, "Unable to get subject name from certificate.");
		goto cleanup;
	}

	for (i = 0; certConstraints[i].oid != NULL; i++) {
		KSI_CertConstraint *ptr = &certConstraints[i];

		KSI_LOG_info(pki->ctx, "%d. Verifying PKI signature certificate with OID: '%s' expected value: '%s'.", i + 1, ptr->oid, ptr->val);

		oid = OBJ_txt2obj(ptr->oid, 1);
		if (oid == NULL) {
			KSI_pushError(pki->ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		res = X509_NAME_get_text_by_OBJ(subj, oid, tmp, sizeof(tmp));
		if (res < 0) {
			KSI_LOG_debug(pki->ctx, "Value for OID: '%s' does not exist.", ptr->oid);
			KSI_pushError(pki->ctx, res = KSI_PKI_CERTIFICATE_NOT_TRUSTED, NULL);
			goto cleanup;
		}

		if (strcmp(tmp, ptr->val)) {
			KSI_LOG_debug(pki->ctx, "Unexpected value: '%s' for OID: '%s'.", tmp, ptr->oid);
			KSI_pushError(pki->ctx, res = KSI_PKI_CERTIFICATE_NOT_TRUSTED, "Unexpected OID value for PKI Certificate constraint.");
			goto cleanup;
		}

		ASN1_OBJECT_free(oid);
		oid = NULL;
	}
	KSI_LOG_debug(pki->ctx, "PKI signature certificate constraints verified.");
	res = KSI_OK;

cleanup:

	KSI_PKICertificate_free(ksi_pki_cert);
	if (oid != NULL) ASN1_OBJECT_free(oid);

	return res;
}

static int pki_truststore_verifySignature(KSI_PKITruststore *pki, const unsigned char *data, size_t data_len, const KSI_PKISignature *signature) {
	int res;
	BIO *bio = NULL;

	if (pki == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(pki->ctx);

	if (data == NULL || signature == NULL) {
		KSI_pushError(pki->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	KSI_LOG_debug(pki->ctx, "Starting to verify publications file signature.");

	if (data_len > INT_MAX) {
		KSI_pushError(pki->ctx, res = KSI_INVALID_ARGUMENT, "Data too long (more than MAX_INT).");
		goto cleanup;
	}

	bio = BIO_new_mem_buf((void *)data, (int)data_len);
	if (bio == NULL) {
		KSI_pushError(pki->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = PKCS7_verify(signature->pkcs7, NULL, NULL, bio, NULL, PKCS7_NOVERIFY);
	if (res < 0) {
		KSI_pushError(pki->ctx, res = KSI_CRYPTO_FAILURE, "Unable to verify signature.");
		goto cleanup;
	}
	if (res != 1) {
		char msg[1024];
		char buf[1024];
		ERR_error_string_n(res, buf, sizeof(buf));
		KSI_snprintf(msg, sizeof(msg), "PKI Signature not verified: %s", buf);
		KSI_pushError(pki->ctx, res = KSI_INVALID_PKI_SIGNATURE, msg);
		goto cleanup;
	}

	KSI_LOG_debug(pki->ctx, "Signature verified.");

	res = KSI_PKITruststore_verifySignatureCertificate(pki, signature);
	if (res != KSI_OK) {
		KSI_pushError(pki->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	BIO_free(bio);

	return res;
}

int KSI_PKITruststore_verifyPKISignature(KSI_PKITruststore *pki, const unsigned char *data, size_t data_len, const KSI_PKISignature *signature, KSI_CertConstraint *certConstraints) {
	int res = KSI_UNKNOWN_ERROR;

	if (pki == NULL || pki->ctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = pki_truststore_verifySignature(pki, data, data_len, signature);
	if (res != KSI_OK) {
		KSI_pushError(pki->ctx, res, "Publications file not trusted.");
		goto cleanup;
	}

	res = pki_truststore_verifyCertificateConstraints(pki, signature, certConstraints);
	if (res != KSI_OK) {
		KSI_pushError(pki->ctx, res, "PKI certificates not trusted.");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_PKITruststore_verifySignature(KSI_PKITruststore *pki, const unsigned char *data, size_t data_len, const KSI_PKISignature *signature) {
	int res;
	BIO *bio = NULL;

	if (pki == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(pki->ctx);

	if (data == NULL || signature == NULL) {
		KSI_pushError(pki->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	KSI_LOG_debug(pki->ctx, "Starting to verify publications file signature.");

	if (data_len > INT_MAX) {
		KSI_pushError(pki->ctx, res = KSI_INVALID_ARGUMENT, "Data too long (more than MAX_INT).");
		goto cleanup;
	}

	bio = BIO_new_mem_buf((void *)data, (int)data_len);
	if (bio == NULL) {
		KSI_pushError(pki->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = PKCS7_verify(signature->pkcs7, NULL, NULL, bio, NULL, PKCS7_NOVERIFY);
	if (res < 0) {
		KSI_pushError(pki->ctx, res = KSI_CRYPTO_FAILURE, "Unable to verify signature.");
		goto cleanup;
	}
	if (res != 1) {
		char msg[1024];
		char buf[1024];
		ERR_error_string_n(res, buf, sizeof(buf));
		KSI_snprintf(msg, sizeof(msg), "PKI Signature not verified: %s", buf);
		KSI_pushError(pki->ctx, res = KSI_INVALID_PKI_SIGNATURE, msg);
		goto cleanup;
	}

	KSI_LOG_debug(pki->ctx, "Signature verified.");

	res = KSI_PKITruststore_verifySignatureCertificate(pki, signature);
	if (res != KSI_OK) {
		KSI_pushError(pki->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	BIO_free(bio);

	return res;
}

int KSI_PKITruststore_verifyRawSignature(KSI_CTX *ctx, const unsigned char *data, size_t data_len, const char *algoOid, const unsigned char *signature, size_t signature_len, const KSI_PKICertificate *certificate) {
	int res;
	ASN1_OBJECT* algorithm = NULL;
	EVP_MD_CTX md_ctx;
	X509 *x509 = NULL;
	const EVP_MD *evp_md;
	EVP_PKEY *pubKey = NULL;

	/* Needs to be initialized before jumping to cleanup. */
	EVP_MD_CTX_init(&md_ctx);

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || data == NULL || signature == NULL || algoOid == NULL || certificate == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (signature_len >= UINT_MAX) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Signature length is more than UINT_MAX.");
		goto cleanup;
	}

	KSI_LOG_debug(ctx, "Verifying PKI signature.");

	x509 = certificate->x509;

	algorithm = OBJ_txt2obj(algoOid, 1);

	if (algorithm == NULL) {
		KSI_LOG_debug(ctx, "Unknown hash algorithm '%s'.", algoOid);
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Unknown hash algorithm.");
		goto cleanup;
	}

	evp_md = EVP_get_digestbyobj(algorithm);
	if (evp_md == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Unsupported algorithm.");
		goto cleanup;
	}

	if (KSI_MD2hashAlg((EVP_MD *)evp_md) < 0) {
		KSI_pushError(ctx, res = KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	pubKey = X509_get_pubkey(x509);
	if (pubKey == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Failed to read public key.");
		goto cleanup;
	}

	if (!EVP_VerifyInit(&md_ctx, evp_md)) {
		KSI_pushError(ctx, res = KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	if (!EVP_VerifyUpdate(&md_ctx, (unsigned char *)data, data_len)) {
		KSI_pushError(ctx, res = KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}

	res = EVP_VerifyFinal(&md_ctx, (unsigned char *)signature, (unsigned)signature_len, pubKey);
	if (res < 0) {
		KSI_pushError(ctx, res = KSI_CRYPTO_FAILURE, NULL);
		goto cleanup;
	}
	if (res == 0) {
		KSI_pushError(ctx, res = KSI_INVALID_PKI_SIGNATURE, NULL);
		goto cleanup;
	}

	KSI_LOG_debug(certificate->ctx, "PKI signature verified successfully.");

	res = KSI_OK;

cleanup:

	EVP_MD_CTX_cleanup(&md_ctx);
	if (algorithm != NULL) ASN1_OBJECT_free(algorithm);
	if (pubKey != NULL) EVP_PKEY_free(pubKey);

	return res;
}

/**
 * OID description array must have the following format:
 * [OID][short name][long name][alias 1][..][alias N][NULL]
 * where OID, short and long name are mandatory. Array must end with NULL.
 */
static char *OID_EMAIL[] = {KSI_CERT_EMAIL, "E", "email", "e-mail", "e_mail", "emailAddress", NULL};
static char *OID_COMMON_NAME[] = {KSI_CERT_COMMON_NAME, "CN", "common name", "common_name", NULL};
static char *OID_COUNTRY[] = {KSI_CERT_COUNTRY, "C", "country", NULL};
static char *OID_ORGANIZATION[] = {KSI_CERT_ORGANIZATION, "O", "org", "organization", NULL};

static char **OID_INFO[] = {OID_EMAIL, OID_COMMON_NAME, OID_COUNTRY, OID_ORGANIZATION, NULL};

static const char *ksi_getShortDescriptionStringByOID(const char *OID) {
	unsigned i = 0;

	if (OID == NULL) return NULL;

	while (OID_INFO[i] != NULL) {
		if (strcmp(OID_INFO[i][0], OID) == 0) return OID_INFO[i][1];
		i++;
	}

	return NULL;
}

static char* pki_certificate_nameToString(KSI_PKICertificate *cert, int type, char *buf, size_t buf_len) {
	char *ret = NULL;
	const char *OID[] = {KSI_CERT_EMAIL, KSI_CERT_COMMON_NAME, KSI_CERT_ORGANIZATION, KSI_CERT_COUNTRY, NULL};
	unsigned i = 0;
	char tmp[1024];
	size_t count;
	char *strn = NULL;
	size_t elements_defined = 0;

	if (cert == NULL || buf == NULL || buf_len == 0 || buf_len > INT_MAX) {
		goto cleanup;
	}

	count = 0;
	while(OID[i] != NULL) {
		if (type == ISSUER) {
			strn = pki_certificate_issuerOIDToString(cert, OID[i], tmp, sizeof(tmp));
		} else {
			strn = pki_certificate_subjectOIDToString(cert, OID[i], tmp, sizeof(tmp));
		}

		if (strn == tmp) {
			count += KSI_snprintf(buf + count, buf_len - count, "%s%s=%s",
					elements_defined == 0 ? "" : " ",
					ksi_getShortDescriptionStringByOID(OID[i]), tmp);

			elements_defined++;
		}

		i++;
	}

	ret = buf;

cleanup:

	return ret;
}

static char* pki_certificate_issuerToString(KSI_PKICertificate *cert, char *buf, size_t buf_len) {
	return pki_certificate_nameToString(cert, ISSUER, buf, buf_len);
}

static char* pki_certificate_subjectToString(KSI_PKICertificate *cert, char *buf, size_t buf_len) {
	return pki_certificate_nameToString(cert, SUBJECT, buf, buf_len);
}

static int pki_certificate_calculateCRC32(KSI_PKICertificate *cert, KSI_OctetString **crc) {
	int res;
	KSI_OctetString *tmp = NULL;
	unsigned long ID;
	unsigned char buf[4];
	unsigned char *raw = NULL;
	size_t raw_len;
	KSI_CTX *ctx = NULL;

	if (cert == NULL || crc == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = cert->ctx;
	if (ctx == NULL) {
		res = KSI_UNKNOWN_ERROR;
		goto cleanup;
	}

	res = KSI_PKICertificate_serialize(cert, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, "Unable to serialize PKI certificate.");
		goto cleanup;
	}

	ID = KSI_crc32(raw, raw_len, 0);

	buf[0] = 0xff & (ID >> 24);
	buf[1] = 0xff & (ID >> 16);
	buf[2] = 0xff & (ID >> 8);
	buf[3] = 0xff & (ID >> 0);

	res = KSI_OctetString_new(ctx, buf, sizeof(buf), &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*crc = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_free(raw);
	KSI_OctetString_free(tmp);

	return res;
}

char* KSI_PKICertificate_toString(KSI_PKICertificate *cert, char *buf, size_t buf_len){
	int res;
	char *ret = NULL;
	char subjectName[1024];
	char issuerName[1024];
	char ID[1024];
	char serial[1024];
	char date_before[64];
	char date_after[64];
	KSI_uint64_t int_notBefore;
	KSI_uint64_t int_notAfter;
	KSI_Integer *notBefore = NULL;
	KSI_Integer *notAfter = NULL;
	KSI_CTX *ctx = NULL;
	KSI_OctetString *serial_number = NULL;
	KSI_OctetString *crc32 = NULL;
	int state;
	const char *stateString = NULL;

	if (cert == NULL || buf == NULL || buf_len == 0) {
		return NULL;
	}

	ctx = cert->ctx;
	if (ctx == NULL){
		return NULL;
	}

	if (pki_certificate_issuerToString(cert, issuerName, sizeof(issuerName)) == NULL) {
		goto cleanup;
	}

	if (pki_certificate_subjectToString(cert, subjectName, sizeof(subjectName)) == NULL) {
		goto cleanup;
	}

	res = pki_certificate_getValidityNotBefore(cert, &int_notBefore);
	if (res != KSI_OK) goto cleanup;

	res = pki_certificate_getValidityNotAfter(cert, &int_notAfter);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(ctx, int_notBefore, &notBefore);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(ctx, int_notAfter, &notAfter);
	if (res != KSI_OK) goto cleanup;

	if (KSI_Integer_toDateString(notBefore, date_before, sizeof(date_before)) == NULL) goto cleanup;
	if (KSI_Integer_toDateString(notAfter, date_after, sizeof(date_after)) == NULL) goto cleanup;

	res = pki_certificate_calculateCRC32(cert, &crc32);
	if (res != KSI_OK) goto cleanup;

	res = pki_certificate_getSerialNumber(cert, &serial_number);
	if (res != KSI_OK) goto cleanup;

	if (KSI_OctetString_toString(crc32, ':', ID, sizeof(ID)) == NULL) {
		goto cleanup;
	}

	if (KSI_OctetString_toString(serial_number, ':', serial, sizeof(serial)) == NULL) {
		goto cleanup;
	}

	res = pki_certificate_getValidityState(cert, &state);
	if (res != KSI_OK) goto cleanup;

	switch(state) {
		case -1: stateString = "invalid"; break;
		case 0: stateString = "valid"; break;
		case 1: stateString = "expired"; break;
		default: stateString = "state unknown"; break;
	}

	KSI_snprintf(buf, buf_len, "PKI Certificate (%s):\n"
			"  * Issued to: %s\n"
			"  * Issued by: %s\n"
			"  * Valid from: %s to %s [%s]\n"
			"  * Serial Number: %s\n",
		ID,	subjectName, issuerName, date_before, date_after, stateString, serial);

	ret = buf;

cleanup:

	KSI_Integer_free(notAfter);
	KSI_Integer_free(notBefore);
	KSI_OctetString_free(serial_number);
	KSI_OctetString_free(crc32);

	return ret;
}




#endif
