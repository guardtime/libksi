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

#include <stdio.h>
#include <stdlib.h>

#include <ksi/ksi.h>
#include <ksi/tlv.h>

#include <openssl/rand.h>
#undef X509_NAME
#include <string.h>
#include <limits.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "../src/ksi/impl/publicationsfile_impl.h"

int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days);
int add_ext(X509 *cert, int nid, char *value);

int publicationsFile_changePKCS7_signature(KSI_PublicationsFile *publicationsFile, const unsigned char *sig_der, unsigned sig_der_len, const char *out) {
	int res;
	int ret = 0;
	KSI_CTX *ctx = NULL;
	KSI_TLV *tlv_tmp = NULL;
	unsigned char *tlv_serialized = NULL;
	size_t tlv_len;
	unsigned char *buf = NULL;
	size_t buf_len;
	FILE *signedPubFile = NULL;

	if (publicationsFile == NULL || sig_der == NULL || sig_der_len == 0) {
		fprintf(stderr, "Error: Invalid argument.");
		goto cleanup;
	}

	ctx = publicationsFile->ctx;

	/* Create Signature TLV from PKCS7 encoded PKI signature. */
	res = KSI_TLV_new(ctx, 0x704, 0, 0, &tlv_tmp);
	if (res != KSI_OK) {
		fprintf(stderr, "Error: unable to create TLV for new signature.");
		goto cleanup;
	}

	res = KSI_TLV_setRawValue(tlv_tmp, sig_der, sig_der_len);
	if (res != KSI_OK) {
		fprintf(stderr, "Error: unable to set TLV's raw data.");
		goto cleanup;
	}

	res = KSI_TLV_serialize(tlv_tmp, &tlv_serialized, &tlv_len);
	if (res != KSI_OK) {
		fprintf(stderr, "Error: unable to serialize signature TLV.");
		goto cleanup;
	}

	/* Create new publications file. */
	buf_len = publicationsFile->signedDataLength + tlv_len;
	buf = (unsigned char*)malloc(buf_len);
	if (buf == NULL) {
		fprintf(stderr, "Error: unable get memory for new publications file.");
		goto cleanup;
	}

	/* Copy publications file data part and append new signature. */
	memcpy(buf, publicationsFile->raw, publicationsFile->signedDataLength);
	memcpy(buf + publicationsFile->signedDataLength, tlv_serialized, tlv_len);

	signedPubFile = fopen(out, "wb");
	if (signedPubFile == NULL) {
		fprintf(stderr, "Error: unable to write new publications file to file.");
		goto cleanup;
	}

	if (fwrite(buf, 1, buf_len, signedPubFile) != buf_len) {
		fprintf(stderr, "Error: unable to write new publications file to file.");
		goto cleanup;
	}

	ret = 1;

cleanup:

	if (signedPubFile != NULL) fclose(signedPubFile);
	KSI_TLV_free(tlv_tmp);
	free(buf);
	free(tlv_serialized);

	return ret;
}


int main(int argc, char **argv) {
	int res;
	int ret = EXIT_FAILURE;
	char *pubfileName = NULL;
	char *outFileName = NULL;
	char *certFileName = NULL;
	char *keyFileName = NULL;
	char *sigFileName = NULL;
	KSI_CTX *ctx = NULL;
	KSI_PublicationsFile *pubFile;
	BIO *bio = NULL;
	X509 *x509 = NULL;
	EVP_PKEY *pkey = NULL;
	PKCS7 *signature;
	unsigned char *buf = NULL;
	unsigned char *p = NULL;
	int len;
	FILE *cert_out = NULL;
	FILE *sign_out = NULL;
	FILE *key_out = NULL;

	if (argc != 4 && argc != 6) {
		fprintf(stderr, "Usage\n"
				"  %s <pub-file in> <pub-file out> <cert file out>\n"
				"  %s <pub-file in> <pub-file out> <cert file out> <key file out> <sig file out>\n", argv[0], argv[0]);
		goto cleanup;
	}

	pubfileName = argv[1];
	outFileName = argv[2];
	certFileName = argv[3];
	if (argc == 6) {
		keyFileName = argv[4];
		sigFileName = argv[5];
	}

	/* Init Openssl and KSI. */
	OpenSSL_add_all_digests();
	ERR_load_crypto_strings();
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

	res = KSI_CTX_new(&ctx);
	if (res != KSI_OK) {
		fprintf(stderr, "Error: Unable to get new KSI context.\n");
		goto cleanup;
	}

	/* Read publications file. */
	res = KSI_PublicationsFile_fromFile(ctx, pubfileName, &pubFile);
	if (res != KSI_OK) {
		fprintf(stderr, "Error: Unable to read KSI publications file.");
		goto cleanup;
	}

	bio = BIO_new(BIO_s_mem());
	if (bio == NULL) {
		fprintf(stderr, "Error: Unable create new openssl bio object.");
		goto cleanup;
	}

	if (pubFile->signedDataLength >= INT_MAX) {
		fprintf(stderr, "Error: publication file too large.");
		goto cleanup;
	}

	if (!BIO_write(bio, pubFile->raw, (int)pubFile->signedDataLength)) {
		fprintf(stderr, "Error: Unable read publications file date from publications file.");
		goto cleanup;
	}

	/* Create new private key and cert for signing process. */
	res = mkcert(&x509, &pkey, 2048, 0, 365);
	if (res != 1) {
		fprintf(stderr, "Error: Unable create new certificate.");
		goto cleanup;
	}

	signature = PKCS7_sign(x509, pkey, NULL, bio, PKCS7_BINARY | PKCS7_NOSMIMECAP | PKCS7_DETACHED);
	if (signature == NULL) {
		fprintf(stderr, "Error: Unable sign publications file.");
		goto cleanup;
	}

	len = i2d_PKCS7(signature, NULL);
	buf = OPENSSL_malloc(len);
	p = buf;
	i2d_PKCS7(signature, &p);

	/* Write data to output. */
	if (keyFileName) {
		key_out = fopen(keyFileName, "wb");
		if (key_out == NULL) {
			fprintf(stderr, "Error: Unable open new file for key.");
			goto cleanup;
		}

		PEM_write_PrivateKey(key_out, pkey, NULL, NULL, 0, NULL, NULL);
	}

	if (certFileName) {
		cert_out = fopen(certFileName, "wb");
		if (cert_out == NULL) {
			fprintf(stderr, "Error: Unable to open new file for certificate.");
			goto cleanup;
		}

		PEM_write_X509(cert_out, x509);
	}

	if (sigFileName) {
		sign_out = fopen(sigFileName, "wb");
		if (sign_out == NULL) {
			fprintf(stderr, "Error: Unable to open new file for signature.");
			goto cleanup;
		}

		if (fwrite(buf, 1, len, sign_out) != len) {
			fprintf(stderr, "Error: Unable to write signature to file.");
			goto cleanup;
		}
	}

	res = publicationsFile_changePKCS7_signature(pubFile, buf, len, outFileName);
	if (res != 1) {
		fprintf(stderr, "Error: Unable to change publications file signature.");
		goto cleanup;
	}

	ret = EXIT_SUCCESS;

cleanup:

	X509_free(x509);
	EVP_PKEY_free(pkey);
	BIO_free(bio);
	OPENSSL_free(buf);
	if (cert_out != NULL) fclose(cert_out);
	if (sign_out != NULL) fclose(sign_out);
	if (key_out != NULL) fclose(key_out);

#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	CRYPTO_cleanup_all_ex_data();

	return ret;
}

static void callback(int p, int n, void *arg) {
	char c = 'B';

	if (p == 0) c = '.';
	if (p == 1) c = '+';
	if (p == 2) c = '*';
	if (p == 3) c = '\n';
	fputc(c, stderr);
}

/*
 * The following helper functions are based on OpenSSL demo code.
 * See <openssl_dir>/demos/x509/mkcert.c
 */

int mkcert(X509 **x509p, EVP_PKEY **pkeyp, int bits, int serial, int days) {
	X509 *x;
	EVP_PKEY *pk;
	RSA *rsa;
	X509_NAME *name = NULL;
	const unsigned char country[] = "EE";
	const unsigned char orgName[] = "Guardtime AS";
	const unsigned char email[] = "publications@guardtime.com";

	if ((pkeyp == NULL) || (*pkeyp == NULL)) {
		if ((pk = EVP_PKEY_new()) == NULL) {
			abort();
			return(0);
		}
	} else {
		pk = *pkeyp;
	}

	if ((x509p == NULL) || (*x509p == NULL)) {
		if ((x = X509_new()) == NULL) {
			goto err;
		}
	} else {
		x = *x509p;
	}

	rsa = RSA_generate_key(bits, RSA_F4, callback, NULL);
	if (!EVP_PKEY_assign_RSA(pk, rsa)) {
		abort();
		goto err;
	}
	rsa = NULL;

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
	X509_gmtime_adj(X509_get_notBefore(x), 0);
	X509_gmtime_adj(X509_get_notAfter(x), (long) 60 * 60 * 24 * days);
	X509_set_pubkey(x, pk);

	name = X509_get_subject_name(x);

	/* This function creates and adds the entry, working out the
	 * correct string type and performing checks on its length.
	 * Normally we'd check the return value for errors... */
	X509_NAME_add_entry_by_txt(name, "C",
			MBSTRING_ASC, country, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "organizationName",
			MBSTRING_ASC, orgName, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "emailAddress",
			MBSTRING_ASC, email, -1, -1, 0);

	/* It's self signed so set the issuer name to be the same as the subject. */
	X509_set_issuer_name(x, name);

	/* Add various extensions: standard extensions. */
	add_ext(x, NID_basic_constraints, "critical,CA:TRUE");
	add_ext(x, NID_key_usage, "critical,keyCertSign,cRLSign");

	add_ext(x, NID_subject_key_identifier, "hash");

	if (!X509_sign(x, pk, EVP_sha256())) {
		goto err;
	}

	*x509p = x;
	*pkeyp = pk;
	return 1;
err:
	return 0;
}

/* Add extension using V3 code: we can set the config file as NULL
 * because we won't reference any other sections. */
int add_ext(X509 *cert, int nid, char *value) {
	X509_EXTENSION *ex;
	X509V3_CTX ctx;
	/* This sets the 'context' of the extensions.
	 * No configuration database */
	X509V3_set_ctx_nodb(&ctx);
	/* Issuer and subject certs: both the target since it is self signed,
	 * no request and no CRL. */
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
	if (!ex) {
		return 0;
	}

	X509_add_ext(cert, ex, -1);
	X509_EXTENSION_free(ex);
	return 1;
}
