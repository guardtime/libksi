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

#include <string.h>
#include <ksi/publicationsfile.h>
#include <ksi/pkitruststore.h>
#include "all_tests.h"
#include "../src/ksi/publicationsfile_impl.h"

extern KSI_CTX *ctx;

#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
#define TEST_PUBLICATIONS_FILE_INVALID_PKI "resource/tlv/publfile-nok-pki.tlv"
#define TAMPERED_PUBLICATIONS_FILE "resource/tlv/publications-fake-publication.tlv"

static void testLoadPublicationsFile(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	KSI_PublicationsFile_free(pubFile);
}

static void testLoadPublicationsFileWithNoCerts(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_LIST(KSI_CertificateRecord) *certList = NULL;
	KSI_PKICertificate *cert = NULL;

	unsigned char dummy[] = {0xca, 0xfe, 0xba, 0xbe};
	KSI_OctetString *certId = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath("resource/publications/publications-nocerts.bin"), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_PublicationsFile_getCertificates(pubFile, &certList);
	CuAssert(tc, "Unable to get certificate list", res == KSI_OK);
	CuAssert(tc, "Unexpected certificate list length.", KSI_CertificateRecordList_length(certList) == 0);

	res = KSI_OctetString_new(ctx, dummy, sizeof(dummy), &certId);
	CuAssert(tc, "Creating an octetstring failed", res == KSI_OK && certId != NULL);

	res = KSI_PublicationsFile_getPKICertificateById(pubFile, certId, &cert);
	CuAssert(tc, "Searching for a non existend certificate failed", res == KSI_OK && cert == NULL);

	KSI_OctetString_free(certId);
	KSI_PublicationsFile_free(pubFile);
}

static void testLoadPublicationsFileContainsInvalidSignatureAndUnknownElement(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath("resource/publications/publications-contains-not-critical-unknown-element.bin"), &pubFile);
	CuAssert(tc, "Invalid publications file must fail.", res != KSI_OK && pubFile == NULL);

	KSI_PublicationsFile_free(pubFile);
}


static void testVerifyPublicationsFile(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new pki truststrore for ksi context.", res == KSI_OK);

	/* Verification should fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file shouldn't verify without mock certificate.", res != KSI_OK);

	/* Verification should succeed. */

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath("resource/tlv/mock.crt"));
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	res = KSI_PublicationsFile_verify(pubFile, ctx);

	CuAssert(tc, "Publications file should verify with mock certificate.", res == KSI_OK);

	KSI_PublicationsFile_free(pubFile);
}

/**
 * To generate new certificate chain one must, generate N x new key pairs, create
 * certificate requests (Containing e.g. email, organization, name ...) for every
 * key pair and ultimately sign all the requests to create the certificates. After
 * keys and certificates are generated ksi-publication can be used to resign or
 * generate new publications file for testing.
 *
 * To generate new keys call:
 *    openssl genrsa -out ok-key-N.pem 2048
 *
 * To generate self signed root certificate thats purpose is CA:
 *    openssl req -x509 -new -extensions v3_ca -key ok-key-1.pem.pkey -days 3650 -out ok-cert-ca-1.pem
 *
 * To generate new certificate requests (user is asked for cert. field values):
 *    openssl req -new -key ok-key-N.pem.pkey -out crt-req-N
 *
 * To make the root CA work, OpenSSL configuration file must be configured. Read
 * about ca and default ca configuration for OpenSSL. Lets assume we have file
 * openssl.cfg (contains info about ok-key-1.pem.pkey, ok-cert-ca-1.pem and
 * more).
 *
 * To generate intermediate CA:
 *    openssl ca -in crt-req-2 -out ok-cert-ca-2.pem -policy policy_anything -extensions v3_ca -days 3650 -config openssl.cnf
 *
 * To create the certificate for the key that is used to sign the publications file:
 *    openssl x509 -req -days 3650 -in crt-req-3 -CA ok-cert-ca-2.pem -CAkey ok-key-2.pem.pkey -set_serial 02 -out ok-cert-3.pem
 *
 * At this point there is
 *    ok-key-1.pem.pkey and ok-cert-ca-1.pem
 *    ok-key-2.pem.pkey and ok-cert-ca-2.pem
 *    ok-key-3.pem.pkey and ok-cert-3.pem
 *
 * To generate new publications file, use ksi-publication tool.
 *
 * 1) Create a configuration file pub.cfg for ksi publication.
 *   [signer]
 *      key_id = "ok-key-3.pem.pkey"
 *      signing_cert = "ok-cert-3.pem"
 *      intermediate_cert.1 = "ok-cert-ca-2.pem"
 *      intermediate_cert.2 = "ok-cert-ca-1.pem"
 *
 *   [constraints]
 *      1.2.840.113549.1.9.1=pub-test@test.com
 *
 * 2) Resign the publications file (or read -h and man page to generate new):
 *    ksi-publication -i ok-cert-3.pem-pubfile.bin -c pub.cfg -o resigned-pubfile.bin -xdsv
 */
static void testVerifyPublicationsFileContainsIntermediateCerts(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PKITruststore *pki = NULL;
	KSI_CTX *ctx = NULL;
	KSI_CertConstraint cnstr[2];

	cnstr[0].oid = KSI_CERT_EMAIL;
	cnstr[0].val = "pub-test@test.com";
	cnstr[1].oid = NULL;
	cnstr[1].val = NULL;


	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Unable to create KSI ctx.", res == KSI_OK && ctx != NULL);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath("resource/tlv/ok-cert-3.pem-pubfile.bin"), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new pki truststrore for ksi context.", res == KSI_OK);

	/* Verification should fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file shouldn't verify without root (ok-cert-ca-1.pem) certificate.", res != KSI_OK);

	/* Verification should succeed. */
	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath("resource/tlv/ok-cert-ca-1.pem"));
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, cnstr);
	CuAssert(tc, "Unable to set verification certificate constraints.", res == KSI_OK);

	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file should verify with specified root certificate.", res == KSI_OK);

	KSI_PublicationsFile_free(pubFile);
	KSI_CTX_free(ctx);
}

static void testReceivePublicationsFileInvalidConstraints(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PKITruststore *pki = NULL;
	KSI_CertConstraint arr[] = {
			{KSI_CERT_EMAIL, "wrong@email.com"},
			{NULL, NULL}
	};
	KSI_CTX *ctx = NULL;

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_setPublicationUrl(ctx, getFullResourcePathUri(TEST_PUBLICATIONS_FILE));
	CuAssert(tc, "Unable to set pubfile URI.", res == KSI_OK);

	/* Configure expected PIK cert and constraints for pub. file. */
	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new pki truststrore for ksi context.", res == KSI_OK);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath("resource/tlv/mock.crt"));
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
	CuAssert(tc, "Unable to set OID 2.5.4.10", res == KSI_OK);

	res = KSI_receivePublicationsFile(ctx, &pubFile);
	CuAssert(tc, "Unable to get publications file.", res == KSI_OK && pubFile != NULL);

	res = KSI_verifyPublicationsFile(ctx, pubFile);
	CuAssert(tc, "Publications file should NOT verify as PKI constraint is wrong.", res != KSI_OK);

	KSI_PublicationsFile_free(pubFile);
	KSI_CTX_free(ctx);
}

static void testReceivePublicationsFileInvalidPki(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PKITruststore *pki = NULL;
	KSI_CertConstraint arr[] = {
			{KSI_CERT_EMAIL, "publications@guardtime.com"},
			{NULL, NULL}
	};
	KSI_CTX *ctx = NULL;

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_setPublicationUrl(ctx, getFullResourcePathUri(TEST_PUBLICATIONS_FILE_INVALID_PKI));
	CuAssert(tc, "Unable to clear pubfile URI.", res == KSI_OK);

	/* Configure expected PIK cert and constraints for pub. file. */
	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new pki truststrore for ksi context.", res == KSI_OK);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath("resource/tlv/mock.crt"));
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
	CuAssert(tc, "Unable to set OID 2.5.4.10", res == KSI_OK);

	res = KSI_receivePublicationsFile(ctx, &pubFile);
	CuAssert(tc, "Unable to receive publications file.", res == KSI_OK && pubFile != NULL);

	res = KSI_verifyPublicationsFile(ctx, pubFile);
	CuAssert(tc, "Publications file should NOT verify as PKI signature is wrong.", res == KSI_INVALID_PKI_SIGNATURE);

	KSI_PublicationsFile_free(pubFile);
	KSI_CTX_free(ctx);
}

static void testVerifyPublicationsFileWithOrganization(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_CertConstraint arr[] = {
			{KSI_CERT_EMAIL, "publications@guardtime.com"},
			{NULL, NULL},
			{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);


	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	arr[1].oid = KSI_CERT_ORGANIZATION;
	arr[1].val = "Guardtime AS";
	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
	CuAssert(tc, "Unable to set OID 2.5.4.10", res == KSI_OK);

	/* Verification should fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify with OID='2.5.4.10' value 'Guardtime AS'.", res == KSI_OK);

	arr[1].val = "Guardtime US";
	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
	CuAssert(tc, "Unable to set OID 2.5.4.10", res == KSI_OK);

	/* Verification should fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file may not verify with wrong company'.", res != KSI_OK);
	/* Verification should succeed. */

	arr[1].oid = NULL;
	arr[1].val = NULL;
	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
	CuAssert(tc, "Unable to set OID 2.5.4.10", res == KSI_OK);

	/* Verification should fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify with OID='2.5.4.10' removed from the constraints", res == KSI_OK);

	CuAssert(tc, "Publications file should verify with mock certificate.", res == KSI_OK);

	KSI_PublicationsFile_free(pubFile);
}

static void testVerifyPublicationsFileWithNoConstraints(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_CertConstraint arr[] = {
			{NULL, NULL},
			{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);


	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
	CuAssert(tc, "Unable to delete OID 1.2.840.113549.1.9.1", res == KSI_OK);

	/* Verification should not fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file may not verify with no constraints.", res == KSI_PUBFILE_VERIFICATION_NOT_CONFIGURED);

	arr[0].oid = KSI_CERT_EMAIL;
	arr[0].val = "publications@guardtime.com";
	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
	CuAssert(tc, "Unable to set OID 1.2.840.113549.1.9.1 back to normal", res == KSI_OK);

	/* Verification should not fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify with e-mail.", res == KSI_OK);

	KSI_PublicationsFile_free(pubFile);
}

static void testVerifyPublicationsFileWithAttributeNotPresent(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_CertConstraint arr[] = {
			{NULL, NULL},
			{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);


	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	arr[0].oid = "2.5.4.9";
	arr[0].val = "Local pub";
	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
	CuAssert(tc, "Unable to delete OID 2.5.4.9", res == KSI_OK);

	/* Verification should fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify with address.", res != KSI_OK);

	arr[0].oid = KSI_CERT_EMAIL;
	arr[0].val = "publications@guardtime.com";
	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
	CuAssert(tc, "Unable to set OID 2.5.4.9 back to normal", res == KSI_OK);

	/* Verification should not fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify.", res == KSI_OK);

	KSI_PublicationsFile_free(pubFile);
}

static void testSetPublicationsFileConstraints(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_CertConstraint empty[] = {
			{NULL, NULL},
			{NULL, NULL}
	};
	KSI_CertConstraint email[] = {
			{KSI_CERT_EMAIL, "publications@guardtime.com"},
			{NULL, NULL}
	};

	res = KSI_CTX_getPublicationsFile(ctx, &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_PublicationsFile_setCertConstraints(pubFile, empty);
	CuAssert(tc, "Unable to set publications file certificate constraints.", res == KSI_OK && pubFile->certConstraints != NULL);
	CuAssert(tc, "Unexpected certificate constraint values", pubFile->certConstraints[0].oid == NULL && pubFile->certConstraints[0].val == NULL);

	res = KSI_PublicationsFile_setCertConstraints(pubFile, email);
	CuAssert(tc, "Unable to set publications file certificate constraints.", res == KSI_OK && pubFile->certConstraints != NULL);
	CuAssert(tc, "Unexpected certificate constraint values",
			 !strcmp(pubFile->certConstraints[0].oid, email[0].oid) &&
			 !strcmp(pubFile->certConstraints[0].val, email[0].val));

	res = KSI_PublicationsFile_setCertConstraints(pubFile, empty);
	CuAssert(tc, "Unable to set publications file certificate constraints.", res == KSI_OK && pubFile->certConstraints != NULL);
	CuAssert(tc, "Unexpected certificate constraint values", pubFile->certConstraints[0].oid == NULL && pubFile->certConstraints[0].val == NULL);

	res = KSI_PublicationsFile_setCertConstraints(pubFile, NULL);
	CuAssert(tc, "Unable to set publications file certificate constraints.", res == KSI_OK && pubFile->certConstraints == NULL);
}

static void testVerifyPublicationsFileWithFileSpecificConstraints(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_CertConstraint empty[] = {
			{NULL, NULL},
			{NULL, NULL}
	};
	KSI_CertConstraint email[] = {
			{KSI_CERT_EMAIL, "publications@guardtime.com"},
			{NULL, NULL}
	};

	KSI_CertConstraint wrong[] = {
			{KSI_CERT_EMAIL, "wrong@email.com"},
			{NULL, NULL}
	};

	KSI_CertConstraint unknown[] = {
			{"3.2.840.113549.1.9.1", "publications@guardtime.com"},
			{NULL, NULL}
	};

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, email);
	CuAssert(tc, "Unable to set default certificate constraints", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_PublicationsFile_setCertConstraints(pubFile, NULL);
	CuAssert(tc, "Unable to set publications file certificate constraints.", res == KSI_OK);

	res = KSI_verifyPublicationsFile(ctx, pubFile);
	CuAssert(tc, "Unable to verify publications file with context based constraints.", res == KSI_OK);

	res = KSI_PublicationsFile_setCertConstraints(pubFile, empty);
	CuAssert(tc, "Unable to set publications file certificate constraints.", res == KSI_OK);

	res = KSI_verifyPublicationsFile(ctx, pubFile);
	CuAssert(tc, "Publications file should not verify with empty certificate constraints.", res != KSI_OK);

	res = KSI_PublicationsFile_setCertConstraints(pubFile, email);
	CuAssert(tc, "Unable to set publications file certificate constraints.", res == KSI_OK);

	res = KSI_verifyPublicationsFile(ctx, pubFile);
	CuAssert(tc, "Unable to verify publications file with email.", res == KSI_OK);

	res = KSI_PublicationsFile_setCertConstraints(pubFile, wrong);
	CuAssert(tc, "Unable to set publications file certificate constraints.", res == KSI_OK);

	res = KSI_verifyPublicationsFile(ctx, pubFile);
	CuAssert(tc, "Publications file should not verify with wrong certificate constraints.", res != KSI_OK);

	res = KSI_PublicationsFile_setCertConstraints(pubFile, unknown);
	CuAssert(tc, "Unable to set publications file certificate constraints.", res == KSI_OK);

	res = KSI_verifyPublicationsFile(ctx, pubFile);
	CuAssert(tc, "Publications file should not verify with unknown certificate constraints.", res == KSI_INVALID_ARGUMENT);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, wrong);
	CuAssert(tc, "Unable to set default certificate constraints", res == KSI_OK);

	res = KSI_PublicationsFile_setCertConstraints(pubFile, email);
	CuAssert(tc, "Unable to set publications file certificate constraints.", res == KSI_OK);

	res = KSI_verifyPublicationsFile(ctx, pubFile);
	CuAssert(tc, "Unable to verify publications file with email.", res == KSI_OK);

	KSI_PublicationsFile_free(pubFile);
}

static void testVerifyPublicationsFileAdditionalPublications(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TAMPERED_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "This publications file does not follow the correct format.", res != KSI_OK && pubFile == NULL);

	KSI_PublicationsFile_free(pubFile);
}

static void testPublicationStringEncodingAndDecoding(CuTest *tc) {
	static const char publication[] = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";
	char *out = NULL;
	int res;
	KSI_PublicationData *pub = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_PublicationData_fromBase32(ctx, publication, &pub);
	CuAssert(tc, "Failed decoding publication string.", res == KSI_OK && pub != NULL);

	res = KSI_PublicationData_toBase32(pub, &out);

	CuAssert(tc, "Failed encoding the published data object", res == KSI_OK && out != NULL);

	CuAssert(tc, "Invalid encoded publication string does not match original.", !strncmp(publication, out, strlen(publication)));

	KSI_PublicationData_free(pub);
	KSI_free(out);
}

static void testFindPublicationByPubStr(CuTest *tc) {
	static const char publication[] = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_PublicationData *pub = NULL;
	KSI_DataHash *pubHsh = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *expHsh = NULL;
	unsigned char buf[0xff];
	size_t len;
	KSI_CTX *ctx = NULL;

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create KSI context.", res == KSI_OK && ctx != NULL);

	res = KSITest_setDefaultPubfileAndVerInfo(ctx);
	CuAssert(tc, "Unable to set default values to context.", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_setPublicationUrl(ctx, getFullResourcePathUri(TEST_PUBLICATIONS_FILE));
	CuAssert(tc, "Unable to set pubfile URI.", res == KSI_OK);

	res = KSI_receivePublicationsFile(ctx, &pubFile);
	CuAssert(tc, "Unable to get publications file.", res == KSI_OK && pubFile != NULL);

	res = KSI_verifyPublicationsFile(ctx, pubFile);
	CuAssert(tc, "Unable to verify publications file.", res == KSI_OK);

	res = KSI_PublicationsFile_getPublicationDataByPublicationString(pubFile, publication, &pubRec);
	CuAssert(tc, "Unable to get publication record by publication string.", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pub);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pub != NULL);

	res = KSI_PublicationData_getImprint(pub, &pubHsh);
	CuAssert(tc, "Unable to get published hash", res == KSI_OK && pubHsh != NULL);

	res = KSI_PublicationData_getTime(pub, &pubTime);
	CuAssert(tc, "Unable to get publication time.", res == KSI_OK && pubTime != NULL);

	KSITest_decodeHexStr("01a1b5238ffb05fccfa67546266a0b2d7130f6656026033b6b578c12e4fbbe231a", buf, sizeof(buf), &len);
	res = KSI_DataHash_fromImprint(ctx, buf, len, &expHsh);
	CuAssert(tc, "Unable to get data hash from imprint.", res == KSI_OK && expHsh != NULL);

	CuAssert(tc, "Publication hash mismatch.", KSI_DataHash_equals(expHsh, pubHsh));
	CuAssert(tc, "Publication time mismatch", KSI_Integer_equalsUInt(pubTime, 1397520000));

	KSI_DataHash_free(expHsh);
	KSI_PublicationsFile_free(pubFile);
	KSI_CTX_free(ctx);

}

static void testFindPublicationByTime(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_PublicationData *pub = NULL;
	KSI_DataHash *pubHsh = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *expHsh = NULL;
	KSI_LIST(KSI_Utf8String) *pubRefList = NULL;
	unsigned char buf[0xff];
	size_t len;
	KSI_CTX *ctx = NULL;

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create KSI context.", res == KSI_OK && ctx != NULL);

	res = KSITest_setDefaultPubfileAndVerInfo(ctx);
	CuAssert(tc, "Unable to set default values to context.", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_setPublicationUrl(ctx, getFullResourcePathUri(TEST_PUBLICATIONS_FILE));
	CuAssert(tc, "Unable to set pubfile URI.", res == KSI_OK);

	res = KSI_receivePublicationsFile(ctx, &pubFile);
	CuAssert(tc, "Unable to get publications file.", res == KSI_OK && pubFile != NULL);

	res = KSI_verifyPublicationsFile(ctx, pubFile);
	CuAssert(tc, "Unable to verify publications file.", res == KSI_OK);

	res = KSI_Integer_new(ctx, 1397520000, &pubTime);
	CuAssert(tc, "Unable to create ksi integer object.", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationsFile_getPublicationDataByTime(pubFile, pubTime, &pubRec);
	CuAssert(tc, "Unable to get publication record by publication date.", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pub);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pub != NULL);

	res = KSI_PublicationData_getImprint(pub, &pubHsh);
	CuAssert(tc, "Unable to get published hash", res == KSI_OK && pubHsh != NULL);

	KSI_Integer_free(pubTime);
	pubTime = NULL;

	res = KSI_PublicationData_getTime(pub, &pubTime);
	CuAssert(tc, "Unable to get publication time.", res == KSI_OK && pubTime != NULL);

	KSITest_decodeHexStr("01a1b5238ffb05fccfa67546266a0b2d7130f6656026033b6b578c12e4fbbe231a", buf, sizeof(buf), &len);
	res = KSI_DataHash_fromImprint(ctx, buf, len, &expHsh);
	CuAssert(tc, "Unable to get datahash from imprint", res == KSI_OK && expHsh != NULL);

	CuAssert(tc, "Publication hash mismatch.", KSI_DataHash_equals(expHsh, pubHsh));
	CuAssert(tc, "Publication time mismatch", KSI_Integer_equalsUInt(pubTime, 1397520000));

	res = KSI_PublicationRecord_getPublicationRefList(pubRec, &pubRefList);
	CuAssert(tc, "Unable to get publications ref list", res == KSI_OK && pubRefList != NULL);

	KSI_DataHash_free(expHsh);
	KSI_PublicationsFile_free(pubFile);
	KSI_CTX_free(ctx);
}

static void testFindPublicationRef(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_LIST(KSI_Utf8String) *pubRefList = NULL;
	size_t i;
	int isPubRefFound = 0;
	KSI_CTX *ctx = NULL;

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create KSI context.", res == KSI_OK && ctx != NULL);

	res = KSITest_setDefaultPubfileAndVerInfo(ctx);
	CuAssert(tc, "Unable to set default values to context.", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_setPublicationUrl(ctx, getFullResourcePathUri(TEST_PUBLICATIONS_FILE));
	CuAssert(tc, "Unable to set pubfile URI.", res == KSI_OK);

	res = KSI_receivePublicationsFile(ctx, &pubFile);
	CuAssert(tc, "Unable to get publications file.", res == KSI_OK && pubFile != NULL);

	res = KSI_verifyPublicationsFile(ctx, pubFile);
	CuAssert(tc, "Unable to verify publications file.", res == KSI_OK);

	res = KSI_Integer_new(ctx, 1397520000, &pubTime);
	CuAssert(tc, "Unable to create ksi integer object.", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationsFile_getPublicationDataByTime(pubFile, pubTime, &pubRec);
	CuAssert(tc, "Unable to get publication record by publication date.", res == KSI_OK && pubRec != NULL);

	KSI_Integer_free(pubTime);
	pubTime = NULL;

	res = KSI_PublicationRecord_getPublicationRefList(pubRec, &pubRefList);
	CuAssert(tc, "Unable to get publications ref list", res == KSI_OK && pubRefList != NULL);

	for (i = 0; i < KSI_Utf8StringList_length(pubRefList); i++) {
		KSI_Utf8String *pubRef = NULL;
		res = KSI_Utf8StringList_elementAt(pubRefList, i, &pubRef);
		CuAssert(tc, "Unable to get element from list", res == KSI_OK && pubRef != NULL);
		if (!strcmp("Financial Times, ISSN: 0307-1766, 2014-04-17", KSI_Utf8String_cstr(pubRef))) {
			isPubRefFound = 1;
		}
	}

	CuAssert(tc, "Financial times publication not found", isPubRefFound);
	KSI_PublicationsFile_free(pubFile);
	KSI_CTX_free(ctx);
}

static void testSerializePublicationsFile(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	char *raw = NULL;
	size_t raw_len = 0;
	FILE *f = NULL;
	int symbol = 0;
	size_t i = 0;
	size_t signedDataLengthAtLoading;
	size_t signedDataLengthAtSerialization;


	KSI_ERR_clearErrors(ctx);


	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_PublicationsFile_getSignedDataLength(pubFile, &signedDataLengthAtLoading);
	CuAssert(tc, "Unable to get signed data length.", res == KSI_OK);

	res = KSI_PublicationsFile_serialize(ctx, pubFile, &raw, &raw_len);
	CuAssert(tc, "Unable to serialize publications file", res == KSI_OK && raw != NULL && raw_len != 0);

	res = KSI_PublicationsFile_getSignedDataLength(pubFile, &signedDataLengthAtSerialization);
	CuAssert(tc, "Unable to get signed data length.", res == KSI_OK);

	f = fopen(getFullResourcePath(TEST_PUBLICATIONS_FILE), "rb");
	CuAssert(tc, "Unable to open publications file", res == KSI_OK && f != NULL);

	while ((symbol = getc(f)) != EOF && i<raw_len){
		CuAssert(tc, "Serialized publications file mismatch", (char) symbol == raw[i]);
		i++;
	}

	CuAssert(tc, "Serialized publications file length mismatch", i == raw_len);

	CuAssert(tc, "Serialized publications file length mismatch", signedDataLengthAtSerialization == signedDataLengthAtLoading);



	KSI_PublicationsFile_free(pubFile);
	KSI_free(raw);
	if (f) fclose(f);
}

static void testGetNearestPublication(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;
	KSI_PublicationData *pubDat = NULL;
	KSI_Integer *pubTm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_Integer_new(ctx, 1289779234, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getNearestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "Unable to find nearest publication", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubDat);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pubDat != NULL);

	res = KSI_PublicationData_getTime(pubDat, &pubTm);
	CuAssert(tc, "Unable to get publication time", res == KSI_OK && pubTm != NULL);

	CuAssert(tc, "Unexpected publication time", KSI_Integer_equalsUInt(pubTm, 1292371200));

	KSI_PublicationRecord_free(pubRec);
	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}


static void testGetNearestPublicationOf0(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;
	KSI_PublicationData *pubDat = NULL;
	KSI_Integer *pubTm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	/* With time set to 0, the result should be the first publication record in the publications file. */
	res = KSI_Integer_new(ctx, 0, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getNearestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "Unable to find nearest publication", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubDat);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pubDat != NULL);

	res = KSI_PublicationData_getTime(pubDat, &pubTm);
	CuAssert(tc, "Unable to get publication time", res == KSI_OK && pubTm != NULL);

	CuAssert(tc, "Unexpected publication time", KSI_Integer_equalsUInt(pubTm, 1208217600));

	KSI_PublicationRecord_free(pubRec);
	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}

static void testGetNearestPublicationWithPubTime(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;
	KSI_PublicationData *pubDat = NULL;
	KSI_Integer *pubTm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	/* With time set to 0, the result should be the first publication record in the publications file. */
	res = KSI_Integer_new(ctx, 1208217600, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getNearestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "Unable to find nearest publication", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubDat);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pubDat != NULL);

	res = KSI_PublicationData_getTime(pubDat, &pubTm);
	CuAssert(tc, "Unable to get publication time", res == KSI_OK && pubTm != NULL);

	CuAssert(tc, "Unexpected publication time", KSI_Integer_equalsUInt(pubTm, 1208217600));

	KSI_PublicationRecord_free(pubRec);
	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}

static void testGetNearestPublicationOfFuture(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	/* With time set to 0, the result should be the first publication record in the publications file. */
	res = KSI_Integer_new(ctx, 2208217600, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getNearestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "There should not be a valid publication", res == KSI_OK && pubRec == NULL);

	KSI_PublicationRecord_free(pubRec);
	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}

static void testGetLatestPublicationOf0(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;
	KSI_PublicationData *pubDat = NULL;
	KSI_Integer *pubTm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_Integer_new(ctx, 1289779234, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getLatestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "Unable to find nearest publication", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubDat);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pubDat != NULL);

	res = KSI_PublicationData_getTime(pubDat, &pubTm);
	CuAssert(tc, "Unable to get publication time", res == KSI_OK && pubTm != NULL);

	CuAssert(tc, "Unexpected publication time (this test might fail, if you have recently updated the publications file in the tests)", KSI_Integer_equalsUInt(pubTm, 1405382400));

	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}

static void testGetLatestPublicationOfLast(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;
	KSI_PublicationData *pubDat = NULL;
	KSI_Integer *pubTm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_Integer_new(ctx, 1405382400, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getLatestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "Unable to find nearest publication", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubDat);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pubDat != NULL);

	res = KSI_PublicationData_getTime(pubDat, &pubTm);
	CuAssert(tc, "Unable to get publication time", res == KSI_OK && pubTm != NULL);

	CuAssert(tc, "Unexpected publication time (this test might fail, if you have recently updated the publications file in the tests)", KSI_Integer_equalsUInt(pubTm, 1405382400));

	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}

static void testGetLatestPublicationOfFuture(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_Integer_new(ctx, 2405382400, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getLatestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "This publication should not exist.", res == KSI_OK && pubRec == NULL);

	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}


CuSuite* KSITest_Publicationsfile_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testLoadPublicationsFile);
	SUITE_ADD_TEST(suite, testLoadPublicationsFileWithNoCerts);
	SUITE_ADD_TEST(suite, testLoadPublicationsFileContainsInvalidSignatureAndUnknownElement);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFile);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFileContainsIntermediateCerts);
	SUITE_ADD_TEST(suite, testPublicationStringEncodingAndDecoding);
	SUITE_ADD_TEST(suite, testFindPublicationByPubStr);
	SUITE_ADD_TEST(suite, testFindPublicationByTime);
	SUITE_ADD_TEST(suite, testFindPublicationRef);
	SUITE_ADD_TEST(suite, testSerializePublicationsFile);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFileWithOrganization);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFileWithNoConstraints);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFileWithAttributeNotPresent);
	SUITE_ADD_TEST(suite, testSetPublicationsFileConstraints);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFileWithFileSpecificConstraints);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFileAdditionalPublications);
	SUITE_ADD_TEST(suite, testGetNearestPublication);
	SUITE_ADD_TEST(suite, testGetNearestPublicationOf0);
	SUITE_ADD_TEST(suite, testGetNearestPublicationWithPubTime);
	SUITE_ADD_TEST(suite, testGetNearestPublicationOfFuture);
	SUITE_ADD_TEST(suite, testGetLatestPublicationOf0);
	SUITE_ADD_TEST(suite, testGetLatestPublicationOfLast);
	SUITE_ADD_TEST(suite, testGetLatestPublicationOfFuture);
	SUITE_ADD_TEST(suite, testReceivePublicationsFileInvalidConstraints);
	SUITE_ADD_TEST(suite, testReceivePublicationsFileInvalidPki);

	return suite;
}

