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
#include <string.h>
#include <ksi/pkitruststore.h>
#include "ksi/tlv.h"
#include "ksi/io.h"

#include "cutest/CuTest.h"
#include "all_tests.h"

extern KSI_CTX *ctx;
char tmp_path[1024];

static int tlvFromFile(const char *fileName, KSI_TLV **tlv) {
	int res;
	KSI_RDR *rdr = NULL;
	FILE *f = NULL;

	KSI_LOG_debug(ctx, "Open TLV file: '%s'", fileName);

	f = fopen(fileName, "rb");
	res = KSI_RDR_fromStream(ctx, f, &rdr);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TLV_fromReader(rdr, tlv);
	if (res != KSI_OK) goto cleanup;

cleanup:

	if (f != NULL) fclose(f);
	KSI_RDR_close(rdr);

	return res;
}

static int DER_CertFromFile(KSI_CTX *ctx, const char *fileName, KSI_PKICertificate **cert) {
	int res;
	FILE *f = NULL;
	char der[0xffff];
	size_t der_len;
	KSI_PKICertificate *tmp = NULL;

	if (ctx == NULL || fileName == NULL || cert == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_LOG_debug(ctx, "Open Certificate file: '%s'", fileName);

	f = fopen(fileName, "rb");
	if (f == NULL) {
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	der_len = fread(der, 1, sizeof (der), f);
	if (der_len == 0) {
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	res = KSI_PKICertificate_new(ctx, der, der_len , &tmp);
	if (res != KSI_OK) goto cleanup;

	*cert = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	if (f != NULL) fclose(f);
	KSI_PKICertificate_free(tmp);

	return res;
}

static void TestAddInvalidLookupFile(CuTest *tc) {
	int res;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI trustsore.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, "KSI_ThisFileDoesProbablyNotExist");
	CuAssert(tc, "Adding missing lookup file did not fail.", res != KSI_OK);

}

static void TestAddValidLookupFile(CuTest *tc) {
	int res;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI trustsore.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath("resource/tlv/mock.crt"));
	CuAssert(tc, "Adding correct lookup file did fail.", res == KSI_OK);

}



static void TestParseAndSeraializeCert(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	KSI_PKICertificate *cert = NULL;
	unsigned char *raw_crt = NULL;
	size_t raw_crt_len;
	const unsigned char *raw = NULL;
	size_t raw_len;

	KSI_ERR_clearErrors(ctx);

	res = tlvFromFile(getFullResourcePath("resource/tlv/ok-crt.tlv"), &tlv);
	CuAssert(tc, "Unable to read tlv from file.", res == KSI_OK && tlv != NULL);

	res = KSI_PKICertificate_fromTlv(tlv, &cert);
	CuAssert(tc, "Unable to get cert from tlv.", res == KSI_OK && cert != NULL);

	res = KSI_PKICertificate_serialize(cert, &raw_crt, &raw_crt_len);
	CuAssert(tc, "Unable to serialize certificate.", res == KSI_OK && raw_crt != NULL && raw_crt_len > 0);

	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	CuAssert(tc, "Unable to get raw cert value.", res == KSI_OK && raw != NULL && raw_len > 0);

	CuAssert(tc, "Certificate and its serialized value length mismatch.", raw_len == raw_crt_len);
	CuAssert(tc, "Certificate and its serialized value mismatch.", memcmp(raw, raw_crt, raw_len) == 0);

	KSI_TLV_free(tlv);
	KSI_PKICertificate_free(cert);
	KSI_free(raw_crt);
}

static void TestRetrieveValidityDate (CuTest *tc) {
	int res;
	KSI_PKICertificate *cert = NULL;
	KSI_uint64_t notafter, notbefore;

	res = DER_CertFromFile(ctx, getFullResourcePath("resource/tlv/mock.crt.der"), &cert);
	CuAssert(tc, "Unable to get cert encoded as der.", res == KSI_OK && cert != NULL);

	res = KSI_PKICertificate_getValidityNotBefore(cert, &notbefore);
	CuAssert(tc, "Unable to get validity time not before.", res == KSI_OK);

	res = KSI_PKICertificate_getValidityNotAfter(cert, &notafter);
	CuAssert(tc, "Unable to get validity time not after.", res == KSI_OK);


	CuAssert(tc, "Unexpected value of validity date not before.", notbefore == 1431084558);
	CuAssert(tc, "Unexpected value of validity date not after.", notafter == 1462620558);

	KSI_PKICertificate_free(cert);
}

static void TestRetrieveSelfSignedCertNames (CuTest *tc) {
	int res;
	char *ret = NULL;
	KSI_PKICertificate *cert = NULL;
	char issuer[1024];
	char subject[1024];

	res = DER_CertFromFile(ctx, getFullResourcePath("resource/tlv/CA_root.crt.der"), &cert);
	CuAssert(tc, "Unable to get cert encoded as der.", res == KSI_OK && cert != NULL);

	ret = KSI_PKICertificate_issuerToString(cert, issuer, sizeof(issuer));
	CuAssert(tc, "Unable to retrieve issuer name.", ret == issuer);

	ret = KSI_PKICertificate_subjectToString(cert, subject, sizeof(subject));
	CuAssert(tc, "Unable to retrieve subject name.", ret == subject);

	CuAssert(tc, "Invalid issuer name.", strcmp(issuer, "Guardtime AS") == 0);
	CuAssert(tc, "Invalid subject name.", strcmp(subject, "Guardtime AS") == 0);

	KSI_PKICertificate_free(cert);
}

static void TestRetrieveIntermediateCertNames (CuTest *tc) {
	int res;
	char *ret = NULL;
	KSI_PKICertificate *cert = NULL;
	char issuer[1024];
	char subject[1024];

	res = DER_CertFromFile(ctx, getFullResourcePath("resource/tlv/CA_2.crt.der"), &cert);
	CuAssert(tc, "Unable to get cert encoded as der.", res == KSI_OK && cert != NULL);

	ret = KSI_PKICertificate_issuerToString(cert, issuer, sizeof(issuer));
	CuAssert(tc, "Unable to retrieve issuer name.", ret == issuer);

	ret = KSI_PKICertificate_subjectToString(cert, subject, sizeof(subject));
	CuAssert(tc, "Unable to retrieve subject name.", ret == subject);

	CuAssert(tc, "Invalid issuer name.", strcmp(issuer, "Guardtime AS") == 0);
	CuAssert(tc, "Invalid subject name.", strcmp(subject, "Unit Testing") == 0);

	KSI_PKICertificate_free(cert);
}

static void TestCertificateCRC32(CuTest *tc) {
	int res = 0;
	KSI_CertificateRecordList *certReclist = NULL;
	KSI_CertificateRecord *certRec = NULL;
	KSI_PKICertificate *cert = NULL;
	KSI_OctetString *id = NULL;
	KSI_OctetString *calculated_id = NULL;
	int i=0;
	KSI_PublicationsFile *pubfile = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath("resource/tlv/publications.tlv"), &pubfile);
	CuAssert(tc, "Unable to load publications file from file.", res == KSI_OK);

	res = KSI_PublicationsFile_getCertificates(pubfile, &certReclist);
	CuAssert(tc, "Unable to get publications file certificates", res == KSI_OK && certReclist != NULL);

	for(i = 0; i < KSI_CertificateRecordList_length(certReclist); i++){
		res = KSI_CertificateRecordList_elementAt(certReclist, i, &certRec);
		CuAssert(tc, "Unable to get certificate record from certificate record list.", res == KSI_OK && certRec != NULL);

		res = KSI_CertificateRecord_getCert(certRec, &cert);
		CuAssert(tc, "Unable to get cert from certificate record.", res == KSI_OK && cert != NULL);

		res = KSI_CertificateRecord_getCertId(certRec, &id);
		CuAssert(tc, "Unable to get cert ID (crc32 of certificate).", res == KSI_OK && id != NULL);

		res = KSI_PKICertificate_calculateCRC32(cert, &calculated_id);
		CuAssert(tc, "Unable to get cert ID (crc32 of certificate).", res == KSI_OK && calculated_id != NULL);
		CuAssert(tc, "Certificate ID and calculated id mismatch.", KSI_OctetString_equals(id, calculated_id));

		KSI_OctetString_free(calculated_id);
	}

	KSI_PublicationsFile_free(pubfile);
	return;
}

static void TestIssuerOIDToSTring (CuTest *tc) {
	int res;
	char *ret = NULL;
	KSI_PKICertificate *cert = NULL;
	char email[1024];
	char country[1024];
	char org[1024];
	char commonname[1024];

	res = DER_CertFromFile(ctx, getFullResourcePath("resource/tlv/CA_2.crt.der"), &cert);
	CuAssert(tc, "Unable to get cert encoded as der.", res == KSI_OK && cert != NULL);

	ret = KSI_PKICertificate_issuerOIDToString(cert, KSI_CERT_EMAIL, email, sizeof(email));
	CuAssert(tc, "Unable to get email by OID.", ret == email);

	ret = KSI_PKICertificate_issuerOIDToString(cert, KSI_CERT_COUNTRY, country, sizeof(country));
	CuAssert(tc, "Unable to get country by OID.", ret == country);

	ret = KSI_PKICertificate_issuerOIDToString(cert, KSI_CERT_ORGANIZATION, org, sizeof(org));
	CuAssert(tc, "Unable to get organization by OID.", ret == org);

	ret = KSI_PKICertificate_issuerOIDToString(cert, KSI_CERT_COMMON_NAME, commonname, sizeof(commonname));
	CuAssert(tc, "Unable to get organization by OID.", ret == commonname);

	CuAssert(tc, "Invalid email.", strcmp(email, "publications@guardtime.com") == 0);
	CuAssert(tc, "Invalid country.", strcmp(country, "EE") == 0);
	CuAssert(tc, "Invalid organization.", strcmp(org, "Guardtime AS") == 0);
	CuAssert(tc, "Invalid commone name.", strcmp(commonname, "Guardtime AS") == 0);

	KSI_PKICertificate_free(cert);
}

static void TestSubjectOIDToSTring (CuTest *tc) {
	int res;
	char *ret = NULL;
	KSI_PKICertificate *cert = NULL;
	char email[1024];
	char country[1024];
	char org[1024];
	char commonname[1024];

	res = DER_CertFromFile(ctx, getFullResourcePath("resource/tlv/CA_2.crt.der"), &cert);
	CuAssert(tc, "Unable to get cert encoded as der.", res == KSI_OK && cert != NULL);

	ret = KSI_PKICertificate_subjectOIDToString(cert, KSI_CERT_EMAIL, email, sizeof(email));
	CuAssert(tc, "Unable to get email by OID.", ret == email);

	ret = KSI_PKICertificate_subjectOIDToString(cert, KSI_CERT_COUNTRY, country, sizeof(country));
	CuAssert(tc, "Unable to get country by OID.", ret == country);

	ret = KSI_PKICertificate_subjectOIDToString(cert, KSI_CERT_ORGANIZATION, org, sizeof(org));
	CuAssert(tc, "Unable to get organization by OID.", ret == org);

	ret = KSI_PKICertificate_subjectOIDToString(cert, KSI_CERT_COMMON_NAME, commonname, sizeof(commonname));
	CuAssert(tc, "Unable to get organization by OID.", ret == commonname);

	CuAssert(tc, "Invalid email.", strcmp(email, "ksicapi@test.com") == 0);
	CuAssert(tc, "Invalid country.", strcmp(country, "EE") == 0);
	CuAssert(tc, "Invalid organization.", strcmp(org, "Unit Testing") == 0);
	CuAssert(tc, "Invalid commone name.", strcmp(commonname, "Unit Testing") == 0);

	KSI_PKICertificate_free(cert);
}

static void TestGetPKICertificateSerialNumber(CuTest *tc) {
	int res;
	char *ret = NULL;
	KSI_PKICertificate *cert = NULL;
	unsigned long serial_number = 0;

	res = DER_CertFromFile(ctx, getFullResourcePath("resource/tlv/CA_3.crt.der"), &cert);
	CuAssert(tc, "Unable to get cert encoded as der.", res == KSI_OK && cert != NULL);

	res = KSI_PKICertificate_getSerialNumber(cert, &serial_number);
	CuAssert(tc, "Unable to retrieve certificates serial number.", res == KSI_OK);
	CuAssert(tc, "PKI certificate serial number mismatch.", serial_number == 6985214);

	KSI_PKICertificate_free(cert);
}

CuSuite* KSITest_Truststore_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestAddInvalidLookupFile);
	SUITE_ADD_TEST(suite, TestAddValidLookupFile);
	SUITE_ADD_TEST(suite, TestParseAndSeraializeCert);
	SUITE_ADD_TEST(suite, TestRetrieveValidityDate);
	SUITE_ADD_TEST(suite, TestRetrieveSelfSignedCertNames);
	SUITE_ADD_TEST(suite, TestRetrieveIntermediateCertNames);
	SUITE_ADD_TEST(suite, TestCertificateCRC32);
	SUITE_ADD_TEST(suite, TestGetPKICertificateSerialNumber);
	SUITE_ADD_TEST(suite, TestIssuerOIDToSTring);
	SUITE_ADD_TEST(suite, TestSubjectOIDToSTring);

	return suite;
}
