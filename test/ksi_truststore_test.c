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

static void TestExtractingOfPKICertificate(CuTest *tc) {
	int res = 0;
	KSI_PKICertificate *cert = NULL;
	KSI_PublicationsFile *pubfile = NULL;
	KSI_PKISignature *pki_sig;
	char buf[2048];
	char *ret = NULL;

	const char expectedValue[] =	"PKI Certificate (34:ec:3d:cc):\n"
									"  * Issued to: E=publications@guardtime.com O=Guardtime AS C=EE\n"
									"  * Issued by: E=publications@guardtime.com O=Guardtime AS C=EE\n"
									"  * Valid from: 2015-05-08 11:29:18 UTC to 2016-05-07 11:29:18 UTC [valid]\n"
									"  * Serial Number: 00\n";

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath("resource/tlv/publications.tlv"), &pubfile);
	CuAssert(tc, "Unable to load publications file from file.", res == KSI_OK && pubfile != NULL);

	res = KSI_PublicationsFile_getSignature(pubfile, &pki_sig);
	CuAssert(tc, "Unable to get PKI signature from publication file.", res == KSI_OK && pki_sig != NULL);

	res = KSI_PKISignature_extractCertificate(pki_sig, &cert);
	CuAssert(tc, "Unable to extract certificate from PKI signature.", res == KSI_OK && cert != NULL);

	ret = KSI_PKICertificate_toString(cert, buf, sizeof(buf));
	CuAssert(tc, "Wrong or invalid certificate extracted.", ret == buf && strcmp(buf, expectedValue) == 0);


	KSI_PKICertificate_free(cert);
	KSI_PublicationsFile_free(pubfile);
	return;
}

static void TestPKICertificateToString(CuTest *tc) {
	int res;
	KSI_PKICertificate *cert_1 = NULL;
	KSI_PKICertificate *cert_2 = NULL;
	KSI_PKICertificate *cert_3 = NULL;
	KSI_PKICertificate *cert_4 = NULL;
	KSI_PKICertificate *cert_5 = NULL;
	char tmp[2048];
	char *ret;

	const char expectedValue_1[] =	"PKI Certificate (b5:b8:2c:f1):\n"
									"  * Issued to: E=publications@guardtime.com CN=Guardtime AS O=Guardtime AS C=EE\n"
									"  * Issued by: E=publications@guardtime.com CN=Guardtime AS O=Guardtime AS C=EE\n"
									"  * Valid from: 2015-10-14 08:11:32 UTC to 2025-10-11 08:11:32 UTC [valid]\n"
									"  * Serial Number: 8b:f2:c0:4e:f9:1c:8d:0f\n";

	const char expectedValue_2[] =	"PKI Certificate (30:46:fe:e4):\n"
									"  * Issued to: E=ksicapi@test.com CN=Unit Testing O=Unit Testing C=EE\n"
									"  * Issued by: E=publications@guardtime.com CN=Guardtime AS O=Guardtime AS C=EE\n"
									"  * Valid from: 2015-10-14 08:27:04 UTC to 2018-10-13 08:27:04 UTC [valid]\n"
									"  * Serial Number: 01\n";

	const char expectedValue_3[] =	"PKI Certificate (c1:c2:80:cb):\n"
									"  * Issued to: E=serial@test.com CN=Serial Test O=Serial Test C=EE\n"
									"  * Issued by: E=ksicapi@test.com CN=Unit Testing O=Unit Testing C=EE\n"
									"  * Valid from: 2015-10-14 12:28:15 UTC to 2018-10-13 12:28:15 UTC [valid]\n"
									"  * Serial Number: 6a:95:fe\n";

	const char expectedValue_4[] =	"PKI Certificate (00:d7:ce:f3):\n"
									"  * Issued to: E=publications@guardtime.com O=Guardtime AS C=EE\n"
									"  * Issued by: E=publications@guardtime.com O=Guardtime AS C=EE\n"
									"  * Valid from: 2014-04-09 13:35:08 UTC to 2015-04-09 13:35:08 UTC [expired]\n"
									"  * Serial Number: d5:5f:8b:04:a8:98:18:90\n";

	const char expectedValue_5[] =	"PKI Certificate (c2:92:37:91):\n"
									"  * Issued to: E=test@test.com O=Testing As C=EE\n"
									"  * Issued by: E=test@test.com O=Testing As C=EE\n"
									"  * Valid from: 2025-10-21 10:47:26 UTC to 2026-10-21 10:47:26 UTC [invalid]\n"
									"  * Serial Number: 92:85:e4:9d:01:71:a2:d5\n";

	res = DER_CertFromFile(ctx, getFullResourcePath("resource/tlv/CA_root.crt.der"), &cert_1);
	CuAssert(tc, "Unable to get cert encoded as der.", res == KSI_OK && cert_1 != NULL);

	res = DER_CertFromFile(ctx, getFullResourcePath("resource/tlv/CA_2.crt.der"), &cert_2);
	CuAssert(tc, "Unable to get cert encoded as der.", res == KSI_OK && cert_2 != NULL);

	res = DER_CertFromFile(ctx, getFullResourcePath("resource/tlv/CA_3.crt.der"), &cert_3);
	CuAssert(tc, "Unable to get cert encoded as der.", res == KSI_OK && cert_3 != NULL);

	res = DER_CertFromFile(ctx, getFullResourcePath("resource/tlv/expired.crt.der"), &cert_4);
	CuAssert(tc, "Unable to get cert encoded as der.", res == KSI_OK && cert_4 != NULL);

	res = DER_CertFromFile(ctx, getFullResourcePath("resource/tlv/future.crt.der"), &cert_5);
	CuAssert(tc, "Unable to get cert encoded as der.", res == KSI_OK && cert_5 != NULL);


	ret = KSI_PKICertificate_toString(cert_1, tmp, sizeof(tmp));
	CuAssert(tc, "Unable to format PKI certificate as string.", ret == tmp && strcmp(tmp, expectedValue_1) == 0);

	ret = KSI_PKICertificate_toString(cert_2, tmp, sizeof(tmp));
	CuAssert(tc, "Unable to format PKI certificate as string.", ret == tmp && strcmp(tmp, expectedValue_2) == 0);

	ret = KSI_PKICertificate_toString(cert_3, tmp, sizeof(tmp));
	CuAssert(tc, "Unable to format PKI certificate as string.", ret == tmp && strcmp(tmp, expectedValue_3) == 0);

	ret = KSI_PKICertificate_toString(cert_4, tmp, sizeof(tmp));
	CuAssert(tc, "Unable to format PKI certificate as string.", ret == tmp && strcmp(tmp, expectedValue_4) == 0);

	ret = KSI_PKICertificate_toString(cert_5, tmp, sizeof(tmp));
	CuAssert(tc, "Unable to format PKI certificate as string.", ret == tmp && strcmp(tmp, expectedValue_5) == 0);



	KSI_PKICertificate_free(cert_1);
	KSI_PKICertificate_free(cert_2);
	KSI_PKICertificate_free(cert_3);
	KSI_PKICertificate_free(cert_4);
	KSI_PKICertificate_free(cert_5);
}



CuSuite* KSITest_Truststore_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestAddInvalidLookupFile);
	SUITE_ADD_TEST(suite, TestAddValidLookupFile);
	SUITE_ADD_TEST(suite, TestParseAndSeraializeCert);
	SUITE_ADD_TEST(suite, TestExtractingOfPKICertificate);
	SUITE_ADD_TEST(suite, TestPKICertificateToString);

	return suite;
}
