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
#include "all_tests.h"
#include "ksi/signature.h"

extern KSI_CTX *ctx;

#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

static void testLoadSignatureFromFile(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	KSI_Signature_free(sig);
}

static void testVerifySignatureNew(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	/* Set the extend response. */
	KSITest_setFileMockResponse(tc, getFullResourcePath("resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"));

	res = KSI_verifySignature(ctx, sig);
	CuAssert(tc, "Unable to verify signature online.", res == KSI_OK);

	KSI_Signature_free(sig);

}

static void testVerifySignatureWithPublication(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/ok-sig-2014-04-30.1-extended.ksig"), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_verifySignature(ctx, sig);

	CuAssert(tc, "Unable to verify signature with publication.", res == KSI_OK);

	KSI_Signature_free(sig);

}

static void testVerifySignatureWithUserPublication(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;
	const char pubStr[] = "AAAAAA-CTOQBY-AAMJYH-XZPM6T-UO6U6V-2WJMHQ-EJMVXR-JEAGID-2OY7P5-XFFKYI-QIF2LG-YOV7SO";
	const char pubStr_bad[] = "AAAAAA-CT5VGY-AAPUCF-L3EKCC-NRSX56-AXIDFL-VZJQK4-WDCPOE-3KIWGB-XGPPM3-O5BIMW-REOVR4";
	KSI_PublicationData *pubData = NULL;
	KSI_PublicationData *pubData_bad = NULL;


	KSI_ERR_clearErrors(ctx);


	res = KSI_PublicationData_fromBase32(ctx, pubStr, &pubData);
	CuAssert(tc, "Unable to parse publication string.", res == KSI_OK && pubData != NULL);

	res = KSI_PublicationData_fromBase32(ctx, pubStr_bad, &pubData_bad);
	CuAssert(tc, "Unable to parse publication string.", res == KSI_OK && pubData_bad != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/ok-sig-2014-04-30.1-extended.ksig"), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_verifyWithPublication(sig, ctx, pubData);
	CuAssert(tc, "Unable to verify signature with publication.", res == KSI_OK);

	res = KSI_Signature_verifyWithPublication(sig, ctx, pubData_bad);
	CuAssert(tc, "Unable to verify signature with publication.", res != KSI_OK);


	KSI_PublicationData_free(pubData);
	KSI_PublicationData_free(pubData_bad);
	KSI_Signature_free(sig);
}

static void testVerifyLegacySignatureAndDoc(CuTest *tc) {
	int res;
	char doc[] = "This is a test data file.\x0d\x0a";
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/ok-legacy-sig-2015-01.gtts"), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, strlen(doc));
	CuAssert(tc, "Failed to verify valid document", res == KSI_OK);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, sizeof(doc));
	CuAssert(tc, "Verification did not fail with expected error.", res == KSI_VERIFICATION_FAILURE);

	KSI_Signature_free(sig);
}

static void testVerifyLegacyExtendedSignatureAndDoc(CuTest *tc) {
	int res;
	char doc[] = "This is a test data file.\x0d\x0a";
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/ok-legacy-sig-2015-01-extended.gtts"), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, strlen(doc));
	CuAssert(tc, "Failed to verify valid document", res == KSI_OK);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, sizeof(doc));
	CuAssert(tc, "Verification did not fail with expected error.", res == KSI_VERIFICATION_FAILURE);

	KSI_Signature_free(sig);
}

static void testRFC3161WrongChainIndex(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/nok-legacy-sig-2015-01-chainIndex.gtts"), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_verify(sig, ctx);
	CuAssert(tc, "Failed to verify valid document", res == KSI_OK);

	KSI_Signature_free(sig);
}

static void testRFC3161WrongAggreTime(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/nok-legacy-sig-2015-01-aggretime.gtts"), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_verify(sig, ctx);
	CuAssert(tc, "Failed to verify valid document", res == KSI_VERIFICATION_FAILURE);

	KSI_Signature_free(sig);
}

static void testRFC3161WrongInputHash(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/nok-legacy-sig-2015-01-inHash.gtts"), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_verify(sig, ctx);
	CuAssert(tc, "Failed to verify valid document", res == KSI_VERIFICATION_FAILURE);

	KSI_Signature_free(sig);
}

static void testVerifySignatureExtendedToHead(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/ok-sig-2014-04-30.1-head.ksig"), &sig);
	CuAssert(tc, "Signature should have either a calendar auth record or publication", res == KSI_OK && sig != NULL);

	/* Set the extend response. */
	KSITest_setFileMockResponse(tc, getFullResourcePath("resource/tlv/ok-sig-2014-04-30.1-head-extend_response.tlv"));

	res = KSI_Signature_verifyOnline(sig, ctx);
	CuAssert(tc, "Signature should verify", res == KSI_OK);

	KSI_Signature_free(sig);

}


static void testSignatureSigningTime(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_Integer *sigTime = NULL;
	KSI_uint64_t utc = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getSigningTime(sig, &sigTime);
	CuAssert(tc, "Unable to get signing time from signature", res == KSI_OK && sigTime != NULL);

	utc = KSI_Integer_getUInt64(sigTime);

	CuAssert(tc, "Unexpected signature signing time.", utc == 1398866256);

	KSI_Signature_free(sig);
}


static void testSerializeSignature(CuTest *tc) {
	int res;

	unsigned char in[0x1ffff];
	unsigned in_len = 0;

	unsigned char *out = NULL;
	unsigned out_len = 0;

	FILE *f = NULL;

	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	f = fopen(getFullResourcePath(TEST_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);

	res = KSI_Signature_parse(ctx, in, in_len, &sig);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sig != NULL);

	res = KSI_Signature_serialize(sig, &out, &out_len);
	CuAssert(tc, "Failed to serialize signature", res == KSI_OK);
	CuAssert(tc, "Serialized signature length mismatch", in_len == out_len);
	CuAssert(tc, "Serialized signature content mismatch", !memcmp(in, out, in_len));

	KSI_free(out);
	KSI_Signature_free(sig);
}

static void testVerifyDocument(CuTest *tc) {
	int res;

	unsigned char in[0x1ffff];
	unsigned in_len = 0;

	char doc[] = "LAPTOP";

	FILE *f = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	f = fopen(getFullResourcePath(TEST_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);

	res = KSI_Signature_parse(ctx, in, in_len, &sig);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sig != NULL);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, strlen(doc));
	CuAssert(tc, "Failed to verify valid document", res == KSI_OK);

	res = KSI_Signature_verifyDocument(sig, ctx, doc, sizeof(doc));
	CuAssert(tc, "Verification did not fail with expected error.", res == KSI_VERIFICATION_FAILURE);

	KSI_Signature_free(sig);
}

static void testVerifyDocumentHash(CuTest *tc) {
	int res;

	unsigned char in[0x1ffff];
	unsigned in_len = 0;

	char doc[] = "LAPTOP";
	KSI_DataHash *hsh = NULL;

	FILE *f = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	f = fopen(getFullResourcePath(TEST_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);

	res = KSI_Signature_parse(ctx, in, in_len, &sig);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sig != NULL);

	/* Chech correct document. */
	res = KSI_DataHash_create(ctx, doc, strlen(doc), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Failed to create data hash", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_verifyDataHash(sig, ctx, hsh);
	CuAssert(tc, "Failed to verify valid document", res == KSI_OK);

	KSI_DataHash_free(hsh);
	hsh = NULL;

	/* Chech wrong document. */
	res = KSI_DataHash_create(ctx, doc, sizeof(doc), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Failed to create data hash", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_verifyDataHash(sig, ctx, hsh);
	CuAssert(tc, "Verification did not fail with expected error.", res == KSI_VERIFICATION_FAILURE);

	KSI_DataHash_free(hsh);
	hsh = NULL;

	/* Check correct document with wrong hash algorithm. */
	res = KSI_DataHash_create(ctx, doc, strlen(doc), KSI_HASHALG_SHA2_512, &hsh);
	CuAssert(tc, "Failed to create data hash", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_verifyDataHash(sig, ctx, hsh);
	CuAssert(tc, "Verification did not fail with expected error.", res == KSI_VERIFICATION_FAILURE);

	KSI_DataHash_free(hsh);


	KSI_Signature_free(sig);
}

static void testSignerIdentity(CuTest *tc) {
	int res;
	const char id_expected[] = "GT :: testA :: 36-test";
	KSI_Signature *sig = NULL;
	char *id_actual = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/ok-sig-2014-08-01.1.ksig"), &sig);
	CuAssert(tc, "Unable to load signature", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getSignerIdentity(sig, &id_actual);
	CuAssert(tc, "Unable to get signer identity from signature.", res == KSI_OK && id_actual != NULL);

	CuAssert(tc, "Unexpected signer identity", !strncmp(id_expected, id_actual, strlen(id_expected)));

	KSI_Signature_free(sig);
	KSI_free(id_actual);

}

static void testSignatureWith2Anchors(CuTest *tc) {
	KSI_Signature *sig = NULL;
	int res;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/nok-sig-two-anchors.tlv"), &sig);
	CuAssert(tc, "Reading a signature with more than one trust anchor should result in format error.", res == KSI_INVALID_FORMAT && sig == NULL);

	KSI_Signature_free(sig);
}

CuSuite* KSITest_Signature_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testLoadSignatureFromFile);
	SUITE_ADD_TEST(suite, testSignatureSigningTime);
	SUITE_ADD_TEST(suite, testSerializeSignature);
	SUITE_ADD_TEST(suite, testVerifyDocument);
	SUITE_ADD_TEST(suite, testVerifyDocumentHash);
	SUITE_ADD_TEST(suite, testVerifySignatureNew);
	SUITE_ADD_TEST(suite, testVerifySignatureWithPublication);
	SUITE_ADD_TEST(suite, testVerifySignatureWithUserPublication);
	SUITE_ADD_TEST(suite, testVerifySignatureExtendedToHead);
	SUITE_SKIP_TEST(suite, testVerifyLegacySignatureAndDoc, "Taavi Valjaots", "Cert not found.");
	SUITE_SKIP_TEST(suite, testVerifyLegacyExtendedSignatureAndDoc, "Taavi Valjaots", "Cert not found.");
	SUITE_SKIP_TEST(suite, testRFC3161WrongChainIndex, "Taavi Valjaots", "Cert not found.");
	SUITE_ADD_TEST(suite, testRFC3161WrongAggreTime);
	SUITE_ADD_TEST(suite, testRFC3161WrongInputHash);
	SUITE_ADD_TEST(suite, testSignerIdentity);
	SUITE_ADD_TEST(suite, testSignatureWith2Anchors);

	return suite;
}
