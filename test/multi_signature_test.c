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
#include <string.h>

#include <ksi/multi_signature.h>
#include "../src/ksi/multi_signature_impl.h"
#include "all_tests.h"
#include "ksi/tlv.h"

extern KSI_CTX *ctx;

#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EX_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

static void testAddingSingle(CuTest* tc) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_MultiSignature *ms = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_MultiSignature_new(ctx, &ms);
	CuAssert(tc, "Unable to create multi signature container.", res == KSI_OK && ms != NULL);

	res = KSI_MultiSignature_add(ms, sig);
	CuAssert(tc, "Unable to add signature to multi signature container.", res == KSI_OK);

	KSI_MultiSignature_free(ms);
	KSI_Signature_free(sig);

}

static void testExtractingSingle(CuTest* tc) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_MultiSignature *ms = NULL;
	KSI_DataHash *hsh = NULL;


	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getDocumentHash(sig, &hsh);
	CuAssert(tc, "Unable to get signed hash value.", res == KSI_OK && hsh != NULL);

	KSI_DataHash_ref(hsh);

	res = KSI_MultiSignature_new(ctx, &ms);
	CuAssert(tc, "Unable to create multi signature container.", res == KSI_OK && ms != NULL);

	res = KSI_MultiSignature_add(ms, sig);
	CuAssert(tc, "Unable to add signature to multi signature container.", res == KSI_OK);

	KSI_Signature_free(sig);
	sig = NULL;

	res = KSI_MultiSignature_get(ms, hsh, &sig);
	CuAssert(tc, "Unable to extract signature from multi signature container.", res == KSI_OK && sig != NULL);

	res = KSI_verifySignature(ctx, sig);
	CuAssert(tc, "Unable to verify extracted signature.", res == KSI_OK);

	KSI_DataHash_free(hsh);
	KSI_MultiSignature_free(ms);
	KSI_Signature_free(sig);
}

static void testExtractingSingleLegacy(CuTest* tc) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_MultiSignature *ms = NULL;
	KSI_DataHash *hsh = NULL;


	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/ok-legacy-sig-2014-06.gtts.ksig"), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getDocumentHash(sig, &hsh);
	CuAssert(tc, "Unable to get signed hash value.", res == KSI_OK && hsh != NULL);

	KSI_DataHash_ref(hsh);

	res = KSI_MultiSignature_new(ctx, &ms);
	CuAssert(tc, "Unable to create multi signature container.", res == KSI_OK && ms != NULL);

	res = KSI_MultiSignature_add(ms, sig);
	CuAssert(tc, "Unable to add signature to multi signature container.", res == KSI_OK);

	KSI_Signature_free(sig);
	sig = NULL;

	res = KSI_MultiSignature_get(ms, hsh, &sig);
	CuAssert(tc, "Unable to extract signature from multi signature container.", res == KSI_OK && sig != NULL);

	res = KSI_verifySignature(ctx, sig);
	CuAssert(tc, "Unable to verify extracted signature.", res == KSI_OK);

	KSI_DataHash_free(hsh);
	KSI_MultiSignature_free(ms);
	KSI_Signature_free(sig);
}

static void testExtractingNotExisting(CuTest* tc) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_MultiSignature *ms = NULL;
	KSI_DataHash *hsh = NULL;


	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_MultiSignature_new(ctx, &ms);
	CuAssert(tc, "Unable to create multi signature container.", res == KSI_OK && ms != NULL);

	res = KSI_MultiSignature_add(ms, sig);
	CuAssert(tc, "Unable to add signature to multi signature container.", res == KSI_OK);

	KSI_Signature_free(sig);
	sig = NULL;

	KSITest_DataHash_fromStr(ctx, "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd", &hsh);

	res = KSI_MultiSignature_get(ms, hsh, &sig);
	CuAssert(tc, "Get should fail with KSI_MULTISIG_NOT_FOUND", res == KSI_MULTISIG_NOT_FOUND && sig == NULL);

	KSI_DataHash_free(hsh);
	KSI_MultiSignature_free(ms);
	KSI_Signature_free(sig);
}

static void testOnlyStrongestProofReturned(CuTest* tc) {
	int res;
	KSI_Signature *sig1 = NULL;
	KSI_Signature *sig2 = NULL;
	KSI_Signature *sig3 = NULL;
	KSI_MultiSignature *ms = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_PublicationRecord *publication = NULL;
	KSI_CalendarAuthRec *calAuth = NULL;


	KSI_ERR_clearErrors(ctx);

	res = KSI_MultiSignature_new(ctx, &ms);
	CuAssert(tc, "Unable to create multi signature container.", res == KSI_OK && ms != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig1);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig1 != NULL);

	res = KSI_MultiSignature_add(ms, sig1);
	CuAssert(tc, "Unable to add signature to multi signature container.", res == KSI_OK);


	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EX_SIGNATURE_FILE), &sig2);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig2 != NULL);

	res = KSI_MultiSignature_add(ms, sig2);
	CuAssert(tc, "Unable to add signature to multi signature container.", res == KSI_OK);

	res = KSI_Signature_getDocumentHash(sig1, &hsh);
	CuAssert(tc, "Unable to get signed hash value.", res == KSI_OK && hsh != NULL);

	res = KSI_MultiSignature_get(ms, hsh, &sig3);
	CuAssert(tc, "Unable to extract signature from multi signature container.", res == KSI_OK && sig3 != NULL);

	res = KSI_verifySignature(ctx, sig3);
	CuAssert(tc, "Unable to verify extracted signature.", res == KSI_OK);

	/* Verify the signature has a publication attached to it. */
	res = KSI_Signature_getPublicationRecord(sig3, &publication);
	CuAssert(tc, "Publication must be present", res == KSI_OK && publication != NULL);

	/* Verify the signature does not contain a calendar authentication record. */
	res = KSI_Signature_getCalendarAuthRec(sig3, &calAuth);
	CuAssert(tc, "Signature may not have a calendar auth record and a publication.", res == KSI_OK && calAuth == NULL);

	KSI_MultiSignature_free(ms);
	KSI_Signature_free(sig1);
	KSI_Signature_free(sig2);
	KSI_Signature_free(sig3);

}

static void testExtractingFromEmpty(CuTest* tc) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_MultiSignature *ms = NULL;
	KSI_DataHash *hsh = NULL;

	KSI_ERR_clearErrors(ctx);

	KSITest_DataHash_fromStr(ctx, "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd", &hsh);

	res = KSI_MultiSignature_new(ctx, &ms);
	CuAssert(tc, "Unable to create multi signature container.", res == KSI_OK && ms != NULL);

	res = KSI_MultiSignature_get(ms, hsh, &sig);
	CuAssert(tc, "Get should fail with KSI_MULTISIG_NOT_FOUND", res == KSI_MULTISIG_NOT_FOUND && sig == NULL);

	KSI_DataHash_free(hsh);
	KSI_MultiSignature_free(ms);
	KSI_Signature_free(sig);
}

static void testgetUsedHashAlgorithmsFromEmpty(CuTest *tc) {
	int res;
	KSI_MultiSignature *ms = NULL;
	KSI_HashAlgorithm *arr = NULL;
	size_t arr_len;

	res = KSI_MultiSignature_new(ctx, &ms);
	CuAssert(tc, "Unable to create multi signature container.", res == KSI_OK && ms != NULL);

	res = KSI_MultiSignature_getUsedHashAlgorithms(ms, &arr, &arr_len);
	CuAssert(tc, "Function should be successful", res == KSI_OK);
	CuAssert(tc, "Number of used hash algorithms should be 0", arr_len == 0);
	CuAssert(tc, "If there are no used algorithms, the output pointer should be NULL", arr == NULL);

	KSI_MultiSignature_free(ms);
	KSI_free(arr);
}

static void testgetUsedHashAlgorithmsFromSingle(CuTest *tc) {
	int res;
	KSI_MultiSignature *ms = NULL;
	KSI_Signature *sig = NULL;
	KSI_HashAlgorithm *arr = NULL;
	size_t arr_len;

	res = KSI_MultiSignature_new(ctx, &ms);
	CuAssert(tc, "Unable to create multi signature container.", res == KSI_OK && ms != NULL);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_MultiSignature_add(ms, sig);
	CuAssert(tc, "Unable to add signature to multi signature container.", res == KSI_OK);
	KSI_Signature_free(sig);

	res = KSI_MultiSignature_getUsedHashAlgorithms(ms, &arr, &arr_len);
	CuAssert(tc, "Function should be successful", res == KSI_OK);
	CuAssert(tc, "Unexpected number of hash algorithms", arr_len == 1);
	CuAssert(tc, "If there are used algorithms, the output pointer should not be NULL", arr != NULL);
	CuAssert(tc, "Unexpected hash algorithm", arr[0] == KSI_HASHALG_SHA2_256);

	KSI_MultiSignature_free(ms);
	KSI_free(arr);
}

static void testgetUsedHashAlgorithmsFromSingleLegacy(CuTest *tc) {
	int res;
	KSI_MultiSignature *ms = NULL;
	KSI_Signature *sig = NULL;
	KSI_HashAlgorithm *arr = NULL;
	size_t arr_len;

	res = KSI_MultiSignature_new(ctx, &ms);
	CuAssert(tc, "Unable to create multi signature container.", res == KSI_OK && ms != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/ok-legacy-sig-2014-06.gtts.ksig"), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_MultiSignature_add(ms, sig);
	CuAssert(tc, "Unable to add signature to multi signature container.", res == KSI_OK);
	KSI_Signature_free(sig);

	res = KSI_MultiSignature_getUsedHashAlgorithms(ms, &arr, &arr_len);
	CuAssert(tc, "Function should be successful", res == KSI_OK);
	CuAssert(tc, "Unexpected number of hash algorithms", arr_len == 1);
	CuAssert(tc, "If there are used algorithms, the output pointer should not be NULL", arr != NULL);
	CuAssert(tc, "Unexpected hash algorithm", arr[0] == KSI_HASHALG_SHA2_256);

	KSI_MultiSignature_free(ms);
	KSI_free(arr);
}

static void testDeleteSignatureAppendedFromFile(CuTest *tc, const char *fname) {
	int res;
	KSI_MultiSignature *ms = NULL;
	KSI_Signature *sig = NULL;
	KSI_HashAlgorithm *arr = NULL;
	KSI_DataHash *hsh = NULL;

	res = KSI_MultiSignature_new(ctx, &ms);
	CuAssert(tc, "Unable to create multi signature container.", res == KSI_OK && ms != NULL);

	res = KSI_Signature_fromFile(ctx, fname, &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getDocumentHash(sig, &hsh);
	CuAssert(tc, "Unable to retrieve signed document hash from the signature.", res == KSI_OK && hsh != NULL);
	KSI_DataHash_ref(hsh);

	res = KSI_MultiSignature_add(ms, sig);
	CuAssert(tc, "Unable to add signature to multi signature container.", res == KSI_OK);

	KSI_Signature_free(sig);
	sig = NULL;

	res = KSI_MultiSignature_remove(ms, hsh);
	CuAssert(tc, "Unable to remove signature.", res == KSI_OK);

	res = KSI_MultiSignature_get(ms, hsh, &sig);
	CuAssert(tc, "There should not be a signature with this hash value anymore.", res == KSI_MULTISIG_NOT_FOUND && sig == NULL);
	/* TimeMapper list functions are not exported so we need to cast to generic list. */
	CuAssert(tc, "The internal structure should be empty", KSI_List_length((KSI_List *)ms->timeList) == 0);

	KSI_MultiSignature_free(ms);
	KSI_DataHash_free(hsh);
	KSI_free(arr);
}

static void testDeleteLast(CuTest *tc) {
	testDeleteSignatureAppendedFromFile(tc, getFullResourcePath(TEST_SIGNATURE_FILE));
}

static void testDeleteLegacySignature(CuTest *tc) {
	testDeleteSignatureAppendedFromFile(tc, getFullResourcePath("resource/tlv/ok-legacy-sig-2014-06.gtts.ksig"));
}

static void createMultiSignature(KSI_MultiSignature **ms) {
	const char *signatures[] = {TEST_SIGNATURE_FILE, TEST_EX_SIGNATURE_FILE, NULL};
	KSI_MultiSignature *tmp = NULL;
	KSI_Signature *sig = NULL;
	size_t i;

	KSI_MultiSignature_new(ctx, &tmp);
	for (i = 0; signatures[i] != NULL; i++) {
		KSI_Signature_fromFile(ctx, getFullResourcePath(signatures[i]), &sig);
		KSI_MultiSignature_add(tmp, sig);
		KSI_Signature_free(sig);
	}

	*ms = tmp;
}

static void createMultiSignatureFromFile(CuTest *tc, const char *fn, KSI_MultiSignature **ms) {
	int res;
	FILE *f = NULL;
	size_t buf_len;
	unsigned char buf[0x1ffff]; /* Hope this is enough for all the tests. */

	f = fopen(fn, "rb");
	CuAssert(tc, "Unable to load test file.", f != NULL);

	buf_len = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	CuAssert(tc, "Read 0 bytes from input file.", buf_len > 0);

	res = KSI_MultiSignature_parse(ctx, buf, buf_len, ms);
	CuAssert(tc, "Unable to parse multi signature container file.", res == KSI_OK && ms != NULL);
}

static void testSerialize(CuTest *tc) {
	int res;
	KSI_MultiSignature *ms = NULL;
	unsigned char buf[0xffff]; /* Increase the size if more samples are added. */
	size_t buf_len;

	createMultiSignature(&ms);

	res = KSI_MultiSignature_writeBytes(ms, buf, sizeof(buf), &buf_len, 0);
	CuAssert(tc, "Unable to serialize multi signature container.", res == KSI_OK && buf_len > 0);

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Multi signature", buf, buf_len);

	KSI_MultiSignature_free(ms);

}

static void testSerializeLength(CuTest *tc) {
	int res;
	KSI_MultiSignature *ms = NULL;
	unsigned char buf[0xffff]; /* Increase the size if more samples are added. */
	size_t buf_len1, buf_len2;

	createMultiSignature(&ms);

	res = KSI_MultiSignature_writeBytes(ms, NULL, 0, &buf_len1, 0);
	CuAssert(tc, "Unable to get the length of serialized multi signature container", res == KSI_OK && buf_len1 > 0);

	res = KSI_MultiSignature_writeBytes(ms, buf, sizeof(buf), &buf_len2, 0);
	CuAssert(tc, "Unable to get the length of serialized multi signature container", res == KSI_OK && buf_len2 > 0);
	CuAssert(tc, "Calculated length and actual length mismatch.", buf_len1 == buf_len2);

	KSI_MultiSignature_free(ms);

}

static void testMultiSerializeSignature(CuTest *tc) {
	int res;
	KSI_MultiSignature *ms = NULL;
	unsigned char *buf = NULL;
	size_t buf_len;

	createMultiSignature(&ms);

	res = KSI_MultiSignature_serialize(ms, &buf, &buf_len);
	CuAssert(tc, "Unable to serialize multi signature container.", res == KSI_OK && buf_len > 0);

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Multi signature", buf, buf_len);

	KSI_MultiSignature_free(ms);
	KSI_free(buf);
}

static void testParse(CuTest *tc) {
	int res;
	FILE *f = NULL;
	unsigned char buf[0xffff]; /* Increase the size if more samples are added to the file. */
	size_t buf_len;
	KSI_MultiSignature *ms = NULL;

	f = fopen(getFullResourcePath("resource/multi_sig/test1.mksi"), "rb");
	CuAssert(tc, "Unable to load test file.", f != NULL);

	buf_len = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	CuAssert(tc, "Read 0 bytes from input file.", buf_len > 0);

	res = KSI_MultiSignature_parse(ctx, buf, buf_len, &ms);
	CuAssert(tc, "Unable to parse multi signature container file.", res == KSI_OK && ms != NULL);

	KSI_MultiSignature_free(ms);
}

static void testParseAndVerifySingle(CuTest *tc) {
	int res;
	KSI_MultiSignature *ms = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	createMultiSignatureFromFile(tc, getFullResourcePath("resource/multi_sig/test1.mksi"), &ms);

	KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);

	res = KSI_MultiSignature_get(ms, hsh, &sig);
	CuAssert(tc, "Unable to get signature from container.", res == KSI_OK && sig != NULL);

	res = KSI_verifySignature(ctx, sig);
	CuAssert(tc, "Unable to verify signature extracted from container.", res == KSI_OK);

	KSI_Signature_free(sig);
	KSI_DataHash_free(hsh);
	KSI_MultiSignature_free(ms);
}

static void testGetOldest(CuTest *tc) {
	int res;
	KSI_MultiSignature *ms = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_Integer *tm = NULL;

	res = KSI_MultiSignature_fromFile(ctx, getFullResourcePath("resource/multi_sig/test2.mksi"), &ms);
	CuAssert(tc, "Unable to read multi signature container from file.", res == KSI_OK && ms != NULL);

	KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);

	res = KSI_MultiSignature_get(ms, hsh, &sig);
	CuAssert(tc, "Unable to get signature from container.", res == KSI_OK && sig != NULL);

	res = KSI_verifySignature(ctx, sig);
	CuAssert(tc, "Unable to verify signature extracted from container.", res == KSI_OK);

	res = KSI_Signature_getSigningTime(sig, &tm);
	CuAssert(tc, "Wrong signing time (probably returning the newer signature).", res == KSI_OK && KSI_Integer_equalsUInt(tm, 1398866256));

	KSI_Signature_free(sig);
	KSI_DataHash_free(hsh);
	KSI_MultiSignature_free(ms);
}

static void testExtend(CuTest *tc) {
	int res;
	KSI_MultiSignature *ms = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_PublicationRecord *pubRec = NULL;

	res = KSI_MultiSignature_fromFile(ctx, getFullResourcePath("resource/multi_sig/test2.mksi"), &ms);
	CuAssert(tc, "Unable to read multi signature container from file.", res == KSI_OK && ms != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri("resource/multi_sig/test2-extend_response-multiple.tlv"), "anon", "anon");
	CuAssert(tc, "Unable to set extender response from file", res == KSI_OK);

	res = KSI_MultiSignature_extend(ms);
	CuAssert(tc, "Unable to perform multi signature container extension.", res == KSI_OK);

	KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);

	res = KSI_MultiSignature_get(ms, hsh, &sig);
	CuAssert(tc, "Unable to get signature from container.", res == KSI_OK && sig != NULL);

	res = KSI_verifySignature(ctx, sig);
	CuAssert(tc, "Unable to verify signature extracted from container.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(sig, &pubRec);
	CuAssert(tc, "Signature should be extended.", res == KSI_OK && pubRec != NULL);

	KSI_Signature_free(sig);
	KSI_DataHash_free(hsh);
	KSI_MultiSignature_free(ms);
}

static void preTest(void) {
}

CuSuite* KSITest_multiSignature_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, testAddingSingle);
	SUITE_ADD_TEST(suite, testExtractingSingle);
	SUITE_ADD_TEST(suite, testExtractingSingleLegacy);
	SUITE_ADD_TEST(suite, testOnlyStrongestProofReturned);
	SUITE_ADD_TEST(suite, testExtractingNotExisting);
	SUITE_ADD_TEST(suite, testExtractingFromEmpty);

	SUITE_ADD_TEST(suite, testgetUsedHashAlgorithmsFromEmpty);
	SUITE_ADD_TEST(suite, testgetUsedHashAlgorithmsFromSingle);
	SUITE_ADD_TEST(suite, testgetUsedHashAlgorithmsFromSingleLegacy);
	SUITE_ADD_TEST(suite, testDeleteLast);
	SUITE_ADD_TEST(suite, testDeleteLegacySignature);

	SUITE_ADD_TEST(suite, testSerialize);
	SUITE_ADD_TEST(suite, testSerializeLength);
	SUITE_ADD_TEST(suite, testMultiSerializeSignature);

	SUITE_ADD_TEST(suite, testParse);
	SUITE_ADD_TEST(suite, testParseAndVerifySingle);

	SUITE_ADD_TEST(suite, testExtend);
	SUITE_ADD_TEST(suite, testGetOldest);

	return suite;
}
