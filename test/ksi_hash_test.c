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

#include "cutest/CuTest.h"
#include "all_tests.h"

extern KSI_CTX *ctx;

#define KSITest_assertCreateCall(tc, errm, res, obj) if ((res) != KSI_OK) KSI_ERR_statusDump(ctx, stdout); CuAssert(tc, errm ": error returned", (res) == KSI_OK); CuAssert(tc, errm ": object is NULL", (obj) != NULL);

static void TestSHA256(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	char *data = "correct horse battery staple";
	unsigned char expected[] = {0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	const unsigned char *digest = NULL;
	size_t digest_length = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	KSITest_assertCreateCall(tc, "Failed to open DataHasher", res, hsr);

	res = KSI_DataHasher_add(hsr, (unsigned char *)data, strlen(data));
	CuAssert(tc, "Failed to add data", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	KSITest_assertCreateCall(tc, "Failed to close hasher", res, hsh);

	res = KSI_DataHash_extract(hsh, NULL, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest length", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, digest, digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void TestSHA256OnEmptyData(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	char buf[1];
	unsigned char expected[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

	const unsigned char *digest = NULL;
	size_t digest_length = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	KSITest_assertCreateCall(tc, "Failed to open DataHasher", res, hsr);

	res = KSI_DataHasher_add(hsr, (unsigned char *)buf, 0);
	CuAssert(tc, "Failed to add data of length 0.", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	KSITest_assertCreateCall(tc, "Failed to close hasher.", res, hsh);

	res = KSI_DataHash_extract(hsh, NULL, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest lenght mismatch", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, digest, digest_length));


	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}


static void TestSHA256Parts(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	char *data[] = {"correct ", "horse ", "battery ", "staple", NULL };
	unsigned i = 0;
	unsigned char expected[] = {0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	const unsigned char *digest = NULL;
	size_t digest_length = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	KSITest_assertCreateCall(tc, "Failed to open DataHasher", res, hsr);

	while (data[i] != NULL) {
		res = KSI_DataHasher_add(hsr, (unsigned char *)data[i], strlen(data[i]));
		CuAssert(tc, "Failed to add data", res == KSI_OK);
		i++;
	}
	res = KSI_DataHasher_close(hsr, &hsh);
	KSITest_assertCreateCall(tc, "Failed to close hasher.", res, hsh);

	res = KSI_DataHash_extract(hsh, NULL, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest lenght mismatch", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, digest, digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void TestSHA256Reset(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	char *data = "correct horse battery staple";
	unsigned char expected[] = {0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	const unsigned char *digest = NULL;
	size_t digest_length = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	KSITest_assertCreateCall(tc, "Failed to open DataHasher", res, hsr);

	res = KSI_DataHasher_add(hsr, "TEST", strlen("TEST"));
	CuAssert(tc, "Failed to add data", res == KSI_OK);

	res = KSI_DataHasher_reset(hsr);
	CuAssert(tc, "Failed to reset hasher", res == KSI_OK);


	res = KSI_DataHasher_add(hsr, (unsigned char *)data, strlen(data));
	CuAssert(tc, "Failed to add data", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	KSITest_assertCreateCall(tc, "Failed to close hasher", res, hsh);

	res = KSI_DataHash_extract(hsh, NULL, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest lenght mismatch", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, digest, digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void TestSHA256Empty(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char expected[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

	const unsigned char *digest = NULL;
	size_t digest_length = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	KSITest_assertCreateCall(tc, "Failed to open DataHasher", res, hsr);

	res = KSI_DataHasher_add(hsr, "TEST", strlen("TEST"));
	CuAssert(tc, "Failed to add data", res == KSI_OK);

	res = KSI_DataHasher_reset(hsr);
	CuAssert(tc, "Failed to reset hasher", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	KSITest_assertCreateCall(tc, "Failed to close empty hasher.", res, hsh);

	res = KSI_DataHash_extract(hsh, NULL, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest lenght mismatch", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, digest, digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void TestSHA256GetData(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char expected[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
	const unsigned char *digest = NULL;
	size_t digest_length;
	KSI_HashAlgorithm algo_id;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	CuAssert(tc, "Failed to open DataHasher", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Failed to close empty hasher.", res == KSI_OK && hsh != NULL);

	res = KSI_DataHash_extract(hsh, &algo_id, &digest, &digest_length);
	CuAssert(tc, "Failed to get data from data hash object.", res == KSI_OK && digest != NULL);
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA2_256, algo_id);
	CuAssert(tc, "Digest lenght mismatch", sizeof(expected) == digest_length);

	CuAssert(tc, "Digest lenght mismatch", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, digest, digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void TestSHA256GetImprint(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char expected[] = {KSI_HASHALG_SHA2_256, 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
	const unsigned char *imprint = NULL;
	size_t imprint_length;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	CuAssert(tc, "Failed to open DataHasher", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Failed to close empty hasher.", res == KSI_OK && hsh != NULL);

	res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_length);
	CuAssert(tc, "Failed to get imprint from data hash object.", res == KSI_OK && imprint != NULL);
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA2_256, *imprint);
	CuAssert(tc, "Imprint lenght mismatch", sizeof(expected) == imprint_length);

	CuAssert(tc, "Imprint lenght mismatch", sizeof(expected) == imprint_length);
	CuAssert(tc, "Imprint value mismatch", !memcmp(expected, imprint, imprint_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void TestSHA256fromImprint(CuTest* tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	unsigned char expected[] = {KSI_HASHALG_SHA2_256, 0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	const unsigned char *imprint = NULL;
	size_t imprint_length;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromImprint(ctx, expected, sizeof(expected), &hsh);
	CuAssert(tc, "Failed to get data hash from imprint.", res == KSI_OK && hsh != NULL);

	res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_length);
	CuAssert(tc, "Failed to get imprint from data hash object.", res == KSI_OK && imprint != NULL);
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA2_256, *imprint);
	CuAssert(tc, "Imprint lenght mismatch", sizeof(expected) == imprint_length);

	CuAssert(tc, "Imprint lenght mismatch", sizeof(expected) == imprint_length);
	CuAssert(tc, "Imprint value mismatch", !memcmp(expected, imprint, imprint_length));

	KSI_DataHash_free(hsh);
}

static void TestParallelHashing(CuTest* tc) {
	int res;
	char data[] = "I'll be Bach";
	char *ptr = data;
	unsigned char exp1[0xff];
	size_t exp1_len = 0;
	unsigned char exp2[0xff];
	size_t exp2_len;

	KSI_DataHasher *hsr1 = NULL;
	KSI_DataHasher *hsr2 = NULL;
	KSI_DataHash *hsh1 = NULL;
	KSI_DataHash *hsh2 = NULL;

	const unsigned char *digest = NULL;
	size_t digest_length = 0;
	KSI_HashAlgorithm algo_id = 0;

	KSITest_decodeHexStr("a0dc7b252059b9a742722508de940a6a208574dd", exp1, sizeof(exp1), &exp1_len);
	KSITest_decodeHexStr("72d0c4f2cb390540f925c8e5d5dde7ed7ffc2a6b722eaab979f854d1c273b35e", exp2, sizeof(exp2), &exp2_len);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA1, &hsr1);
	CuAssert(tc, "Failed to open hasher", res == KSI_OK && hsr1 != NULL);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr2);
	CuAssert(tc, "Failed to open hasher", res == KSI_OK && hsr2 != NULL);

	while (*ptr) {
		res = KSI_DataHasher_add(hsr1, ptr, 1);
		CuAssert(tc, "Unable to add data to hasher", res == KSI_OK);

		res = KSI_DataHasher_add(hsr2, ptr, 1);
		CuAssert(tc, "Unable to add data to hasher", res == KSI_OK);

		ptr++;
	}

	res = KSI_DataHasher_close(hsr1, &hsh1);
	CuAssert(tc, "Unable to close hasher", res == KSI_OK && hsh1 != NULL);

	res = KSI_DataHash_extract(hsh1, &algo_id, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest length mismatch", exp1_len == digest_length);
	CuAssert(tc, "Digest mismatch", !memcmp(exp1, digest, exp1_len));
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA1, algo_id);

	res = KSI_DataHasher_close(hsr2, &hsh2);
	CuAssert(tc, "Unable to close hasher", res == KSI_OK && hsh2 != NULL);

	res = KSI_DataHash_extract(hsh2, &algo_id, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest length mismatch", exp2_len == digest_length);
	CuAssert(tc, "Digest mismatch", !memcmp(exp2, digest, exp2_len));
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA2_256, algo_id);

	KSI_DataHash_free(hsh1);
	KSI_DataHash_free(hsh2);
	KSI_DataHasher_free(hsr1);
	KSI_DataHasher_free(hsr2);
}

static void TestHashGetAlgByName(CuTest* tc) {
	KSI_HashAlgorithm algo;
	CuAssertIntEquals_Msg(tc, "Default algorithm", KSI_HASHALG_SHA2_256, algo = KSI_getHashAlgorithmByName("default"));
	CuAssert(tc, "Algorithm must be trusted", KSI_isHashAlgorithmTrusted(algo));

	CuAssertIntEquals_Msg(tc, "Sha2 algorithm", KSI_HASHALG_SHA2_256, algo = KSI_getHashAlgorithmByName("Sha2"));
	CuAssert(tc, "Algorithm must be trusted", KSI_isHashAlgorithmTrusted(algo));

	CuAssertIntEquals_Msg(tc, "Sha-2 algorithm", KSI_HASHALG_SHA2_256, algo = KSI_getHashAlgorithmByName("Sha-2"));
	CuAssert(tc, "Algorithm must be trusted", KSI_isHashAlgorithmTrusted(algo));

	CuAssertIntEquals_Msg(tc, "Sha3-256 algorithm", KSI_HASHALG_SHA3_256, algo = KSI_getHashAlgorithmByName("Sha3-256"));
	CuAssert(tc, "Algorithm must be trusted", KSI_isHashAlgorithmTrusted(algo));

	CuAssertIntEquals_Msg(tc, "Sha3 algorithm", KSI_HASHALG_INVALID, algo = KSI_getHashAlgorithmByName("SHA3"));
	CuAssert(tc, "Algorithm must be trusted", !KSI_isHashAlgorithmTrusted(algo));

	CuAssertIntEquals_Msg(tc, "Sha3_384 algorithm", KSI_HASHALG_SHA3_384, algo = KSI_getHashAlgorithmByName("Sha3_384"));
	CuAssert(tc, "Algorithm must be trusted", KSI_isHashAlgorithmTrusted(algo));

	CuAssertIntEquals_Msg(tc, "SHA2,SHA-2 algorithm", KSI_HASHALG_INVALID, algo = KSI_getHashAlgorithmByName("SHA2,SHA-2"));
	CuAssert(tc, "Algorithm must be trusted", !KSI_isHashAlgorithmTrusted(algo));

}

static void TestIncorrectHashLen(CuTest* tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	static unsigned char badImprit1[] = {0x01, 0x02, 0x03};
	static unsigned char badImprint2[] = { 0x01, 0x01, 0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromImprint(ctx, badImprit1, sizeof(badImprit1), &hsh);
	CuAssert(tc, "Datahash accepts incorrectly short imprint value", res != KSI_OK && hsh == NULL);

	res = KSI_DataHash_fromImprint(ctx, badImprint2, sizeof(badImprint2), &hsh);
	CuAssert(tc, "Datahash accepts incorrectly long imprint value", res != KSI_OK && hsh == NULL);

}

static void testAllHashing(CuTest *tc) {
	const char *input = "Once I was blind but now I C!";
	const char *expected[KSI_NUMBER_OF_KNOWN_HASHALGS];
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_HashAlgorithm algo_id;

	for (algo_id = 0; algo_id < KSI_NUMBER_OF_KNOWN_HASHALGS; expected[algo_id++] = NULL);

	expected[KSI_HASHALG_SHA1] = "17feaf7afb41e469c907170915eab91aa9114c05";
	expected[KSI_HASHALG_SHA2_256] = "4d151c05f29a9757ff252ff1000fdcd28f88caaa52c020bc7d25e683890e7335";
	expected[KSI_HASHALG_RIPEMD160] = "404a79f20439e1d82492ed73ad413b6d95d643a6";
	expected[0x03] = NULL; /* Deprecated hash function. */
	expected[KSI_HASHALG_SHA2_384] = "4495385793894ac9a2cc1b2d8760da3ce50d14a193b19166417d503d853ad3588689e5a6b0e65675367394a207cac264";
	expected[KSI_HASHALG_SHA2_512] = "2dcee3bebeeec061751c7e2c886fddb069502c3c71e1f70272d77a64c092e51b6a262d208939cc557de7650da347b08f643d515ff8009a7342454e73247761dd";
	expected[0x06] = NULL; /* Deprecated hash function. */
	expected[KSI_HASHALG_SHA3_244] = "TODO!";
	expected[KSI_HASHALG_SHA3_256] = "TODO!";
	expected[KSI_HASHALG_SHA3_384] = "TODO!";
	expected[KSI_HASHALG_SHA3_512] = "TODO!";
	expected[KSI_HASHALG_SM3] = "TODO!";

	for (algo_id = 0; algo_id < KSI_NUMBER_OF_KNOWN_HASHALGS; algo_id++) {
		unsigned char expectedImprint[0xff];
		size_t expectedLen = 0;
		const unsigned char *imprint = NULL;
		size_t imprintLen;
		char errm[0x1ff];
		char tmp[0xff];

		/* Skip unsupported. */
		if (!KSI_isHashAlgorithmSupported(algo_id)) continue;


		res = KSI_DataHasher_open(ctx, algo_id, &hsr);
		CuAssert(tc, "Unable to initialize hasher", res == KSI_OK && hsr != NULL);

		res = KSI_DataHasher_add(hsr, input, strlen(input));
		CuAssert(tc, "Unable to add data to the hasher.", res == KSI_OK);

		KSI_snprintf(errm, sizeof(errm), "Unable to close data hasher for algo_id=%d (%s)", algo_id, KSI_getHashAlgorithmName(algo_id));

		res = KSI_DataHasher_close(hsr, &hsh);

		CuAssert(tc, errm, res == KSI_OK && hsh != NULL);

		KSI_snprintf(tmp, sizeof(tmp), "%02x%s", algo_id, expected[algo_id]);
		KSITest_decodeHexStr(tmp, expectedImprint, sizeof(expectedImprint), &expectedLen);

		res = KSI_DataHash_getImprint(hsh, &imprint, &imprintLen);

		CuAssert(tc, "Unable to retreive imprint value", res == KSI_OK && imprint != NULL && imprintLen > 0);

		KSI_snprintf(errm, sizeof(errm), "Hash values mismatch for algo_id=%d (%s)", algo_id, KSI_getHashAlgorithmName(algo_id));
		CuAssert(tc, errm, imprintLen == expectedLen && !memcmp(imprint, expectedImprint, imprintLen));

		imprint = NULL;
		imprintLen = 0;

		KSI_DataHash_free(hsh);
		hsh = NULL;

		KSI_DataHasher_free(hsr);
		hsr = NULL;
	}
}

static void testReset(CuTest *tc) {
	int res;
	KSI_DataHasher *hsr = NULL;

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA1, &hsr);
	CuAssert(tc, "Unable to create data hasher.", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_reset(hsr);
	CuAssert(tc, "Immediate hasher reset failed.", res == KSI_OK);

	KSI_DataHasher_free(hsr);
}

static void test_free_without_close(CuTest *tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	char data[3] = "aa\0";

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA1, &hsr);
	CuAssert(tc, "Unable to create data hasher.", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_add(hsr, data, sizeof(data));
	CuAssert(tc, "Unable to add to the hasher.", res == KSI_OK);

	KSI_DataHasher_free(hsr);
}

CuSuite* KSITest_Hash_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestSHA256);
	SUITE_ADD_TEST(suite, TestSHA256OnEmptyData);
	SUITE_ADD_TEST(suite, TestSHA256Parts);
	SUITE_ADD_TEST(suite, TestSHA256Reset);
	SUITE_ADD_TEST(suite, TestSHA256Empty);
	SUITE_ADD_TEST(suite, TestSHA256GetData);
	SUITE_ADD_TEST(suite, TestSHA256GetImprint);
	SUITE_ADD_TEST(suite, TestSHA256fromImprint);
	SUITE_ADD_TEST(suite, TestParallelHashing);
	SUITE_ADD_TEST(suite, TestHashGetAlgByName);
	SUITE_ADD_TEST(suite, TestIncorrectHashLen);
	SUITE_ADD_TEST(suite, testAllHashing);
	SUITE_ADD_TEST(suite, testReset);
	SUITE_ADD_TEST(suite, test_free_without_close);

	return suite;
}
