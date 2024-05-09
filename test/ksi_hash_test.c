/*
 * Copyright 2013-2017 Guardtime, Inc.
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

static void testSHA256(CuTest* tc) {
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
	CuAssert(tc, "Failed to add data.", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	KSITest_assertCreateCall(tc, "Failed to close hasher.", res, hsh);

	res = KSI_DataHash_extract(hsh, NULL, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest length mismatch.", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch.", !memcmp(expected, digest, digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void testSHA256OnEmptyData(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	char buf[1];
	unsigned char expected[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

	const unsigned char *digest = NULL;
	size_t digest_length = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	KSITest_assertCreateCall(tc, "Failed to open DataHasher.", res, hsr);

	res = KSI_DataHasher_add(hsr, (unsigned char *)buf, 0);
	CuAssert(tc, "Failed to add data of length 0.", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	KSITest_assertCreateCall(tc, "Failed to close hasher.", res, hsh);

	res = KSI_DataHash_extract(hsh, NULL, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest length mismatch.", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch.", !memcmp(expected, digest, digest_length));


	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}


static void testSHA256Parts(CuTest* tc) {
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
	KSITest_assertCreateCall(tc, "Failed to open DataHasher.", res, hsr);

	while (data[i] != NULL) {
		res = KSI_DataHasher_add(hsr, (unsigned char *)data[i], strlen(data[i]));
		CuAssert(tc, "Failed to add data", res == KSI_OK);
		i++;
	}
	res = KSI_DataHasher_close(hsr, &hsh);
	KSITest_assertCreateCall(tc, "Failed to close hasher.", res, hsh);

	res = KSI_DataHash_extract(hsh, NULL, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest length mismatch.", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch.", !memcmp(expected, digest, digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void testSHA256Reset(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	char *data = "correct horse battery staple";
	unsigned char expected[] = {0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	const unsigned char *digest = NULL;
	size_t digest_length = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	KSITest_assertCreateCall(tc, "Failed to open DataHasher.", res, hsr);

	res = KSI_DataHasher_add(hsr, "TEST", strlen("TEST"));
	CuAssert(tc, "Failed to add data.", res == KSI_OK);

	res = KSI_DataHasher_reset(hsr);
	CuAssert(tc, "Failed to reset hasher.", res == KSI_OK);


	res = KSI_DataHasher_add(hsr, (unsigned char *)data, strlen(data));
	CuAssert(tc, "Failed to add data.", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	KSITest_assertCreateCall(tc, "Failed to close hasher.", res, hsh);

	res = KSI_DataHash_extract(hsh, NULL, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest length mismatch.", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch.", !memcmp(expected, digest, digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void testSHA256Empty(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char expected[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

	const unsigned char *digest = NULL;
	size_t digest_length = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	KSITest_assertCreateCall(tc, "Failed to open DataHasher.", res, hsr);

	res = KSI_DataHasher_add(hsr, "TEST", strlen("TEST"));
	CuAssert(tc, "Failed to add data.", res == KSI_OK);

	res = KSI_DataHasher_reset(hsr);
	CuAssert(tc, "Failed to reset hasher.", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	KSITest_assertCreateCall(tc, "Failed to close empty hasher.", res, hsh);

	res = KSI_DataHash_extract(hsh, NULL, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest length mismatch.", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch.", !memcmp(expected, digest, digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void testSHA256GetData(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char expected[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
	const unsigned char *digest = NULL;
	size_t digest_length;
	KSI_HashAlgorithm algo_id;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	CuAssert(tc, "Failed to open DataHasher.", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Failed to close empty hasher.", res == KSI_OK && hsh != NULL);

	res = KSI_DataHash_extract(hsh, &algo_id, &digest, &digest_length);
	CuAssert(tc, "Failed to get data from data hash object.", res == KSI_OK && digest != NULL);
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA2_256, algo_id);
	CuAssert(tc, "Digest length mismatch.", sizeof(expected) == digest_length);

	CuAssert(tc, "Digest length mismatch.", sizeof(expected) == digest_length);
	CuAssert(tc, "Digest value mismatch.", !memcmp(expected, digest, digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void testSHA256GetImprint(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char expected[] = {KSI_HASHALG_SHA2_256, 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
	const unsigned char *imprint = NULL;
	size_t imprint_length;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	CuAssert(tc, "Failed to open DataHasher.", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Failed to close empty hasher.", res == KSI_OK && hsh != NULL);

	res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_length);
	CuAssert(tc, "Failed to get imprint from data hash object.", res == KSI_OK && imprint != NULL);
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA2_256, *imprint);
	CuAssert(tc, "Imprint length mismatch.", sizeof(expected) == imprint_length);

	CuAssert(tc, "Imprint length mismatch.", sizeof(expected) == imprint_length);
	CuAssert(tc, "Imprint value mismatch.", !memcmp(expected, imprint, imprint_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void testSHA256fromImprint(CuTest* tc) {
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
	CuAssert(tc, "Imprint length mismatch.", sizeof(expected) == imprint_length);

	CuAssert(tc, "Imprint length mismatch.", sizeof(expected) == imprint_length);
	CuAssert(tc, "Imprint value mismatch.", !memcmp(expected, imprint, imprint_length));

	KSI_DataHash_free(hsh);
}

static void testParallelHashing(CuTest* tc) {
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
	CuAssert(tc, "Failed to open hasher.", res == KSI_OK && hsr1 != NULL);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr2);
	CuAssert(tc, "Failed to open hasher.", res == KSI_OK && hsr2 != NULL);

	while (*ptr) {
		res = KSI_DataHasher_add(hsr1, ptr, 1);
		CuAssert(tc, "Unable to add data to hasher.", res == KSI_OK);

		res = KSI_DataHasher_add(hsr2, ptr, 1);
		CuAssert(tc, "Unable to add data to hasher.", res == KSI_OK);

		ptr++;
	}

	res = KSI_DataHasher_close(hsr1, &hsh1);
	CuAssert(tc, "Unable to close hasher.", res == KSI_OK && hsh1 != NULL);

	res = KSI_DataHash_extract(hsh1, &algo_id, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest length mismatch.", exp1_len == digest_length);
	CuAssert(tc, "Digest mismatch.", !memcmp(exp1, digest, exp1_len));
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA1, algo_id);

	res = KSI_DataHasher_close(hsr2, &hsh2);
	CuAssert(tc, "Unable to close hasher.", res == KSI_OK && hsh2 != NULL);

	res = KSI_DataHash_extract(hsh2, &algo_id, &digest, &digest_length);
	CuAssert(tc, "Failed to parse imprint.", res == KSI_OK);

	CuAssert(tc, "Digest length mismatch.", exp2_len == digest_length);
	CuAssert(tc, "Digest mismatch.", !memcmp(exp2, digest, exp2_len));
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA2_256, algo_id);

	KSI_DataHash_free(hsh1);
	KSI_DataHash_free(hsh2);
	KSI_DataHasher_free(hsr1);
	KSI_DataHasher_free(hsr2);
}

static void testHashGetAlgByName(CuTest* tc) {
	KSI_HashAlgorithm algo;
	time_t t0 = 1379408100;
	time_t t1 = 1505638500;

	CuAssertIntEquals_Msg(tc, "Default algorithm", KSI_HASHALG_SHA1, algo = KSI_getHashAlgorithmByName("SHA1"));
	CuAssert(tc, "SHA1 must be trusted before the deprecation time.", KSI_checkHashAlgorithmAt(algo, t0) == KSI_OK);
	CuAssert(tc, "SHA1 is not trusted after deprecation time.", KSI_checkHashAlgorithmAt(algo, t1) == KSI_HASH_ALGORITHM_DEPRECATED);

	CuAssertIntEquals_Msg(tc, "Default algorithm", KSI_HASHALG_SHA2_256, algo = KSI_getHashAlgorithmByName("default"));
	CuAssert(tc, "Algorithm must be trusted.", KSI_checkHashAlgorithmAt(algo, t0) == KSI_OK && KSI_checkHashAlgorithmAt(algo, t1) == KSI_OK);

	CuAssertIntEquals_Msg(tc, "Sha2 algorithm", KSI_HASHALG_SHA2_256, algo = KSI_getHashAlgorithmByName("Sha2"));
	CuAssert(tc, "Algorithm must be trusted.", KSI_checkHashAlgorithmAt(algo, t0) == KSI_OK && KSI_checkHashAlgorithmAt(algo, t1) == KSI_OK);
	CuAssert(tc, "Algorithm must be trusted.", KSI_isHashAlgorithmTrusted(algo));

	CuAssertIntEquals_Msg(tc, "Sha-2 algorithm", KSI_HASHALG_SHA2_256, algo = KSI_getHashAlgorithmByName("Sha-2"));
	CuAssert(tc, "Algorithm must be trusted.", KSI_checkHashAlgorithmAt(algo, t0) == KSI_OK && KSI_checkHashAlgorithmAt(algo, t1) == KSI_OK);
	CuAssert(tc, "Algorithm must be trusted.", KSI_isHashAlgorithmTrusted(algo));

	CuAssertIntEquals_Msg(tc, "Sha3-256 algorithm", KSI_HASHALG_SHA3_256, algo = KSI_getHashAlgorithmByName("Sha3-256"));
	CuAssert(tc, "Algorithm must be trusted.", KSI_checkHashAlgorithmAt(algo, t0) == KSI_OK && KSI_checkHashAlgorithmAt(algo, t1) == KSI_OK);
	CuAssert(tc, "Algorithm must be trusted.", KSI_isHashAlgorithmTrusted(algo));

	CuAssertIntEquals_Msg(tc, "Sha3 algorithm", -1, algo = KSI_getHashAlgorithmByName("SHA3"));
	CuAssert(tc, "Algorithm must be trusted.", KSI_checkHashAlgorithmAt(algo, t0) == KSI_UNKNOWN_HASH_ALGORITHM_ID && KSI_checkHashAlgorithmAt(algo, t1) == KSI_UNKNOWN_HASH_ALGORITHM_ID);
	CuAssert(tc, "Algorithm must be trusted.", !KSI_isHashAlgorithmTrusted(algo));

	CuAssertIntEquals_Msg(tc, "Sha3_384 algorithm", KSI_HASHALG_SHA3_384, algo = KSI_getHashAlgorithmByName("Sha3_384"));
	CuAssert(tc, "Algorithm must be trusted.", KSI_checkHashAlgorithmAt(algo, t0) == KSI_OK && KSI_checkHashAlgorithmAt(algo, t1) == KSI_OK);
	CuAssert(tc, "Algorithm must be trusted.", KSI_isHashAlgorithmTrusted(algo));

	CuAssertIntEquals_Msg(tc, "SHA2,SHA-2 algorithm", -1, algo = KSI_getHashAlgorithmByName("SHA2,SHA-2"));
	CuAssert(tc, "Algorithm must be trusted.", KSI_checkHashAlgorithmAt(algo, t0) == KSI_UNKNOWN_HASH_ALGORITHM_ID && KSI_checkHashAlgorithmAt(algo, t1) == KSI_UNKNOWN_HASH_ALGORITHM_ID);
	CuAssert(tc, "Algorithm must be trusted.", !KSI_isHashAlgorithmTrusted(algo));
}

static void testHashAlgorithmDeprecatedDates(CuTest *tc) {
	CuAssert(tc, "Invalid algorithm has no valid date.", KSI_HashAlgorithm_getDeprecatedFrom(KSI_HASHALG_INVALID_VALUE) < 0);

	CuAssert(tc, "SHA1 is deprecated as of  01.07.2016T00:00 UTC.", KSI_HashAlgorithm_getDeprecatedFrom(KSI_HASHALG_SHA1) == 1467331200);

	CuAssert(tc, "Hash algorithm should not be deprecated.", KSI_HashAlgorithm_getDeprecatedFrom(KSI_HASHALG_SHA2_256) == 0);
	CuAssert(tc, "Hash algorithm should not be deprecated.", KSI_HashAlgorithm_getDeprecatedFrom(KSI_HASHALG_RIPEMD160) == 0);
	CuAssert(tc, "Hash algorithm should not be deprecated.", KSI_HashAlgorithm_getDeprecatedFrom(KSI_HASHALG_SHA2_384) == 0);
	CuAssert(tc, "Hash algorithm should not be deprecated.", KSI_HashAlgorithm_getDeprecatedFrom(KSI_HASHALG_SHA2_512) == 0);
	CuAssert(tc, "Hash algorithm should not be deprecated.", KSI_HashAlgorithm_getDeprecatedFrom(KSI_HASHALG_SHA3_224) == 0);
	CuAssert(tc, "Hash algorithm should not be deprecated.", KSI_HashAlgorithm_getDeprecatedFrom(KSI_HASHALG_SHA3_256) == 0);
	CuAssert(tc, "Hash algorithm should not be deprecated.", KSI_HashAlgorithm_getDeprecatedFrom(KSI_HASHALG_SHA3_384) == 0);
	CuAssert(tc, "Hash algorithm should not be deprecated.", KSI_HashAlgorithm_getDeprecatedFrom(KSI_HASHALG_SHA3_512) == 0);
	CuAssert(tc, "Hash algorithm should not be deprecated.", KSI_HashAlgorithm_getDeprecatedFrom(KSI_HASHALG_SM3) == 0);
}

static void testHashAlgorithmObsoleteDates(CuTest *tc) {
	CuAssert(tc, "Invalid algorithm has no valid date.", KSI_HashAlgorithm_getObsoleteFrom(KSI_HASHALG_INVALID_VALUE) < 0);

	CuAssert(tc, "No obsolete algorithm defined.", KSI_HashAlgorithm_getObsoleteFrom(KSI_HASHALG_SHA1) == 0);
	CuAssert(tc, "No obsolete algorithm defined.", KSI_HashAlgorithm_getObsoleteFrom(KSI_HASHALG_SHA2_256) == 0);
	CuAssert(tc, "No obsolete algorithm defined.", KSI_HashAlgorithm_getObsoleteFrom(KSI_HASHALG_RIPEMD160) == 0);
	CuAssert(tc, "No obsolete algorithm defined.", KSI_HashAlgorithm_getObsoleteFrom(KSI_HASHALG_SHA2_384) == 0);
	CuAssert(tc, "No obsolete algorithm defined.", KSI_HashAlgorithm_getObsoleteFrom(KSI_HASHALG_SHA2_512) == 0);
	CuAssert(tc, "No obsolete algorithm defined.", KSI_HashAlgorithm_getObsoleteFrom(KSI_HASHALG_SHA3_224) == 0);
	CuAssert(tc, "No obsolete algorithm defined.", KSI_HashAlgorithm_getObsoleteFrom(KSI_HASHALG_SHA3_256) == 0);
	CuAssert(tc, "No obsolete algorithm defined.", KSI_HashAlgorithm_getObsoleteFrom(KSI_HASHALG_SHA3_384) == 0);
	CuAssert(tc, "No obsolete algorithm defined.", KSI_HashAlgorithm_getObsoleteFrom(KSI_HASHALG_SHA3_512) == 0);
	CuAssert(tc, "No obsolete algorithm defined.", KSI_HashAlgorithm_getObsoleteFrom(KSI_HASHALG_SM3) == 0);
}

static void testIncorrectHashLen(CuTest* tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	static unsigned char badImprit1[] = {0x01, 0x02, 0x03};
	static unsigned char badImprint2[] = { 0x01, 0x01, 0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromImprint(ctx, badImprit1, sizeof(badImprit1), &hsh);
	CuAssert(tc, "Datahash accepts incorrectly short imprint value.", res != KSI_OK && hsh == NULL);

	res = KSI_DataHash_fromImprint(ctx, badImprint2, sizeof(badImprint2), &hsh);
	CuAssert(tc, "Datahash accepts incorrectly long imprint value.", res != KSI_OK && hsh == NULL);

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
	expected[KSI_HASHALG_SHA3_224] = "TODO!";
	expected[KSI_HASHALG_SHA3_256] = "05d89ebd9e3ecb536ad11cac3bda51a7a81e043f7843274b49e7893ab161ffc6";
	expected[KSI_HASHALG_SHA3_384] = "3b45a4e97d912b2cb05f6c4ea659714c3db95280f37117a05e679338a5064fd434b1c73164c51ec9687ce39096d7b7b7";
	expected[KSI_HASHALG_SHA3_512] = "90f8c16c5e7d134deaf1c64a9ab79851ac7f7c1718c918c6ae902b84d8954de94b2d96bc2abf8fbd13a6b5d4f108c2ec0e64b912d379f4f970efa079c01a2eb7";
	expected[KSI_HASHALG_SM3] = "06d3dad6636fae1a39e02361f3d67908e0315a610cdf640502f36987258f2a71";

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
		CuAssert(tc, "Unable to initialize hasher.", res == KSI_OK && hsr != NULL);

		res = KSI_DataHasher_add(hsr, input, strlen(input));
		CuAssert(tc, "Unable to add data to the hasher.", res == KSI_OK);

		KSI_snprintf(errm, sizeof(errm), "Unable to close data hasher for algo_id=%d (%s).", algo_id, KSI_getHashAlgorithmName(algo_id));

		res = KSI_DataHasher_close(hsr, &hsh);

		CuAssert(tc, errm, res == KSI_OK && hsh != NULL);

		KSI_snprintf(tmp, sizeof(tmp), "%02x%s", algo_id, expected[algo_id]);
		KSITest_decodeHexStr(tmp, expectedImprint, sizeof(expectedImprint), &expectedLen);

		res = KSI_DataHash_getImprint(hsh, &imprint, &imprintLen);

		CuAssert(tc, "Unable to retreive imprint value.", res == KSI_OK && imprint != NULL && imprintLen > 0);

		KSI_snprintf(errm, sizeof(errm), "Hash values mismatch for algo_id=%d (%s).", algo_id, KSI_getHashAlgorithmName(algo_id));
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
	KSI_DataHash *hsh = NULL;
	KSI_DataHash *exp = NULL;

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	CuAssert(tc, "Unable to create data hasher.", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_add(hsr, "random", 6);
	CuAssert(tc, "Unable to add random data to the hasher.", res == KSI_OK);

	res = KSI_DataHasher_reset(hsr);
	CuAssert(tc, "Immediate hasher reset failed.", res == KSI_OK);

	res = KSI_DataHasher_add(hsr, "LAPTOP", 6);
	CuAssert(tc, "Unable to add random data to the hasher.", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Unable to close valid data hasher.", res == KSI_OK && hsh != NULL);

	KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &exp);

	CuAssert(tc, "Output hash does not match expected.", KSI_DataHash_equals(hsh, exp));

	KSI_DataHash_free(exp);
	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);
}

static void testUnimplemented(CuTest *tc) {
	int res;
	KSI_DataHash *h1 = NULL;
	KSI_DataHash *h2 = NULL;
	KSI_DataHash *h3 = NULL;
	const unsigned char *ptr = NULL;
	size_t ptr_len;

	KSI_HashAlgorithm algo = KSI_HASHALG_SHA3_224;

	CuAssert(tc, "The algorithm used for this test must not be implemented.", !KSI_isHashAlgorithmSupported(algo));

	res = KSI_DataHash_createZero(ctx, algo, &h1);
	CuAssert(tc, "Unable to create zero hash value.", res == KSI_OK && h1 != NULL);

	res = KSI_DataHash_getImprint(h1, &ptr, &ptr_len);
	CuAssert(tc, "Unable to extract imprint.", res == KSI_OK && ptr != NULL && ptr_len > 0);

	res = KSI_DataHash_fromImprint(ctx, ptr, ptr_len, &h2);
	CuAssert(tc, "Unable to create data hash from imprint.", res == KSI_OK && h2 != NULL);
	CuAssert(tc, "The new hash value should match with the original.", KSI_DataHash_equals(h1, h2));

	ptr = NULL;
	ptr_len = 0;
	res = KSI_DataHash_extract(h1, NULL, &ptr, &ptr_len);
	CuAssert(tc, "Unable to extract digest and length.", res == KSI_OK && ptr != NULL && ptr_len > 0);

	res = KSI_DataHash_fromDigest(ctx, algo, ptr, ptr_len, &h3);
	CuAssert(tc, "Unable to create data hash from digest.", res == KSI_OK && h3 != NULL);
	CuAssert(tc, "The new hash value should match with the original.", KSI_DataHash_equals(h1, h3));

	KSI_DataHash_free(h1);
	KSI_DataHash_free(h2);
	KSI_DataHash_free(h3);
}

static void testFreeWithoutClose(CuTest *tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	char data[3] = "aa";

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA1, &hsr);
	CuAssert(tc, "Unable to create data hasher.", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_add(hsr, data, sizeof(data));
	CuAssert(tc, "Unable to add to the hasher.", res == KSI_OK);

	KSI_DataHasher_free(hsr);
}

static void testUnavailableFunction0x03(CuTest *tc) {
	int res;
	KSI_DataHash *h = NULL;

	/* Hash algorithms with ID 0x03 should not be available. */
	res = KSI_DataHash_createZero(ctx, 0x03, &h);
	CuAssert(tc, "Hash algorithm 0x03 should not be available.", res == KSI_UNAVAILABLE_HASH_ALGORITHM && h == NULL);
}

static void testUnavailableFunction0x06(CuTest *tc) {
	int res;
	KSI_DataHash *h = NULL;

	/* Hash algorithms with ID 0x06 should not be available. */
	res = KSI_DataHash_createZero(ctx, 0x06, &h);
	CuAssert(tc, "Hash algorithm 0x06 should not be available.", res == KSI_UNAVAILABLE_HASH_ALGORITHM && h == NULL);
}

static void testUnavailableFunctionsFromImprint(CuTest *tc) {
	int res;
	KSI_DataHash *h = NULL;
	unsigned char buf[1];

	buf[0] = 0x03;
	/* Note: the array is actually shorter than the given length - the function should not read any further after it detects
	 * the hash function is not available. */
	res = KSI_DataHash_fromImprint(ctx, buf, 29, &h);
	CuAssert(tc, "Hash algorithm 0x03 should not be available.", res == KSI_UNAVAILABLE_HASH_ALGORITHM && h == NULL);

	/* An other magic hash algorithm value we should test. */
	buf[0] = 0x1f;
	res = KSI_DataHash_fromImprint(ctx, buf, 255, &h);
	CuAssert(tc, "Hash algorithm 0x1f should not be available.", res == KSI_UNAVAILABLE_HASH_ALGORITHM && h == NULL);
}

static void testUnavailableFunctionsFromDigest(CuTest *tc) {
	int res;
	KSI_DataHash *h = NULL;
	unsigned char buf[1] = {0};

	/* Note: the array is actually shorter than the given length - the function should not read any further after it detects
	 * the hash function is not available. */
	res = KSI_DataHash_fromDigest(ctx, 0x03, buf, 29, &h);
	CuAssert(tc, "Hash algorithm 0x03 should not be available.", res == KSI_UNAVAILABLE_HASH_ALGORITHM && h == NULL);

	/* An other magic hash algorithm value we should test. */
	res = KSI_DataHash_fromDigest(ctx, 0x1f, buf, 255, &h);
	CuAssert(tc, "Hash algorithm 0x1f should not be available.", res == KSI_UNAVAILABLE_HASH_ALGORITHM && h == NULL);
}

static void testDoubleClose(CuTest *tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;

	res = KSI_DataHasher_open(ctx, KSI_getHashAlgorithmByName("default"), &hsr);
	CuAssert(tc, "Creating a hasher with default hash algorithm should succeed.", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Closing an open hasher should succeed.", res == KSI_OK && hsh != NULL);

	KSI_DataHash_free(hsh);
	hsh = NULL;

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Closing a hasher for the second time should not succeed.", res == KSI_INVALID_STATE && hsh == NULL);

	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);
}

static void testAddToClosed(CuTest *tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;

	res = KSI_DataHasher_open(ctx, KSI_getHashAlgorithmByName("default"), &hsr);
	CuAssert(tc, "Creating a hasher with default hash algorithm should succeed.", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Closing an open hasher should succeed.", res == KSI_OK && hsh != NULL);

	KSI_DataHash_free(hsh);
	hsh = NULL;

	res = KSI_DataHasher_add(hsr, "FOO", 3);
	CuAssert(tc, "Should not be able to add data to a closed hasher.", res == KSI_INVALID_STATE);

	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);

}

static void testAddToCloseAndReset(CuTest *tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;

	res = KSI_DataHasher_open(ctx, KSI_getHashAlgorithmByName("default"), &hsr);
	CuAssert(tc, "Creating a hasher with default hash algorithm should succeed.", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Closing an open hasher should succeed.", res == KSI_OK && hsh != NULL);

	KSI_DataHash_free(hsh);
	hsh = NULL;

	res = KSI_DataHasher_reset(hsr);
	CuAssert(tc, "Reseting a closed hasher should succeed.", res == KSI_OK);

	res = KSI_DataHasher_add(hsr, "FOO", 3);
	CuAssert(tc, "Should not be able to add data to a closed hasher.", res == KSI_OK);

	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);

}

void testCreateHashNoContext(CuTest *tc) {
	KSI_DataHash *hsh = NULL;
	KSI_DataHash *exp = NULL;
	int res;

	KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &exp);


	res = KSI_DataHash_create(NULL, "LAPTOP", 6, KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Unable to create hash with a NULL context.", res == KSI_OK);
	CuAssert(tc, "Hash values do not match.", KSI_DataHash_equals(hsh, exp));

	KSI_DataHash_free(exp);
	KSI_DataHash_free(hsh);
}

void testOpenCloseNoContext(CuTest *tc) {
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_DataHash *exp = NULL;
	int res;

	KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &exp);

	res = KSI_DataHasher_open(NULL, KSI_HASHALG_SHA2_256, &hsr);
	CuAssert(tc, "Unable to create hasher with a NULL context.", res == KSI_OK);

	res = KSI_DataHasher_add(hsr, "LAPTOP", 6);
	CuAssert(tc, "Unable to add data to hasher with a NULL context.", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Unable to close hasher with a NULL context.", res == KSI_OK);
	CuAssert(tc, "Hash values do not match.", KSI_DataHash_equals(hsh, exp));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(exp);
	KSI_DataHash_free(hsh);
}


CuSuite* KSITest_Hash_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testSHA256);
	SUITE_ADD_TEST(suite, testSHA256OnEmptyData);
	SUITE_ADD_TEST(suite, testSHA256Parts);
	SUITE_ADD_TEST(suite, testSHA256Reset);
	SUITE_ADD_TEST(suite, testSHA256Empty);
	SUITE_ADD_TEST(suite, testSHA256GetData);
	SUITE_ADD_TEST(suite, testSHA256GetImprint);
	SUITE_ADD_TEST(suite, testSHA256fromImprint);
	SUITE_ADD_TEST(suite, testParallelHashing);
	SUITE_ADD_TEST(suite, testHashGetAlgByName);
	SUITE_ADD_TEST(suite, testHashAlgorithmDeprecatedDates);
	SUITE_ADD_TEST(suite, testHashAlgorithmObsoleteDates);
	SUITE_ADD_TEST(suite, testIncorrectHashLen);
	SUITE_ADD_TEST(suite, testAllHashing);
	SUITE_ADD_TEST(suite, testReset);
	SUITE_ADD_TEST(suite, testFreeWithoutClose);
	SUITE_ADD_TEST(suite, testUnimplemented);
	SUITE_ADD_TEST(suite, testUnavailableFunction0x03);
	SUITE_ADD_TEST(suite, testUnavailableFunction0x06);
	SUITE_ADD_TEST(suite, testUnavailableFunctionsFromImprint);
	SUITE_ADD_TEST(suite, testUnavailableFunctionsFromDigest);
	SUITE_ADD_TEST(suite, testDoubleClose);
	SUITE_ADD_TEST(suite, testAddToClosed);
	SUITE_ADD_TEST(suite, testAddToCloseAndReset);
	SUITE_ADD_TEST(suite, testCreateHashNoContext);
	SUITE_ADD_TEST(suite, testOpenCloseNoContext);

	return suite;
}
