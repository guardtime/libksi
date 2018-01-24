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
#include <ksi/hmac.h>

extern KSI_CTX *ctx;

#define KEY					"secret"
#define MESSAGE				"correct horse battery staple"
#define SHA1_MESSAGE_HMAC	"006cce352c6b788a3217b0439d231eb68180c529c1"
#define SHA256_MESSAGE_HMAC "01f24bedb4e103c9bf78b312b570af224ceb090e0bcda18c2c106943269259cfed"
#define SHA256_EMPTY_HMAC	"01f9e66e179b6747ae54108f82f8ade8b3c25d76fd30afde6c395822c530196169"

static int CompareHmac(KSI_DataHash *hmac, const char *expected) {
	int res = KSI_HMAC_MISMATCH;
	char buf[KSI_MAX_IMPRINT_LEN * 2 + 1];

	KSI_DataHash_toString(hmac, buf, sizeof(buf));

	if (!strcmp(buf, expected)) {
		res = KSI_OK;
	}

	return res;
}

static void TestSHA256Create(CuTest* tc) {
	int res;
	KSI_DataHash *hmac = NULL;
	const unsigned char *data = (const unsigned char *)MESSAGE;
	const char *key = KEY;
	const char *expected = SHA256_MESSAGE_HMAC;
	size_t data_len = strlen(MESSAGE);

	KSI_ERR_clearErrors(ctx);

	res = KSI_HMAC_create(ctx, KSI_HASHALG_SHA2_256, key, data, data_len, &hmac);
	CuAssert(tc, "Failed to create HMAC.", res == KSI_OK && hmac != NULL);

	res = CompareHmac(hmac, expected);
	CuAssert(tc, "HMAC mismatch.", res == KSI_OK);


	KSI_DataHash_free(hmac);
}

static void TestSHA256AddEmptyData(CuTest* tc) {
	int res;
	KSI_HmacHasher *hasher = NULL;
	KSI_DataHash *hmac = NULL;
	unsigned char empty[1];
	const char *key = KEY;
	const char *expected = SHA256_EMPTY_HMAC;

	KSI_ERR_clearErrors(ctx);

	res = KSI_HmacHasher_open(ctx, KSI_HASHALG_SHA2_256, key, &hasher);
	CuAssert(tc, "Failed to open HMAC hasher.", res == KSI_OK && hasher != NULL);

	res = KSI_HmacHasher_add(hasher, empty, 0);
	CuAssert(tc, "Failed to add data of length 0.", res == KSI_OK);

	res = KSI_HmacHasher_close(hasher, &hmac);
	CuAssert(tc, "Failed to close HMAC hasher.", res == KSI_OK && hmac != NULL);

	res = CompareHmac(hmac, expected);
	CuAssert(tc, "HMAC mismatch.", res == KSI_OK);


	KSI_HmacHasher_free(hasher);
	KSI_DataHash_free(hmac);
}

static void TestSHA256AddMany(CuTest* tc) {
	int res;
	KSI_HmacHasher *hasher = NULL;
	KSI_DataHash *hmac = NULL;
	char *data = MESSAGE;
	unsigned i = 0;
	const char *key = KEY;
	const char *expected = SHA256_MESSAGE_HMAC;

	KSI_ERR_clearErrors(ctx);

	res = KSI_HmacHasher_open(ctx, KSI_HASHALG_SHA2_256, key, &hasher);
	CuAssert(tc, "Failed to open HMAC hasher.", res == KSI_OK && hasher != NULL);

	while (data[i]) {
		res = KSI_HmacHasher_add(hasher, &data[i], 1);
		CuAssert(tc, "Failed to add data.", res == KSI_OK);
		i++;
	}
	res = KSI_HmacHasher_close(hasher, &hmac);
	CuAssert(tc, "Failed to close HMAC hasher.", res == KSI_OK && hmac != NULL);

	res = CompareHmac(hmac, expected);
	CuAssert(tc, "HMAC mismatch.", res == KSI_OK);


	KSI_HmacHasher_free(hasher);
	KSI_DataHash_free(hmac);
}

static void TestSHA256Reset(CuTest* tc) {
	int res;
	KSI_HmacHasher *hasher = NULL;
	KSI_DataHash *hmac = NULL;
	char *data = MESSAGE;
	const char *key = KEY;
	const char *expected = SHA256_MESSAGE_HMAC;

	KSI_ERR_clearErrors(ctx);

	res = KSI_HmacHasher_open(ctx, KSI_HASHALG_SHA2_256, key, &hasher);
	CuAssert(tc, "Failed to open HMAC hasher.", res == KSI_OK && hasher != NULL);

	res = KSI_HmacHasher_add(hasher, "TEST", strlen("TEST"));
	CuAssert(tc, "Failed to add data.", res == KSI_OK);

	res = KSI_HmacHasher_reset(hasher);
	CuAssert(tc, "Failed to reset HMAC hasher.", res == KSI_OK);

	res = KSI_HmacHasher_add(hasher, (unsigned char *)data, strlen(data));
	CuAssert(tc, "Failed to add data.", res == KSI_OK);

	res = KSI_HmacHasher_close(hasher, &hmac);
	CuAssert(tc, "Failed to close HMAC hasher.", res == KSI_OK && hmac != NULL);

	res = CompareHmac(hmac, expected);
	CuAssert(tc, "HMAC mismatch.", res == KSI_OK);


	KSI_HmacHasher_free(hasher);
	KSI_DataHash_free(hmac);
}

static void TestSHA256NoData(CuTest* tc) {
	int res;
	KSI_HmacHasher *hasher = NULL;
	KSI_DataHash *hmac = NULL;
	const char *key = KEY;
	const char *expected = SHA256_EMPTY_HMAC;

	KSI_ERR_clearErrors(ctx);

	res = KSI_HmacHasher_open(ctx, KSI_HASHALG_SHA2_256, key, &hasher);
	CuAssert(tc, "Failed to open HMAC hasher.", res == KSI_OK && hasher != NULL);

	res = KSI_HmacHasher_close(hasher, &hmac);
	CuAssert(tc, "Failed to close HMAC hasher.", res == KSI_OK && hmac != NULL);

	res = CompareHmac(hmac, expected);
	CuAssert(tc, "HMAC mismatch.", res == KSI_OK);


	KSI_HmacHasher_free(hasher);
	KSI_DataHash_free(hmac);
}

static void TestAllAlgorithms(CuTest* tc) {
	int res;
	KSI_DataHash *hmac = NULL;
	const unsigned char *data = (const unsigned char *)MESSAGE;
	const char *key = KEY;
	const char *expected[KSI_NUMBER_OF_KNOWN_HASHALGS];
	size_t data_len = strlen(MESSAGE);
	KSI_HashAlgorithm algo_id;

	expected[KSI_HASHALG_SHA1] = SHA1_MESSAGE_HMAC;
	expected[KSI_HASHALG_SHA2_256] = SHA256_MESSAGE_HMAC;
	expected[KSI_HASHALG_RIPEMD160] = "022f50d19982a69c801e709f8b2df1472d0de2d727";
	expected[0x03] = NULL;
	expected[KSI_HASHALG_SHA2_384] = "0417df9e5205924edf24677bd365535827d150ba5c88e6ea769a16f4910f4b62d65ed730b2f5511c79750b8a32cee6373c";
	expected[KSI_HASHALG_SHA2_512] = "05fb7ed4edda2e2631c53103413823b1d7613d756e43b5182550f04decbde99bd3848ff38dbc5a4210f3439754b77de10c294acdb0704fbfcd2493d48f2e65ed98";
	expected[0x06] = NULL; /* Deprecated hash function. */
	expected[KSI_HASHALG_SHA3_244] = "TODO!";
	expected[KSI_HASHALG_SHA3_256] = "TODO!";
	expected[KSI_HASHALG_SHA3_384] = "TODO!";
	expected[KSI_HASHALG_SHA3_512] = "TODO!";
	expected[KSI_HASHALG_SM3] = "TODO!";

	for (algo_id = 0; algo_id < KSI_NUMBER_OF_KNOWN_HASHALGS; algo_id++) {
		char errm[0x1ff];

		/* Skip unsupported. */
		if (!KSI_isHashAlgorithmSupported(algo_id)) continue;

		KSI_ERR_clearErrors(ctx);

		res = KSI_HMAC_create(ctx, algo_id, key, data, data_len, &hmac);
		KSI_snprintf(errm, sizeof(errm), "Failed to create HMAC for algorithm %s", KSI_getHashAlgorithmName(algo_id));
		CuAssert(tc, errm, res == KSI_OK && hmac != NULL);

		res = CompareHmac(hmac, expected[algo_id]);
		KSI_snprintf(errm, sizeof(errm), "HMAC mismatch for algorithm %s", KSI_getHashAlgorithmName(algo_id));
		CuAssert(tc, errm, res == KSI_OK && hmac != NULL);

		KSI_DataHash_free(hmac);
		hmac = NULL;
	}
}

static void TestSHA512LongKey(CuTest* tc) {
	int res;
	KSI_DataHash *hmac = NULL;
	const unsigned char *data = (const unsigned char *)MESSAGE;
	const char *key = "Secret key longer than 128 bytes. Secret key longer than 128 bytes. Secret key longer than 128 bytes. Secret key longer than 128 bytes.";
	const char *expected = "05ff9707fad045722e7b1466933d6ee76f3f933447aaf0c79c4ed32ed643bb38231b45accc5a15cef894570b1e642bc2609c68918ce51ed712d94a9d8d9cad7bb1";
	size_t data_len = strlen(MESSAGE);

	KSI_ERR_clearErrors(ctx);

	res = KSI_HMAC_create(ctx, KSI_HASHALG_SHA2_512, key, data, data_len, &hmac);
	CuAssert(tc, "Failed to create HMAC.", res == KSI_OK && hmac != NULL);

	res = CompareHmac(hmac, expected);
	CuAssert(tc, "HMAC mismatch.", res == KSI_OK);


	KSI_DataHash_free(hmac);
}

static void TestParallelHashing(CuTest* tc) {
	int res;
	KSI_HmacHasher *hasher1 = NULL;
	KSI_HmacHasher *hasher2 = NULL;
	KSI_DataHash *hmac1 = NULL;
	KSI_DataHash *hmac2 = NULL;
	const char *data = MESSAGE;
	unsigned i = 0;
	const char *key = KEY;
	const char *expected1 = SHA1_MESSAGE_HMAC;
	const char *expected2 = SHA256_MESSAGE_HMAC;

	KSI_ERR_clearErrors(ctx);

	res = KSI_HmacHasher_open(ctx, KSI_HASHALG_SHA1, key, &hasher1);
	CuAssert(tc, "Failed to open HMAC hasher.", res == KSI_OK && hasher1 != NULL);

	res = KSI_HmacHasher_open(ctx, KSI_HASHALG_SHA2_256, key, &hasher2);
	CuAssert(tc, "Failed to open HMAC hasher.", res == KSI_OK && hasher2 != NULL);

	while (data[i]) {
		res = KSI_HmacHasher_add(hasher1, &data[i], 1);
		CuAssert(tc, "Failed to add data.", res == KSI_OK);

		res = KSI_HmacHasher_add(hasher2, &data[i], 1);
		CuAssert(tc, "Failed to add data.", res == KSI_OK);
		i++;
	}

	res = KSI_HmacHasher_close(hasher1, &hmac1);
	CuAssert(tc, "Failed to close HMAC hasher.", res == KSI_OK && hmac1 != NULL);

	res = CompareHmac(hmac1, expected1);
	CuAssert(tc, "HMAC mismatch.", res == KSI_OK);

	res = KSI_HmacHasher_close(hasher2, &hmac2);
	CuAssert(tc, "Failed to close HMAC hasher.", res == KSI_OK && hmac2 != NULL);

	res = CompareHmac(hmac2, expected2);
	CuAssert(tc, "HMAC mismatch.", res == KSI_OK);

	KSI_HmacHasher_free(hasher1);
	KSI_DataHash_free(hmac1);

	KSI_HmacHasher_free(hasher2);
	KSI_DataHash_free(hmac2);
}

static void TestInvalidParams(CuTest* tc) {
	int res;
	KSI_HmacHasher *hasher = NULL;
	KSI_DataHash *hmac = NULL;
	const unsigned char *data = (const unsigned char *)MESSAGE;
	const char *key = KEY;
	size_t data_len = strlen(MESSAGE);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HMAC_create(NULL, KSI_HASHALG_SHA2_256, key, data, data_len, &hmac);
	CuAssert(tc, "Context NULL accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HmacHasher_open(NULL, KSI_HASHALG_SHA2_256, key, &hasher);
	CuAssert(tc, "Context NULL accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HMAC_create(ctx, KSI_NUMBER_OF_KNOWN_HASHALGS, key, data, data_len, &hmac);
	CuAssert(tc, "Invalid algorithm accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HmacHasher_open(ctx, KSI_NUMBER_OF_KNOWN_HASHALGS, key, &hasher);
	CuAssert(tc, "Invalid algorithm accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HMAC_create(ctx, KSI_HASHALG_SHA2_256, NULL, data, data_len, &hmac);
	CuAssert(tc, "Key NULL accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HmacHasher_open(ctx, KSI_HASHALG_SHA2_256, NULL, &hasher);
	CuAssert(tc, "Key NULL accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HMAC_create(ctx, KSI_HASHALG_SHA2_256, key, NULL, data_len, &hmac);
	CuAssert(tc, "Data NULL accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HMAC_create(ctx, KSI_HASHALG_SHA2_256, key, data, data_len, NULL);
	CuAssert(tc, "HMAC NULL accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HmacHasher_open(ctx, KSI_HASHALG_SHA2_256, key, NULL);
	CuAssert(tc, "HMAC hasher NULL accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HmacHasher_reset(NULL);
	CuAssert(tc, "HMAC hasher NULL accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HmacHasher_add(NULL, data, data_len);
	CuAssert(tc, "HMAC hasher NULL accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HmacHasher_close(NULL, &hmac);
	CuAssert(tc, "HMAC hasher NULL accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HmacHasher_open(ctx, KSI_HASHALG_SHA2_256, key, &hasher);
	CuAssert(tc, "Failed to open HMAC hasher.", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HmacHasher_add(hasher, NULL, data_len);
	CuAssert(tc, "Data NULL accepted.", res != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_HmacHasher_close(hasher, NULL);
	CuAssert(tc, "HMAC NULL accepted.", res != KSI_OK);

	KSI_HmacHasher_free(hasher);
	KSI_DataHash_free(hmac);
}

static void testUnimplementedHashAlgorithm(CuTest *tc) {
	KSI_DataHash *hsh = NULL;

	int res = KSI_HMAC_create(ctx, KSI_HASHALG_SM3, "key", (unsigned char *)"data", 4, &hsh);
	CuAssert(tc, "Unimplemented hash algorithm may not be used for HMAC computation.", res = KSI_UNAVAILABLE_HASH_ALGORITHM && hsh == NULL);

	KSI_DataHash_free(hsh);
}

CuSuite* KSITest_HMAC_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestSHA256Create);
	SUITE_ADD_TEST(suite, TestSHA256AddEmptyData);
	SUITE_ADD_TEST(suite, TestSHA256AddMany);
	SUITE_ADD_TEST(suite, TestSHA256Reset);
	SUITE_ADD_TEST(suite, TestSHA256NoData);
	SUITE_ADD_TEST(suite, TestAllAlgorithms);
	SUITE_ADD_TEST(suite, TestSHA512LongKey);
	SUITE_ADD_TEST(suite, TestParallelHashing);
	SUITE_ADD_TEST(suite, TestInvalidParams);
	SUITE_ADD_TEST(suite, testUnimplementedHashAlgorithm);

	return suite;
}
