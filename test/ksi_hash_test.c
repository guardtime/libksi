#include <stdio.h>
#include <string.h>

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"
#include "../src/ksi_hash.h"

extern KSI_CTX *ctx;

static void TestSHA256(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char *data = "correct horse battery staple";
	unsigned char expected[] = {0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA256, &hsr);
	CuAssert(tc, "Failed to open DataHasher", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_add(hsr, data, strlen(data));
	CuAssert(tc, "Failed to add data", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Failed to close hasher.", res == KSI_OK && hsh != NULL);
	CuAssertIntEquals_Msg(tc, "Digest lenght", sizeof(expected), hsh->digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, hsh->digest, hsh->digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void TestSHA256Parts(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char *data[] = {"correct ", "horse ", "battery ", "staple", NULL };
	int i = 0;
	unsigned char expected[] = {0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA256, &hsr);
	CuAssert(tc, "Failed to open DataHasher", res == KSI_OK && hsr != NULL);

	while (data[i] != NULL) {
		res = KSI_DataHasher_add(hsr, data[i], strlen(data[i]));
		CuAssert(tc, "Failed to add data", res == KSI_OK);
		i++;
	}
	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Failed to close hasher.", res == KSI_OK && hsh != NULL);
	CuAssertIntEquals_Msg(tc, "Digest lenght", sizeof(expected), hsh->digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, hsh->digest, hsh->digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void TestSHA256Reset(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char *data = "correct horse battery staple";
	unsigned char expected[] = {0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA256, &hsr);
	CuAssert(tc, "Failed to open DataHasher", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_add(hsr, "TEST", strlen("TEST"));
	CuAssert(tc, "Failed to add data", res == KSI_OK);

	res = KSI_DataHasher_reset(hsr);
	CuAssert(tc, "Failed to reset hasher", res == KSI_OK);


	res = KSI_DataHasher_add(hsr, data, strlen(data));
	CuAssert(tc, "Failed to add data", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Failed to close hasher.", res == KSI_OK && hsh != NULL);
	CuAssertIntEquals_Msg(tc, "Digest lenght", sizeof(expected), hsh->digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, hsh->digest, hsh->digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void TestSHA256Empty(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char expected[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA256, &hsr);
	CuAssert(tc, "Failed to open DataHasher", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_add(hsr, "TEST", strlen("TEST"));
	CuAssert(tc, "Failed to add data", res == KSI_OK);

	res = KSI_DataHasher_reset(hsr);
	CuAssert(tc, "Failed to reset hasher", res == KSI_OK);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Failed to close empty hasher.", res == KSI_OK && hsh != NULL);

	CuAssertIntEquals_Msg(tc, "Digest lenght", sizeof(expected), hsh->digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, hsh->digest, hsh->digest_length));

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}


CuSuite* KSI_Hash_GetSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestSHA256);
	SUITE_ADD_TEST(suite, TestSHA256Parts);
	SUITE_ADD_TEST(suite, TestSHA256Reset);
	SUITE_ADD_TEST(suite, TestSHA256Empty);

	return suite;
}
