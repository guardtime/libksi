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

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
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

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
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

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
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

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
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

static void TestSHA256GetData(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char expected[] = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
	unsigned char *digest = NULL;
	int digest_length;
	int algorithm;


	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	CuAssert(tc, "Failed to open DataHasher", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Failed to close empty hasher.", res == KSI_OK && hsh != NULL);

	res = KSI_DataHash_getData(hsh, &algorithm, &digest, &digest_length);
	CuAssert(tc, "Failed to get data from data hash object.", res == KSI_OK && digest != NULL);
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA2_256, algorithm);
	CuAssertIntEquals_Msg(tc, "Digest lenght", sizeof(expected), digest_length);

	CuAssertIntEquals_Msg(tc, "Digest lenght", sizeof(expected), hsh->digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, digest, digest_length));

	KSI_free(digest);
	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void TestSHA256GetImprint(CuTest* tc) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char expected[] = {KSI_HASHALG_SHA2_256, 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
	unsigned char *imprint = NULL;
	int imprint_length;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	CuAssert(tc, "Failed to open DataHasher", res == KSI_OK && hsr != NULL);

	res = KSI_DataHasher_close(hsr, &hsh);
	CuAssert(tc, "Failed to close empty hasher.", res == KSI_OK && hsh != NULL);

	res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_length);
	CuAssert(tc, "Failed to get imprint from data hash object.", res == KSI_OK && imprint != NULL);
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA2_256, *imprint);
	CuAssertIntEquals_Msg(tc, "Imprint lenght", sizeof(expected), imprint_length);

	CuAssertIntEquals_Msg(tc, "Imprint lenght", sizeof(expected), imprint_length);
	CuAssert(tc, "Imprint value mismatch", !memcmp(expected, imprint, imprint_length));

	KSI_free(imprint);
	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
}

static void TestSHA256fromImprint(CuTest* tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	unsigned char unexpected[] = {KSI_HASHALG_SHA2_256, 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
	unsigned char expected[] = {KSI_HASHALG_SHA2_256, 0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	unsigned char *imprint = NULL;
	int imprint_length;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromImprint(ctx, unexpected, sizeof(unexpected), &hsh);
	CuAssert(tc, "Failed to get data hash from imprint.", res == KSI_OK && hsh != NULL);

	res = KSI_DataHash_fromImprint_ex(expected, sizeof(expected), hsh);
	CuAssert(tc, "Failed to get data hash from imprint to existing data hash object.", res == KSI_OK);

	res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_length);
	CuAssert(tc, "Failed to get imprint from data hash object.", res == KSI_OK && imprint != NULL);
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA2_256, *imprint);
	CuAssertIntEquals_Msg(tc, "Imprint lenght", sizeof(expected), imprint_length);

	CuAssertIntEquals_Msg(tc, "Imprint lenght", sizeof(expected), imprint_length);
	CuAssert(tc, "Imprint value mismatch", !memcmp(expected, imprint, imprint_length));

	KSI_free(imprint);
	KSI_DataHash_free(hsh);
}

static void TestParallelHashing(CuTest* tc) {
	int res;
	char data[] = "I'll be Bach";
	char *ptr = data;
	unsigned char exp1[] = {0x91, 0x05, 0xeb, 0xd0, 0x16, 0xf5, 0xcf, 0xf2, 0xe2, 0xa8, 0x04, 0xe2, 0xee, 0x24, 0xac, 0x05, 0x89, 0xf4, 0x7e, 0x21};
	unsigned char exp2[] = {0x9b, 0x07, 0x11, 0x1f, 0x17, 0x3b, 0x3d, 0x2b, 0x9e, 0xc8, 0x29, 0xe8, 0xab, 0x25, 0xb5, 0x94, 0xef, 0x5d, 0x57, 0xfe,
			0x53, 0x7f, 0x2b, 0x66, 0xa6, 0xfe, 0xc4, 0xc0, 0x92, 0x66, 0x89, 0xa9, 0x34, 0x10, 0x58, 0x59, 0x1b, 0xa1, 0xef, 0x68, 0x69, 0xae,
			0xff, 0x46, 0x6d, 0x2a, 0x87, 0x1d, 0xb2, 0x47, 0xd0, 0xc5, 0xd6, 0x82, 0xa0, 0x14, 0x1a, 0x98, 0xa7, 0xcd, 0xbd, 0x2f, 0x10, 0xea};
	KSI_DataHasher *hsr1 = NULL;
	KSI_DataHasher *hsr2 = NULL;
	KSI_DataHash *hsh1 = NULL;
	KSI_DataHash *hsh2 = NULL;

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_RIPEMD160, &hsr1);
	CuAssert(tc, "Failed to open hasher", res == KSI_OK && hsr1 != NULL);

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_512, &hsr2);
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
	CuAssertIntEquals_Msg(tc, "Digest length", sizeof(exp1), hsh1->digest_length);
	CuAssert(tc, "Digest mismatch", !memcmp(exp1, hsh1->digest, sizeof(exp1)));
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_RIPEMD160, hsh1->algorithm);

	res = KSI_DataHasher_close(hsr2, &hsh2);
	CuAssert(tc, "Unable to close hasher", res == KSI_OK && hsh2 != NULL);
	CuAssertIntEquals_Msg(tc, "Digest length", sizeof(exp2), hsh2->digest_length);
	CuAssert(tc, "Digest mismatch", !memcmp(exp2, hsh2->digest, sizeof(exp2)));
	CuAssertIntEquals_Msg(tc, "Algorithm", KSI_HASHALG_SHA2_512, hsh2->algorithm);

	KSI_DataHash_free(hsh1);
	KSI_DataHash_free(hsh2);
	KSI_DataHasher_free(hsr1);
	KSI_DataHasher_free(hsr2);
}

static void TestHashGetAlgByName(CuTest* tc) {
	CuAssertIntEquals_Msg(tc, "Default algorithm", KSI_getHashAlgorithmByName("default"), KSI_HASHALG_SHA2_256);
	CuAssertIntEquals_Msg(tc, "Sha2 algorithm", KSI_getHashAlgorithmByName("Sha2"), KSI_HASHALG_SHA2_256);
	CuAssertIntEquals_Msg(tc, "Sha-2 algorithm", KSI_getHashAlgorithmByName("Sha-2"), KSI_HASHALG_SHA2_256);
	CuAssertIntEquals_Msg(tc, "Sha3-256 algorithm", KSI_getHashAlgorithmByName("Sha3-256"), KSI_HASHALG_SHA3_256);
}

CuSuite* KSI_Hash_GetSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestSHA256);
	SUITE_ADD_TEST(suite, TestSHA256Parts);
	SUITE_ADD_TEST(suite, TestSHA256Reset);
	SUITE_ADD_TEST(suite, TestSHA256Empty);
	SUITE_ADD_TEST(suite, TestSHA256GetData);
	SUITE_ADD_TEST(suite, TestSHA256GetImprint);
	SUITE_ADD_TEST(suite, TestSHA256fromImprint);
	SUITE_ADD_TEST(suite, TestParallelHashing);
	SUITE_ADD_TEST(suite, TestHashGetAlgByName);

	return suite;
}
