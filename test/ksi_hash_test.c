#include <stdio.h>
#include <string.h>

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"
#include "../src/ksi_hash.h"

extern KSI_CTX *ctx;

static void TestSHA2(CuTest* tc) {
	int res;
	KSI_Hasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	unsigned char *data = "correct horse battery staple";
	unsigned char expected[] = {0xc4, 0xbb, 0xcb, 0x1f, 0xbe, 0xc9, 0x9d, 0x65, 0xbf, 0x59, 0xd8, 0x5c, 0x8c, 0xb6, 0x2e, 0xe2, 0xdb, 0x96, 0x3f, 0x0f, 0xe1, 0x06, 0xf4, 0x83, 0xd9, 0xaf, 0xa7, 0x3b, 0xd4, 0xe3, 0x9a, 0x8a};

	KSI_ERR_clearErrors(ctx);

	res = KSI_Hasher_open(ctx, KSI_HASHALG_SHA256, &hsr);
	CuAssert(tc, "Failed to open DataHasher", res == KSI_OK && hsr != NULL);

	res = KSI_Hasher_add(hsr, data, strlen(data));
	CuAssert(tc, "Failed to add data", res == KSI_OK);

	res = KSI_Hasher_close(hsr, &hsh);
	CuAssert(tc, "Failed to close hasher.", res == KSI_OK && hsh != NULL);
	CuAssertIntEquals_Msg(tc, "Digest lenght", sizeof(expected), hsh->digest_length);
	CuAssert(tc, "Digest value mismatch", !memcmp(expected, hsh->digest, hsh->digest_length));

	KSI_Hasher_free(hsr);
	KSI_DataHash_free(hsh);
}

CuSuite* KSI_Hash_GetSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestSHA2);

	return suite;
}
