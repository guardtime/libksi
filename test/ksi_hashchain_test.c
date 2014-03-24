#include <stdio.h>
#include <string.h>

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"
#include "../src/ksi_hash.h"

extern KSI_CTX *ctx;


static void TestHashChainBuild(CuTest* tc) {
	int res;
	KSI_HashNode *root = NULL;
	KSI_HashNode *tmp = NULL;
	KSI_DataHash *hsh = NULL;
	const char data1[] = "Some important data";
	const char data2[] = "Some otheh important data";
	const unsigned char expectedRoot[] = { 0x01,
			0x05, 0x92, 0xcb, 0xbb, 0xe6, 0xe0, 0x14, 0xe8, 0xc7, 0xb7, 0x3e, 0xb4, 0x8b, 0x36, 0x8d, 0x21,
			0x70, 0x35, 0x46, 0x64, 0x47, 0x29, 0x29, 0x8a, 0x7e, 0x19, 0x0d, 0x3e, 0x22, 0xa6, 0x59, 0x9e};
	unsigned char *imprint = NULL;
	int imprint_len = 0;

	KSI_ERR_clearErrors(ctx);

	printf("ctx = %x\n", ctx);

	res = KSI_DataHash_create(ctx, data1, strlen(data1), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

	res = KSI_HashNode_new(ctx, hsh, 0, &root);
	CuAssert(tc, "Unable to create hash node.", res == KSI_OK && root != NULL);

	res = KSI_DataHash_create(ctx, data2, strlen(data2), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

	res = KSI_HashNode_new(ctx, hsh, 0, &tmp);
	CuAssert(tc, "Unable to create hash node.", res == KSI_OK && tmp != NULL);

	/* Aggregate nodes. */
	res = KSI_HashNode_join(root, tmp, KSI_HASHALG_SHA2_256, &root);
	CuAssert(tc, "Unable to join hash nodes.", res == KSI_OK && tmp != NULL);

	res = KSI_DataHash_create(ctx, data2, strlen(data2), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

	res = KSI_HashNode_new(ctx, hsh, 5, &tmp);
	CuAssert(tc, "Unable to create hash node.", res == KSI_OK && tmp != NULL);

	/* Aggregate nodes. */
	res = KSI_HashNode_join(tmp, root, KSI_HASHALG_SHA2_256, &root);
	CuAssert(tc, "Unable to join hash nodes.", res == KSI_OK && tmp != NULL);

	/* Extract the imprint.*/
	res = KSI_HashNode_getImprint(root, &imprint, &imprint_len);
	CuAssert(tc, "Cant't extract imprint from root node.", imprint != NULL && imprint_len > 0 && res == KSI_OK);

	/* Validate result */
	CuAssertIntEquals_Msg(tc, "Result imprint length", sizeof(expectedRoot), imprint_len);
	CuAssert(tc, "Unexpected imprint", !memcmp(expectedRoot, imprint, imprint_len));

	KSI_free(imprint);
	KSI_HashNode_free(root);
	KSI_nofree(tmp);

}

CuSuite* KSI_HashChain_GetSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestHashChainBuild);

	return suite;
}
