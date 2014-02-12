#include <stdio.h>

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"

static void TestRdrBadFileName(CuTest* tc) {
	int res;
	char tmpFile[L_tmpnam];
	char tmpBuf[0xffff];

	KSI_CTX *ctx = NULL;
	KSI_RDR *rdr = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", tmpnam_r(tmpFile) != NULL);

	/* Init reader from non existing file name */
	res = KSI_RDR_fromFile(ctx, tmpFile, "r", &rdr);

	/* Assert failure to initialize */
	CuAssert(tc, "Reader initzialisation did not fail from bad input file name.", res != KSI_OK);

	/* Assert there is no reader object. */
	CuAssert(tc, "There should be no reader object after failure.", rdr == NULL);

	/* Closing a NULL reader should not fail. */
	KSI_RDR_close(NULL);
	CuAssertTrue(tc, 1 == 1);

	KSI_CTX_free(ctx);

}

CuSuite* KSI_RDR_GetSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestRdrBadFileName);

	return suite;
}
