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
	KSI_CTX_free(ctx);

}

static void TestRdrFileReading(CuTest* tc) {
	int res;
	char tmpFile[L_tmpnam];
	char tmpBuf[0xffff];
	int readh;

	static char testStr[] = "Randomness is too important to be left to chance";

	FILE *f = NULL;

	KSI_CTX *ctx = NULL;
	KSI_RDR *rdr = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", tmpnam_r(tmpFile) != NULL);

	/* Write some data to file */
	f = fopen(tmpFile, "w");
	CuAssert(tc, "Unable to create tempprary file", f != NULL);
	CuAssert(tc, "Unable to write temporary file", fprintf(f, testStr) > 0);
	CuAssert(tc, "Unable to close temporary file", !fclose(f));

	/* Try reading it back. */
	res = KSI_RDR_fromFile(ctx, tmpFile, "r", &rdr);
	CuAssert(tc, "Error creating reader from file.", res == KSI_OK);
	CuAssert(tc, "Creating reader from file did not fail, but object is still NULL", rdr != NULL);
	/* Read two blocks */
	KSI_RDR_read(rdr, tmpBuf + readh, sizeof(tmpBuf), &readh);

	CuAssert(tc, "Wrong length read", readh == strlen(testStr));

	CuAssert(tc, "Reader is not at EOF", rdr->eof);
	KSI_RDR_close(rdr);

	/* Remove temporary file */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);


	KSI_CTX_free(ctx);
}

CuSuite* KSI_RDR_GetSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestRdrBadFileName);
	SUITE_ADD_TEST(suite, TestRdrFileReading);

	return suite;
}
