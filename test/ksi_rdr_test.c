#include <stdio.h>
#include <string.h>

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"

static void TestRdrFileBadFileName(CuTest* tc) {
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

static void TestRdrFileFileReading(CuTest* tc) {
	int res;
	char tmpFile[L_tmpnam];
	char tmpBuf[0xffff];
	int readCount;

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
	/* Read as a single block. */
	KSI_RDR_read(rdr, tmpBuf, sizeof(tmpBuf), &readCount);

	CuAssert(tc, "Wrong length read", readCount == strlen(testStr));

	CuAssert(tc, "Reader is not at EOF", rdr->eof);
	KSI_RDR_close(rdr);

	/* Remove temporary file */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);


	KSI_CTX_free(ctx);
}


static void TestRdrFileReadingChuncks(CuTest* tc) {
	int res;
	char tmpFile[L_tmpnam];
	char tmpBuf[0xffff];
	int readCount;
	int size = 0;

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
	/* Read blocks of size 10. */
	while (!KSI_RDR_isEOF(rdr)) {
		KSI_RDR_read(rdr, tmpBuf + size, 10, &readCount);
		size += readCount;
	}

	CuAssert(tc, "Wrong length read", size == strlen(testStr));

	CuAssert(tc, "Reader is not at EOF", rdr->eof);
	KSI_RDR_close(rdr);

	/* Remove temporary file */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);

	KSI_CTX_free(ctx);
}

static void TestRdrMemInitExtStorage(CuTest* tc) {
	int res;
	int readCount;

	KSI_CTX *ctx = NULL;
	KSI_RDR *rdr = NULL;
	static char testData[] = "Random binary data.";
	char tmpBuf[0xffff];

	/* Init context. */
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Failed initializing context.", res == KSI_OK);

	/* Init reader. */
	res = KSI_RDR_fromMem(ctx, testData, sizeof(testData), 0, &rdr);
	CuAssert(tc, "Failed initializing context from shared memory.", res == KSI_OK);
	CuAssert(tc, "Init did not fail, but object not created.", rdr != NULL);

	res = KSI_RDR_read(rdr, tmpBuf, sizeof(tmpBuf), &readCount);
	CuAssert(tc, "Incorrect read count.", readCount = sizeof(testData));



	KSI_RDR_close(rdr);
	KSI_CTX_free(ctx);
}

static void TestRdrMemInitOwnStorage(CuTest* tc) {
	int res;
	int readCount;

	KSI_CTX *ctx = NULL;
	KSI_RDR *rdr = NULL;
	static char testData[] = "Random binary data.";
	char tmpBuf[0xffff];

	/* Init context. */
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Failed initializing context.", res == KSI_OK);

	/* Init reader. */
	res = KSI_RDR_fromMem(ctx, testData, sizeof(testData), 1, &rdr);
	CuAssert(tc, "Failed initializing context from private memory.", res == KSI_OK);
	CuAssert(tc, "Init did not fail, but object not created.", rdr != NULL);

	res = KSI_RDR_read(rdr, tmpBuf, sizeof(tmpBuf), &readCount);
	CuAssert(tc, "Incorrect read count.", readCount = sizeof(testData));



	KSI_RDR_close(rdr);
	KSI_CTX_free(ctx);
}

CuSuite* KSI_RDR_GetSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestRdrFileBadFileName);
	SUITE_ADD_TEST(suite, TestRdrFileFileReading);
	SUITE_ADD_TEST(suite, TestRdrFileReadingChuncks);

	SUITE_ADD_TEST(suite, TestRdrMemInitExtStorage);
	SUITE_ADD_TEST(suite, TestRdrMemInitOwnStorage);

	return suite;
}
