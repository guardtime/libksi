#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"

struct KSI_RDR_st {
	/* Context for the reader. */
	KSI_CTX *ctx;

	/* Type of the reader (see #KSI_IO_Type) */
	int ioType;

	/* Union of inputs. */
	union {
		/* KSI_IO_FILE type input. */
		FILE *file;

		/* KSI_IO_MEM type input */
		struct {
			char *buffer;
			size_t buffer_length;

			/* Does the memory belong to this reader? */
			int ownCopy;
		} mem;
	} data;

	/* Offset of stream. */
	size_t offset;

	/* Indicates end of stream.
	 * \note This will be set after reading the stream. */
	int eof;
};


static void TestRdrFileBadFileName(CuTest* tc) {
	int res;
	char tmpFile[] = "tmpXXXXXXXX";

	KSI_CTX *ctx = NULL;
	KSI_RDR *rdr = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

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
	char tmpFile[] = "tmpXXXXXXXX";
	unsigned char tmpBuf[0xffff];
	int readCount;

	static char testStr[] = "Randomness is too important to be left to chance";

	FILE *f = NULL;

	KSI_CTX *ctx = NULL;
	KSI_RDR *rdr = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", mkstemp(tmpFile) > 0);

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
	KSI_RDR_read_ex(rdr, tmpBuf, sizeof(tmpBuf), &readCount);

	CuAssert(tc, "Wrong length read", readCount == strlen(testStr));

	CuAssert(tc, "Reader is not at EOF", rdr->eof);
	KSI_RDR_close(rdr);

	/* Remove temporary file */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);


	KSI_CTX_free(ctx);
}


static void TestRdrFileReadingChuncks(CuTest* tc) {
	int res;
	char tmpFile[] = "tmpXXXXXXXX";
	unsigned char tmpBuf[0xffff];
	int readCount;
	int size = 0;

	static char testStr[] = "Randomness is too important to be left to chance";

	FILE *f = NULL;

	KSI_CTX *ctx = NULL;
	KSI_RDR *rdr = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", mkstemp(tmpFile) > 0);

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
		KSI_RDR_read_ex(rdr, tmpBuf + size, 10, &readCount);
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
	unsigned char tmpBuf[0xffff];

	/* Init context. */
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Failed initializing context.", res == KSI_OK);

	/* Init reader. */
	res = KSI_RDR_fromSharedMem(ctx, (unsigned char *)testData, sizeof(testData), &rdr);
	CuAssert(tc, "Failed initializing context from shared memory.", res == KSI_OK);
	CuAssert(tc, "Init did not fail, but object not created.", rdr != NULL);

	res = KSI_RDR_read_ex(rdr, tmpBuf, sizeof(tmpBuf), &readCount);
	CuAssert(tc, "Incorrect read count.", readCount = sizeof(testData));

	CuAssert(tc, "Data missmatch", !memcmp(tmpBuf, testData, sizeof(testData)));

	KSI_RDR_close(rdr);
	KSI_CTX_free(ctx);
}

static void TestRdrMemInitOwnStorage(CuTest* tc) {
	int res;
	int readCount;

	KSI_CTX *ctx = NULL;
	KSI_RDR *rdr = NULL;
	static char testData[] = "Random binary data.";
	unsigned char tmpBuf[0xffff];

	/* Init context. */
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Failed initializing context.", res == KSI_OK);

	/* Init reader. */
	res = KSI_RDR_fromMem(ctx, (unsigned char *) testData, sizeof(testData), &rdr);
	CuAssert(tc, "Failed initializing context from private memory.", res == KSI_OK);
	CuAssert(tc, "Init did not fail, but object not created.", rdr != NULL);

	res = KSI_RDR_read_ex(rdr, tmpBuf, sizeof(tmpBuf), &readCount);
	CuAssert(tc, "Incorrect read count.", readCount = sizeof(testData));

	CuAssert(tc, "Data missmatch", !memcmp(tmpBuf, testData, sizeof(testData)));

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
