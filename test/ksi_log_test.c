#include <stdio.h>

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"

/*** HELPER FUNCTIONS ***/

static void doLog(CuTest *tc, KSI_CTX *ctx) {
	KSI_LOG_debug(ctx, "Test log %s", "debug");
	KSI_LOG_warn(ctx, "Test log %s", "warn");
	KSI_LOG_info(ctx, "Test log %s", "info");
	KSI_LOG_error(ctx, "Test log %s", "error");
	KSI_LOG_fatal(ctx, "Test log %s", "fatal");
}

static int failWithError(KSI_CTX *ctx, int statusCode) {
	KSI_ERR err;
	KSI_ERR_init(ctx, &err);

	if (statusCode != KSI_OK) {
		KSI_fail(&err, statusCode, "Some random error");
	} else {
		KSI_success(&err);
	}
	return KSI_end(&err);
}


/*** TESTS ***/

static void TestLogInit(CuTest* tc) {
	int res;
	char tmpFile[L_tmpnam];
	char tmpBuf[0xffff];
	FILE *f = NULL;
	int len;

	KSI_CTX *ctx = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", tmpnam_r(tmpFile) != NULL);

	/* Init logging. */
	res = KSI_LOG_init(ctx, tmpFile, KSI_LOG_DEBUG );
	CuAssert(tc, "Failed to initialize logger.", res == KSI_OK);

	/* Generate data. */
	KSI_LOG_debug(ctx, "Test log %s", "file");

	/* Close context. */
	KSI_CTX_free(ctx);

	/* Read the log file. */
	f = fopen(tmpFile, "r");
	CuAssert(tc, "Unable to open log file.", f != NULL);

	/* Read log contents. */
	CuAssert(tc, "Unable to read log file", (len = fread(tmpBuf, 1, sizeof(tmpBuf) - 1, f)) > 0);
	tmpBuf[len] = '\0';

	/* Close file. */
	CuAssert(tc, "Unable to close file", !fclose(f));

	CuAssert(tc, "Wrong log data", !strcmp(tmpBuf, "DEBUG: Test log file\n"));

	/* Cleanup */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);
}

static void TestLogLevel(CuTest* tc) {
	int res;
	char tmpFile[L_tmpnam];
	char tmpBuf[0xffff];
	FILE *f = NULL;
	int len;

	KSI_CTX *ctx = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", tmpnam_r(tmpFile) != NULL);

	/* Init logging. */
	res = KSI_LOG_init(ctx, tmpFile, KSI_LOG_DEBUG );
	CuAssert(tc, "Failed to initialize logger.", res == KSI_OK);

	/* Generate data. */
	doLog(tc, ctx);

	/* Close context. */
	KSI_CTX_free(ctx);

	/* Read the log file. */
	f = fopen(tmpFile, "r");
	CuAssert(tc, "Unable to open log file.", f != NULL);

	/* Read log contents. */
	CuAssert(tc, "Unable to read log file", (len = fread(tmpBuf, 1, sizeof(tmpBuf) - 1, f)) > 0);
	tmpBuf[len] = '\0';

	/* Close file. */
	CuAssert(tc, "Unable to close file", !fclose(f));

	CuAssert(tc, "Wrong log data", !strcmp(tmpBuf,
			"DEBUG: Test log debug\n"
			"WARN: Test log warn\n"
			"INFO: Test log info\n"
			"ERROR: Test log error\n"
			"FATAL: Test log fatal\n"));

	/* Cleanup */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);
}

static void TestLogLevelRestriction(CuTest* tc) {
	int res;
	char tmpFile[L_tmpnam];
	char tmpBuf[0xffff];
	int len;
	FILE *f = NULL;

	KSI_CTX *ctx = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", tmpnam_r(tmpFile) != NULL);

	/* Init logging. */
	res = KSI_LOG_init(ctx, tmpFile, KSI_LOG_INFO );
	CuAssert(tc, "Failed to initialize logger.", res == KSI_OK);

	/* Generate data. */
	doLog(tc, ctx);

	/* Close context. */
	KSI_CTX_free(ctx);

	/* Read the log file. */
	f = fopen(tmpFile, "r");
	CuAssert(tc, "Unable to open log file.", f != NULL);

	/* Read log contents. */
	CuAssert(tc, "Unable to read log file", (len = fread(tmpBuf, 1, sizeof(tmpBuf) - 1, f)) > 0);
	tmpBuf[len] = '\0';

	CuAssert(tc, "Wrong log data", !strcmp(tmpBuf,
			"INFO: Test log info\n"
			"ERROR: Test log error\n"
			"FATAL: Test log fatal\n"));

	/* Cleanup */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);
}

static void TestDoNotChangeFault(CuTest* tc) {
	int res;
	char tmpFile[L_tmpnam];
	int i;

	static int failures[] = {KSI_IO_ERROR, KSI_INVALID_ARGUMENT, KSI_OUT_OF_MEMORY};

	KSI_CTX *ctx = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", tmpnam_r(tmpFile) != NULL);

	/* Init logging. */
	res = KSI_LOG_init(ctx, tmpFile, KSI_LOG_INFO );
	CuAssert(tc, "Failed to initialize logger.", res == KSI_OK);


	for (i = 0; i < sizeof(failures); i++) {
		/* Before logging - set context as failed. */
		res = failWithError(ctx, failures[i]);

		/* Generate data. */
		doLog(tc, ctx);

		/* The state of the context should be the same as before logging. */
		CuAssert(tc, "Context did not remain in failed state.", ctx->errors_count > 0);

		CuAssert(tc, "Failure status changed", res == failures[i]);

	}
	/* Close context. */
	KSI_CTX_free(ctx);

	/* Cleanup */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);

}

CuSuite* KSI_LOG_GetSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestLogInit);
	SUITE_ADD_TEST(suite, TestLogLevel);
	SUITE_ADD_TEST(suite, TestLogLevelRestriction);
	SUITE_ADD_TEST(suite, TestDoNotChangeFault);

	return suite;
}
