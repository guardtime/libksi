#include <stdio.h>

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"

static void TestLogInit(CuTest* tc) {
	int res;
	char tmpFile[L_tmpnam];
	char tmpBuf[0xffff];
	FILE *f = NULL;
	int len;

	KSI_CTX *ctx = NULL;

	/* Init context. */
	KSI_CTX_init(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", tmpnam_r(tmpFile) != NULL);

	/* Init logging. */
	KSI_LOG_init(ctx, tmpFile, KSI_LOG_DEBUG );
	CuAssert(tc, "Failed to initialize logger.", KSI_OK(ctx));

	/* Generate data. */
	KSI_LOG_debug(ctx, "Test log %s", "file");
	CuAssert(tc, "Logging failed.", KSI_OK(ctx));

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
	KSI_CTX_init(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", tmpnam_r(tmpFile) != NULL);

	/* Init logging. */
	KSI_LOG_init(ctx, tmpFile, KSI_LOG_DEBUG );
	CuAssert(tc, "Failed to initialize logger.", KSI_OK(ctx));

	/* Generate data. */
	KSI_LOG_debug(ctx, "Test log %s", "file");
	CuAssert(tc, "Logging failed.", KSI_OK(ctx));

	KSI_LOG_warn(ctx, "Test log %s", "file");
	CuAssert(tc, "Logging failed.", KSI_OK(ctx));

	KSI_LOG_info(ctx, "Test log %s", "file");
	CuAssert(tc, "Logging failed.", KSI_OK(ctx));

	KSI_LOG_error(ctx, "Test log %s", "file");
	CuAssert(tc, "Logging failed.", KSI_OK(ctx));

	KSI_LOG_fatal(ctx, "Test log %s", "file");
	CuAssert(tc, "Logging failed.", KSI_OK(ctx));

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
			"DEBUG: Test log file\n"
			"WARN: Test log file\n"
			"INFO: Test log file\n"
			"ERROR: Test log file\n"
			"FATAL: Test log file\n"));

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
	KSI_CTX_init(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", tmpnam_r(tmpFile) != NULL);

	/* Init logging. */
	KSI_LOG_init(ctx, tmpFile, KSI_LOG_INFO );
	CuAssert(tc, "Failed to initialize logger.", KSI_OK(ctx));

	/* Generate data. */
	KSI_LOG_debug(ctx, "Test log %s", "debug");
	CuAssert(tc, "Logging failed.", KSI_OK(ctx));

	KSI_LOG_warn(ctx, "Test log %s", "warn");
	CuAssert(tc, "Logging failed.", KSI_OK(ctx));

	KSI_LOG_info(ctx, "Test log %s", "info");
	CuAssert(tc, "Logging failed.", KSI_OK(ctx));

	KSI_LOG_error(ctx, "Test log %s", "error");
	CuAssert(tc, "Logging failed.", KSI_OK(ctx));

	KSI_LOG_fatal(ctx, "Test log %s", "fatal");
	CuAssert(tc, "Logging failed.", KSI_OK(ctx));

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



CuSuite* KSI_LOG_GetSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestLogInit);
	SUITE_ADD_TEST(suite, TestLogLevel);
	SUITE_ADD_TEST(suite, TestLogLevelRestriction);

	return suite;
}
