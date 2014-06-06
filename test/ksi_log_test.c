#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
		KSI_FAIL(&err, statusCode, "Some random error");
	} else {
		KSI_SUCCESS(&err);
	}
	return KSI_RETURN(&err);
}


/*** TESTS ***/

static void TestLogInit(CuTest* tc) {
	int res;
	char tmpFile[] = "tmpXXXXXXXX";
	char tmpBuf[0xffff];
	FILE *f = NULL;
	int len;
	KSI_Logger *logger = NULL;

	KSI_CTX *ctx = NULL;

	/* Init context. */
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Unable to create ctx", res == KSI_OK && ctx != NULL);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", mkstemp(tmpFile) > 0);

	/* Init logging. */
	res = KSI_Logger_new(ctx, tmpFile, KSI_LOG_DEBUG, &logger);
	CuAssert(tc, "Unable to create logger", res == KSI_OK && logger != NULL);

	res = KSI_setLogger(ctx, logger);
	CuAssert(tc, "Unable to set logger", res == KSI_OK);

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

	CuAssert(tc, "Wrong log data", strstr(tmpBuf, "DEBUG") != NULL);
	CuAssert(tc, "Wrong log data", strstr(tmpBuf, "Test log file\n") != NULL);

	/* Cleanup */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);
}

static void TestLogLevel(CuTest* tc) {
	int res;
	char tmpFile[] = "tmpXXXXXXXX";
	char tmpBuf[0xffff];
	FILE *f = NULL;
	int len;
	char *ptr = NULL;
	KSI_Logger *logger = NULL;

	KSI_CTX *ctx = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", mkstemp(tmpFile) > 0);

	/* Init logging. */
	res = KSI_Logger_new(ctx, tmpFile, KSI_LOG_DEBUG, &logger);
	CuAssert(tc, "Unable to create logger", res == KSI_OK && logger != NULL);

	res = KSI_setLogger(ctx, logger);
	CuAssert(tc, "Unable to set logger", res == KSI_OK);

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

	ptr = tmpBuf;
	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "DEBUG")) != NULL);
	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "Test log debug\n")) != NULL);

	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "WARN")) != NULL);
	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "Test log warn\n")) != NULL);

	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "INFO")) != NULL);
	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "Test log info\n")) != NULL);

	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "ERROR")) != NULL);
	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "Test log error\n")) != NULL);

	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "FATAL")) != NULL);
	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "Test log fatal\n")) != NULL);

	/* Cleanup */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);
}

static void TestLogLevelRestriction(CuTest* tc) {
	int res;
	char tmpFile[] = "tmpXXXXXXXX";
	char tmpBuf[0xffff];
	int len;
	char *ptr = NULL;
	FILE *f = NULL;
	KSI_Logger *logger = NULL;

	KSI_CTX *ctx = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", mkstemp(tmpFile) > 0);

	/* Init logging. */
	res = KSI_Logger_new(ctx, tmpFile, KSI_LOG_INFO, &logger);
	CuAssert(tc, "Unable to create logger", res == KSI_OK && logger != NULL);

	res = KSI_setLogger(ctx, logger);
	CuAssert(tc, "Unable to set logger", res == KSI_OK);

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

	ptr = tmpBuf;
	CuAssert(tc, "Wrong log data", (strstr(ptr, "DEBUG")) == NULL);
	CuAssert(tc, "Wrong log data", (strstr(ptr, "Test log debug\n")) == NULL);

	CuAssert(tc, "Wrong log data", (strstr(ptr, "WARN")) == NULL);
	CuAssert(tc, "Wrong log data", (strstr(ptr, "Test log warn\n")) == NULL);

	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "INFO")) != NULL);
	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "Test log info\n")) != NULL);

	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "ERROR")) != NULL);
	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "Test log error\n")) != NULL);

	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "FATAL")) != NULL);
	CuAssert(tc, "Wrong log data", (ptr = strstr(ptr, "Test log fatal\n")) != NULL);

	/* Cleanup */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);
	fclose(f);
}

static void TestDoNotChangeFault(CuTest* tc) {
	int res;
	char tmpFile[] = "tmpXXXXXXXX";
	int i;
	KSI_Logger *logger = NULL;

	static int failures[] = {KSI_IO_ERROR, KSI_INVALID_ARGUMENT, KSI_OUT_OF_MEMORY};

	KSI_CTX *ctx = NULL;

	/* Init context. */
	KSI_CTX_new(&ctx);

	/* Create tmp file name. */
	CuAssert(tc, "Unable to create temporary file name.", mkstemp(tmpFile) > 0);

	/* Init logging. */
	res = KSI_Logger_new(ctx, tmpFile, KSI_LOG_INFO, &logger);
	CuAssert(tc, "Unable to create logger", res == KSI_OK && logger != NULL);

	res = KSI_setLogger(ctx, logger);
	CuAssert(tc, "Unable to set logger", res == KSI_OK);


	for (i = 0; i < sizeof(failures); i++) {
		/* Before logging - set context as failed. */
		res = failWithError(ctx, failures[i]);

		/* Generate data. */
		doLog(tc, ctx);

		/* The state of the context should be the same as before logging. */
		CuAssert(tc, "Context did not remain in failed state.", KSI_CTX_getStatus(ctx) == failures[i]);
	}
	/* Close context. */
	KSI_CTX_free(ctx);

	/* Cleanup */
	CuAssert(tc, "Unable to remove temporary file", remove(tmpFile) == 0);

}

CuSuite* KSITest_LOG_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestLogInit);
	SUITE_ADD_TEST(suite, TestLogLevel);
	SUITE_ADD_TEST(suite, TestLogLevelRestriction);
	SUITE_ADD_TEST(suite, TestDoNotChangeFault);

	return suite;
}
