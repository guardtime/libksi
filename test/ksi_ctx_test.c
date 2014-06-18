#include "cutest/CuTest.h"

#include "all_tests.h"
#include "../src/ksi/internal.h"

static int failingMethod(KSI_CTX *ctx, int caseNr) {
	KSI_ERR err;
	KSI_ERR_init(ctx, &err);

	switch (caseNr) {
		case 0: /* No failure */
			KSI_SUCCESS(&err);
			break;
		case 1:
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Some random error.");
			break;
		case 2:
			/* Forget to fail or succeed. */
			break;
	}

	return KSI_RETURN(&err);
}

static int failingPreCondition() {
	KSI_ERR err;

	KSI_PRE(&err, 1 > 2) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static void TestCtxInit(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *ctx = NULL;
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "KSI_CTX_init did not return KSI_OK", res == KSI_OK);
	CuAssert(tc, "Context is NULL.", ctx != NULL);

	KSI_CTX_free(ctx);
}



static void TestCtxAddFailure(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *ctx = NULL;
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Unable to create ctx", ctx != NULL);

	res = failingMethod(ctx, 1);
	CuAssert(tc, "Adding first fault failed.", res == KSI_INVALID_ARGUMENT);

	CuAssert(tc, "Context does not detect failure.", KSI_CTX_getStatus(ctx) != KSI_OK);

	KSI_ERR_clearErrors(ctx);
	CuAssert(tc, "Clear error may not set state to success.", KSI_CTX_getStatus(ctx) != KSI_OK);

	res = failingMethod(ctx, 0);

	CuAssert(tc, "Context did not succeed", KSI_CTX_getStatus(ctx) == KSI_OK);

	KSI_CTX_free(ctx);
}

static void TestCtxAddFailureOverflow(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	int i;
	KSI_Logger *logger = NULL;

	KSI_CTX *ctx = NULL;
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Unable to create ctx", ctx != NULL);

	res = KSI_Logger_new(ctx, "test.log", KSI_LOG_DEBUG, &logger);
	CuAssert(tc, "Unable to create logger", res == KSI_OK && logger != NULL);

	res = KSI_setLogger(ctx, logger);
	CuAssert(tc, "Unable to set logger", res == KSI_OK);

	for (i = 0;
			i < 1000;
			i++) {
		res = failingMethod(ctx, 1);
		CuAssert(tc, "Failed adding failure to failure stack.", res == KSI_INVALID_ARGUMENT);
	}

	KSI_CTX_free(ctx);
}

static void TestCtxFailingPreCondition(CuTest* tc) {
	int res;

	res = failingPreCondition();
	CuAssert(tc, "Precondition was unsuccessful", res == KSI_INVALID_ARGUMENT);
}

CuSuite* KSITest_CTX_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestCtxInit);
	SUITE_ADD_TEST(suite, TestCtxAddFailure);
	SUITE_ADD_TEST(suite, TestCtxAddFailureOverflow);
	SUITE_ADD_TEST(suite, TestCtxFailingPreCondition);

	return suite;
}
