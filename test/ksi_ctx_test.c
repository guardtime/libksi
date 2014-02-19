#include "cutest/CuTest.h"

#include"../src/ksi_internal.h"

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
	KSI_CTX_new(&ctx);

	res = failingMethod(ctx, 1);
	CuAssert(tc, "Adding first fault failed.", res == KSI_INVALID_ARGUMENT);

	CuAssert(tc, "Context does not detect failure.", ctx->errors_count > 0);

	KSI_ERR_clearErrors(ctx);
	CuAssert(tc, "Clear error may not set state to success.", (ctx->errors_count == 0));

	res = failingMethod(ctx, 0);

	CuAssert(tc, "Context did not succeed", ctx->errors_count == 0);

	KSI_CTX_free(ctx);
}

static void TestCtxAddFailureOverflow(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	int i;


	KSI_CTX *ctx = NULL;
	KSI_CTX_new(&ctx);

	KSI_LOG_init(ctx, "test.log", KSI_LOG_DEBUG);

	for (i = 0;
			i < (ctx->errors_size) + 1;
			i++) {
		res = failingMethod(ctx, 1);
		CuAssert(tc, "Failed adding failure to failure stack.", res == KSI_INVALID_ARGUMENT);
	}

	KSI_CTX_free(ctx);
}

CuSuite* KSI_CTX_GetSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestCtxInit);
	SUITE_ADD_TEST(suite, TestCtxAddFailure);
	SUITE_ADD_TEST(suite, TestCtxAddFailureOverflow);

	return suite;
}
