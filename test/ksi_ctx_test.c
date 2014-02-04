#include "cutest-1.5/CuTest.h"

#include"../src/ksi_internal.h"

static void TestCtxInit(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *ctx = NULL;
	res = KSI_CTX_init(&ctx);
	CuAssert(tc, "KSI_CTX_init did not return KSI_OK", res == KSI_OK);
	CuAssert(tc, "Context is NULL.", ctx != NULL);

	KSI_CTX_free(ctx);
}

static void TestCtxAddFailure(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *ctx = NULL;
	KSI_CTX_init(&ctx);

	res = KSI_fail(ctx, KSI_INVALID_ARGUMENT, "Some random test fault just happened.");
	CuAssert(tc, "Adding first fault failed.", res == KSI_OK);

	CuAssert(tc, "Context does not detect failure.", !KSI_ERR_isOK(ctx));

	KSI_ERR_clearErrors(ctx);
	CuAssert(tc, "Clear error may not set state to success.", !KSI_ERR_isOK(ctx));

	KSI_success(ctx);
	CuAssert(tc, "Context did not succeed", KSI_ERR_isOK(ctx));

	KSI_CTX_free(ctx);
}

static void TestCtxAddFailureOverflow(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	int i;


	KSI_CTX *ctx = NULL;
	KSI_CTX_init(&ctx);

	KSI_LOG_init(ctx, "test.log", KSI_LOG_DEBUG);

	for (i = 0;
			i < (ctx->errors_size) + 1;
			i++) {
		res = KSI_fail(ctx, KSI_INVALID_ARGUMENT, "Some random test fault just happened.");
		CuAssert(tc, "Failed adding failure to failure stack.", res == KSI_OK);
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
