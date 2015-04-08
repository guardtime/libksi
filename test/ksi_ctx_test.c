/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#include "cutest/CuTest.h"

#include "all_tests.h"
#include "../src/ksi/internal.h"

static int mockInitCount = 0;

static int mock_init(void) {
	mockInitCount++;
	return KSI_OK;
}

static void mock_cleanup(void) {
	mockInitCount--;
}

static void TestCtxInit(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *ctx = NULL;
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "KSI_CTX_init did not return KSI_OK", res == KSI_OK);
	CuAssert(tc, "Context is NULL.", ctx != NULL);

	KSI_CTX_free(ctx);
}

static void TestCtxAddFailureOverflow(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	int i;

	KSI_CTX *ctx = NULL;
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Unable to create ctx", res == KSI_OK && ctx != NULL);

	for (i = 0;
			i < 1000;
			i++) {
		res = failingMethod(ctx, 1);
		CuAssert(tc, "Failed adding failure to failure stack.", res == KSI_INVALID_ARGUMENT);
	}

	KSI_CTX_free(ctx);
}

static void TestRegisterGlobals(CuTest *tc) {
	int res;
	KSI_CTX *ctx = NULL;

	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Unable to create KSI context.", res == KSI_OK && ctx != NULL);

	res = KSI_CTX_registerGlobals(ctx, mock_init, mock_cleanup);
	CuAssert(tc, "Unable to register globals.", res == KSI_OK);

	res = KSI_CTX_registerGlobals(ctx, mock_init, mock_cleanup);
	CuAssert(tc, "Unable to register globals the 2nd time.", res == KSI_OK);

	CuAssert(tc, "Global init called wrong number of times", mockInitCount == 1);

	KSI_CTX_free(ctx);

	CuAssert(tc, "Globals not propperly cleaned up.", mockInitCount == 0);
}

CuSuite* KSITest_CTX_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestCtxInit);
	SUITE_ADD_TEST(suite, TestRegisterGlobals);

	return suite;
}
