/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
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
