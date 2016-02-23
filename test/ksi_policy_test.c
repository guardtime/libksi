/*
 * Copyright 2013-2016 Guardtime, Inc.
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
#include "../src/ksi/policy.h"
#include "../src/ksi/internal.h"

extern KSI_CTX *ctx;

static void TestInvalidParams(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createUserProvidedPublicationBased(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createUserProvidedPublicationBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createUserProvidedPublicationBased(ctx, &policy);
	CuAssert(tc, "Create policy failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_setFallback(NULL, policy, policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_setFallback(NULL, NULL, policy);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_setFallback(NULL, policy, NULL);
	CuAssert(tc, "Fallback policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(NULL, &context);
	CuAssert(tc, "KSI context NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, NULL);
	CuAssert(tc, "Verification context NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(NULL, context, &result);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, NULL, &result);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, NULL);
	CuAssert(tc, "Result NULL accepted", res == KSI_INVALID_ARGUMENT);

	/* TODO: create signature for verification */
	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	CuAssert(tc, "Policy verification accepted empty context", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	KSI_Policy_free(policy);
	KSI_VerificationContext_free(context);
	KSI_PolicyVerificationResult_free(result);
}

CuSuite* KSITest_Policy_getSuite(void) {
	CuSuite* suite = CuSuiteNew();
	SUITE_ADD_TEST(suite, TestInvalidParams);
	return suite;
}
