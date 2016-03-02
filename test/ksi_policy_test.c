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
#include "../src/ksi/policy_impl.h"
#include "../src/ksi/ctx_impl.h"
#include "../src/ksi/net_impl.h"
#include "../src/ksi/verification_impl.h"
#include "../src/ksi/signature_impl.h"
#include "../src/ksi/hashchain.h"

extern KSI_CTX *ctx;

#define TEST_USER "anon"
#define TEST_PASS "anon"

static void preTest(void) {
	ctx->netProvider->requestCount = 0;
}

typedef struct {
	const Rule *rule;
	int res;
	VerificationResultCode result;
	VerificationErrorCode error;
} TestRule;

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

#define DUMMY_VERIFIER(resValue, resultValue, errorValue) DummyRule_Return_##resValue##_##resultValue##_##errorValue
#define IMPLEMENT_DUMMY_VERIFIER(resValue, resultValue, errorValue) \
static int DUMMY_VERIFIER(resValue, resultValue, errorValue)(VerificationContext *context, KSI_RuleVerificationResult *result) {\
	result->resultCode = resultValue;\
	result->errorCode = errorValue;\
	result->ruleName = __FUNCTION__;\
	return resValue;\
}

IMPLEMENT_DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1);
IMPLEMENT_DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_2);
IMPLEMENT_DUMMY_VERIFIER(KSI_OK, VER_RES_FAIL, VER_ERR_INT_1);
IMPLEMENT_DUMMY_VERIFIER(KSI_OK, VER_RES_NA, VER_ERR_GEN_1);
IMPLEMENT_DUMMY_VERIFIER(KSI_INVALID_ARGUMENT, VER_RES_OK, VER_ERR_CAL_1);

static const Rule singleRule1[] = {
	{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule singleRule2[] = {
	{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_2)},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule singleRule3[] = {
	{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_FAIL, VER_ERR_INT_1)},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule singleRule4[] = {
	{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_NA, VER_ERR_GEN_1)},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule singleRule5[] = {
	{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_INVALID_ARGUMENT, VER_RES_OK, VER_ERR_CAL_1)},
	{RULE_TYPE_BASIC, NULL}
};

static void TestSingleRulePolicy(CuTest* tc) {
	int res;
	int i;
	KSI_Policy policy;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;

	TestRule rules[] = {
		{singleRule1, KSI_OK,				VER_RES_OK,		VER_ERR_PUB_1},
		{singleRule2, KSI_OK,				VER_RES_OK,		VER_ERR_PUB_2},
		{singleRule3, KSI_OK,				VER_RES_FAIL,	VER_ERR_INT_1},
		{singleRule4, KSI_OK,				VER_RES_NA,		VER_ERR_GEN_1},
		{singleRule5, KSI_INVALID_ARGUMENT,	VER_RES_NA,		VER_ERR_GEN_2},
	};

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	policy.fallbackPolicy = NULL;

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		policy.rules = rules[i].rule;
		res = KSI_Policy_verify(&policy, context, &result);
		CuAssert(tc, "Policy verification failed", res == rules[i].res);
		CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == rules[i].result && result->finalResult.errorCode == rules[i].error);
		KSI_PolicyVerificationResult_free(result);
	}

	KSI_VerificationContext_free(context);
}

static void TestBasicRulesPolicy(CuTest* tc) {
	int res;
	int i;
	KSI_Policy policy;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;

	static const Rule basicRules1[] = {
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_2)},
		{RULE_TYPE_BASIC, NULL}
	};

	static const Rule basicRules2[] = {
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_FAIL, VER_ERR_INT_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_2)},
		{RULE_TYPE_BASIC, NULL}
	};

	static const Rule basicRules3[] = {
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_NA, VER_ERR_GEN_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_2)},
		{RULE_TYPE_BASIC, NULL}
	};

	static const Rule basicRules4[] = {
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_INVALID_ARGUMENT, VER_RES_OK, VER_ERR_CAL_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_1)},
		{RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, VER_RES_OK, VER_ERR_PUB_2)},
		{RULE_TYPE_BASIC, NULL}
	};

	TestRule rules[] = {
		{basicRules1, KSI_OK,				VER_RES_OK,		VER_ERR_PUB_2},
		{basicRules2, KSI_OK,				VER_RES_FAIL,	VER_ERR_INT_1},
		{basicRules3, KSI_OK,				VER_RES_NA,		VER_ERR_GEN_1},
		{basicRules4, KSI_INVALID_ARGUMENT,	VER_RES_NA,		VER_ERR_GEN_2},
	};

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	policy.fallbackPolicy = NULL;

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		policy.rules = rules[i].rule;
		res = KSI_Policy_verify(&policy, context, &result);
		CuAssert(tc, "Policy verification failed", res == rules[i].res);
		CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == rules[i].result && result->finalResult.errorCode == rules[i].error);
		KSI_PolicyVerificationResult_free(result);
	}

	KSI_VerificationContext_free(context);
}

static void TestCompositeRulesPolicy(CuTest* tc) {
	int res;
	int i;
	KSI_Policy policy;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;

	static const Rule compositeRule1[] = {
		{RULE_TYPE_COMPOSITE_AND, singleRule1},
		{RULE_TYPE_COMPOSITE_AND, singleRule2},
		{RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const Rule compositeRule2[] = {
		{RULE_TYPE_COMPOSITE_AND, singleRule2},
		{RULE_TYPE_COMPOSITE_AND, singleRule1},
		{RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const Rule compositeRule3[] = {
		{RULE_TYPE_COMPOSITE_OR, singleRule2},
		{RULE_TYPE_COMPOSITE_OR, singleRule1},
		{RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const Rule compositeRule4[] = {
		{RULE_TYPE_COMPOSITE_OR, singleRule1},
		{RULE_TYPE_COMPOSITE_OR, singleRule2},
		{RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const Rule compositeRule5[] = {
		{RULE_TYPE_COMPOSITE_AND, singleRule1},
		{RULE_TYPE_COMPOSITE_AND, singleRule3},
		{RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const Rule compositeRule6[] = {
		{RULE_TYPE_COMPOSITE_AND, singleRule4},
		{RULE_TYPE_COMPOSITE_AND, singleRule1},
		{RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const Rule compositeRule7[] = {
		{RULE_TYPE_COMPOSITE_OR, singleRule1},
		{RULE_TYPE_COMPOSITE_OR, singleRule4},
		{RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const Rule compositeRule8[] = {
		{RULE_TYPE_COMPOSITE_OR, singleRule3},
		{RULE_TYPE_COMPOSITE_OR, singleRule1},
		{RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const Rule compositeRule9[] = {
		{RULE_TYPE_COMPOSITE_AND, singleRule1},
		{RULE_TYPE_COMPOSITE_AND, singleRule5},
		{RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const Rule compositeRule10[] = {
		{RULE_TYPE_COMPOSITE_AND, singleRule5},
		{RULE_TYPE_COMPOSITE_AND, singleRule1},
		{RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const Rule compositeRule11[] = {
		{RULE_TYPE_COMPOSITE_OR, singleRule1},
		{RULE_TYPE_COMPOSITE_OR, singleRule5},
		{RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const Rule compositeRule12[] = {
		{RULE_TYPE_COMPOSITE_OR, singleRule5},
		{RULE_TYPE_COMPOSITE_OR, singleRule1},
		{RULE_TYPE_COMPOSITE_OR, NULL}
	};

	TestRule rules[] = {
		{compositeRule1,	KSI_OK,					VER_RES_OK,		VER_ERR_PUB_2},
		{compositeRule2,	KSI_OK,					VER_RES_OK,		VER_ERR_PUB_1},
		{compositeRule3,	KSI_OK,					VER_RES_OK,		VER_ERR_PUB_2},
		{compositeRule4,	KSI_OK,					VER_RES_OK,		VER_ERR_PUB_1},
		{compositeRule5,	KSI_OK,					VER_RES_FAIL,	VER_ERR_INT_1},
		{compositeRule6,	KSI_OK,					VER_RES_NA,		VER_ERR_GEN_1},
		{compositeRule7,	KSI_OK,					VER_RES_OK,		VER_ERR_PUB_1},
		{compositeRule8,	KSI_OK,					VER_RES_FAIL,	VER_ERR_INT_1},
		{compositeRule9,	KSI_INVALID_ARGUMENT,	VER_RES_NA,		VER_ERR_GEN_2},
		{compositeRule10,	KSI_INVALID_ARGUMENT,	VER_RES_NA,		VER_ERR_GEN_2},
		{compositeRule11,	KSI_OK,					VER_RES_OK,		VER_ERR_PUB_1},
		{compositeRule12,	KSI_OK,					VER_RES_OK,		VER_ERR_PUB_1}
	};

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	policy.fallbackPolicy = NULL;

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		policy.rules = rules[i].rule;
		res = KSI_Policy_verify(&policy, context, &result);
		CuAssert(tc, "Policy verification failed", res == rules[i].res);
		CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == rules[i].result && result->finalResult.errorCode == rules[i].error);
		KSI_PolicyVerificationResult_free(result);
	}

	KSI_VerificationContext_free(context);
}

static void TestCalendarBasedPolicy_OK_WithPublicationRecord(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_OK && result->finalResult.errorCode == VER_ERR_NONE);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestCalendarBasedPolicy_FAIL_WithPublicationRecord(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_FAIL && result->finalResult.errorCode == VER_ERR_CAL_1);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_OK_WithoutPublicationRecord(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_OK && result->finalResult.errorCode == VER_ERR_NONE);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_FAIL_WithoutPublicationRecord(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_FAIL && result->finalResult.errorCode == VER_ERR_CAL_4);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_OK_WithoutCalendarHashChain(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	KSI_CalendarHashChain_free(context->userData.sig->calendarChain);
	context->userData.sig->calendarChain = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_OK && result->finalResult.errorCode == VER_ERR_NONE);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_FAIL_WithoutCalendarHashChain(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	KSI_CalendarHashChain_free(context->userData.sig->calendarChain);
	context->userData.sig->calendarChain = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_FAIL && result->finalResult.errorCode == VER_ERR_CAL_2);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestKeyBasedPolicy_NA_WithoutCalendarHashChain(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	KSI_CalendarHashChain_free(context->userData.sig->calendarChain);
	context->userData.sig->calendarChain = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_NA && result->finalResult.errorCode == VER_ERR_GEN_2);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
}

static void TestKeyBasedPolicy_NA_WithoutCalendarAuthenticationRecord(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/signature-calendar-authentication-record-missing.ksig"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_NA && result->finalResult.errorCode == VER_ERR_GEN_2);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
}

static void TestKeyBasedPolicy_FAIL_WithCalendarAuthenticationRecord(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-authentication-record-hash.ksig"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_FAIL && result->finalResult.errorCode == VER_ERR_INT_8);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
}

static void TestKeyBasedPolicy_FAIL_WithoutCertificate(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications-one-cert-one-publication-record-with-wrong-hash.tlv"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->tempData.publicationsFile != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_FAIL && result->finalResult.errorCode == VER_ERR_KEY_1);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestKeyBasedPolicy_FAIL_WithCertificate(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE    "resource/tlv/signature-cal-auth-wrong-signing-value.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->tempData.publicationsFile != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_FAIL && result->finalResult.errorCode == VER_ERR_KEY_2);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestKeyBasedPolicy_OK(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->tempData.publicationsFile != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_OK && result->finalResult.errorCode == VER_ERR_NONE);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_OK_WithPublicationRecord(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->tempData.publicationsFile != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_OK && result->finalResult.errorCode == VER_ERR_NONE);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_NA_WithPublicationRecord(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->tempData.publicationsFile != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_NA && result->finalResult.errorCode == VER_ERR_GEN_2);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_NA_WithoutSuitablePublication(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->tempData.publicationsFile != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_NA && result->finalResult.errorCode == VER_ERR_GEN_2);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_NA_WithSuitablePublication(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->tempData.publicationsFile != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_NA && result->finalResult.errorCode == VER_ERR_GEN_2);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_OK_WithSuitablePublication(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->tempData.publicationsFile != NULL);

	context->userData.extendingAllowed = true;

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_OK && result->finalResult.errorCode == VER_ERR_NONE);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_FAIL_AfterExtending(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->tempData.publicationsFile != NULL);

	context->userData.extendingAllowed = true;

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_FAIL && result->finalResult.errorCode == VER_ERR_PUB_1);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestUserProvidedPublicationBasedPolicy(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok.ksig"

	KSI_LOG_debug(ctx, __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createUserProvidedPublicationBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_verify(policy, context, &result);
	KSI_LOG_debug(ctx, "Policy verification res = %i, result = %i, error = %i", res, result->finalResult.resultCode, result->finalResult.errorCode);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == VER_RES_OK && result->finalResult.errorCode == VER_ERR_NONE);

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
}

CuSuite* KSITest_Policy_getSuite(void) {
	CuSuite* suite = CuSuiteNew();
	suite->preTest = preTest;
	SUITE_ADD_TEST(suite, TestInvalidParams);
	SUITE_ADD_TEST(suite, TestSingleRulePolicy);
	SUITE_ADD_TEST(suite, TestBasicRulesPolicy);
	SUITE_ADD_TEST(suite, TestCompositeRulesPolicy);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_OK_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_FAIL_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_OK_WithoutPublicationRecord);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_FAIL_WithoutPublicationRecord);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_OK_WithoutCalendarHashChain);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_FAIL_WithoutCalendarHashChain);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_NA_WithoutCalendarHashChain);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_NA_WithoutCalendarAuthenticationRecord);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_FAIL_WithCalendarAuthenticationRecord);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_FAIL_WithoutCertificate);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_FAIL_WithCertificate);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_OK);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_OK_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_NA_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_NA_WithoutSuitablePublication);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_NA_WithSuitablePublication);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_OK_WithSuitablePublication);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_FAIL_AfterExtending);
	//SUITE_ADD_TEST(suite, TestUserProvidedPublicationBasedPolicy);
	return suite;
}
