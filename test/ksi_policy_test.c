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
#include <string.h>
#include "../src/ksi/policy.h"
#include "../src/ksi/internal.h"
#include "../src/ksi/policy_impl.h"
#include "../src/ksi/ctx_impl.h"
#include "../src/ksi/net_impl.h"
#include "../src/ksi/verification_impl.h"
#include "../src/ksi/signature_impl.h"
#include "../src/ksi/hashchain.h"
#include "../src/ksi/publicationsfile_impl.h"
#include "../src/ksi/hash_impl.h"

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

	res = KSI_Policy_createKeyBased(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_createPublicationsFileBased(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_createUserProvidedPublicationBased(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_createCalendarBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_createKeyBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_createPublicationsFileBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_createUserProvidedPublicationBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_createUserProvidedPublicationBased(ctx, &policy);
	CuAssert(tc, "Create policy failed", res == KSI_OK);

	res = KSI_Policy_setFallback(NULL, policy, policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_setFallback(NULL, NULL, policy);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_setFallback(NULL, policy, NULL);
	CuAssert(tc, "Fallback policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_VerificationContext_create(NULL, &context);
	CuAssert(tc, "KSI context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_VerificationContext_create(ctx, NULL);
	CuAssert(tc, "Verification context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	res = KSI_VerificationContext_setSignature(NULL, NULL);
	CuAssert(tc, "Verification context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_VerificationContext_setDocumentHash(NULL, NULL);
	CuAssert(tc, "Verification context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_VerificationContext_setUserPublication(NULL, NULL);
	CuAssert(tc, "Verification context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_VerificationContext_setPublicationsFile(NULL, NULL);
	CuAssert(tc, "Verification context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_VerificationContext_setExtendingAllowed(NULL, true);
	CuAssert(tc, "Verification context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_SignatureVerifier_verify(NULL, context, &result);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_SignatureVerifier_verify(policy, NULL, &result);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_SignatureVerifier_verify(policy, context, NULL);
	CuAssert(tc, "Result NULL accepted", res == KSI_INVALID_ARGUMENT);

	/* TODO: create signature for verification */
	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification accepted empty context", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	KSI_Policy_free(policy);
	KSI_VerificationContext_free(context);
	KSI_PolicyVerificationResult_free(result);
}

static void TestVerificationContext(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_MOCK_IMPRINT   "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	VerificationContext *context = NULL;
	KSI_Signature *sig = NULL;
	KSI_Signature *extSig = NULL;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *aggrHash = NULL;
	KSI_PublicationData *userPublication = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;
	KSI_PublicationsFile *publicationsFile = NULL;
	static const char publicationString[] = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK && context != NULL && context->ctx == ctx);
	CuAssert(tc, "Non-empty verification context created",
			 context->userData.sig == NULL &&
			 context->userData.documentHash == NULL &&
			 context->userData.userPublication == NULL &&
			 context->userData.userPublicationsFile == NULL &&
			 context->userData.extendingAllowed == false &&
			 context->userData.docAggrLevel == 0 &&
			 context->tempData.extendedSig == NULL &&
			 context->tempData.publicationsFile == NULL &&
			 context->tempData.aggregationOutputHash == NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &extSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && extSig != NULL);

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &hash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && hash != NULL);

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &aggrHash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && aggrHash != NULL);

	res = KSI_PublicationData_fromBase32(ctx, publicationString, &userPublication);
	CuAssert(tc, "Failed decoding publication string.", res == KSI_OK && userPublication != NULL);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && publicationsFile != NULL);

	res = KSI_VerificationContext_setSignature(context, sig);
	CuAssert(tc, "Failed to set signature", res == KSI_OK && context->userData.sig == sig);

	res = KSI_VerificationContext_setDocumentHash(context, hash);
	CuAssert(tc, "Failed to set document hash", res == KSI_OK && context->userData.documentHash == hash);

	res = KSI_VerificationContext_setUserPublication(context, userPublication);
	CuAssert(tc, "Failed to set user publication", res == KSI_OK && context->userData.userPublication == userPublication);

	res = KSI_VerificationContext_setPublicationsFile(context, userPublicationsFile);
	CuAssert(tc, "Failed to set publications file", res == KSI_OK && context->userData.userPublicationsFile == userPublicationsFile);

	res = KSI_VerificationContext_setExtendingAllowed(context, true);
	CuAssert(tc, "Failed to set extending allowed flag", res == KSI_OK && context->userData.extendingAllowed == true);

	res = KSI_VerificationContext_setAggregationLevel(context, 10);
	CuAssert(tc, "Failed to set extending allowed flag", res == KSI_OK && context->userData.docAggrLevel == 10);

	context->tempData.extendedSig = extSig;
	context->tempData.aggregationOutputHash = aggrHash;
	context->tempData.publicationsFile = publicationsFile;

	KSI_VerificationContext_clean(context);
	CuAssert(tc, "Verification context not cleaned",
			 context->tempData.extendedSig == NULL &&
			 context->tempData.aggregationOutputHash == NULL &&
			 context->tempData.publicationsFile == NULL);

	KSI_VerificationContext_free(context);
	KSI_PublicationsFile_free(publicationsFile);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_MOCK_IMPRINT
#undef TEST_PUBLICATIONS_FILE
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

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	policy.fallbackPolicy = NULL;

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		policy.rules = rules[i].rule;
		res = KSI_SignatureVerifier_verify(&policy, context, &result);
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

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	policy.fallbackPolicy = NULL;

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		policy.rules = rules[i].rule;
		res = KSI_SignatureVerifier_verify(&policy, context, &result);
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

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	policy.fallbackPolicy = NULL;

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		policy.rules = rules[i].rule;
		res = KSI_SignatureVerifier_verify(&policy, context, &result);
		CuAssert(tc, "Policy verification failed", res == rules[i].res);
		CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == rules[i].result && result->finalResult.errorCode == rules[i].error);
		KSI_PolicyVerificationResult_free(result);
	}

	KSI_VerificationContext_free(context);
}

bool ResultsMatch(KSI_PolicyResult *expected, KSI_PolicyResult *actual) {
	bool match = true;

	if (expected->resultCode != actual->resultCode) {
		KSI_LOG_debug(ctx, "Expected result: %i, actual result: %i", expected->resultCode, actual->resultCode);
		match = false;
	}
	if (expected->errorCode != actual->errorCode) {
		KSI_LOG_debug(ctx, "Expected error: %i, actual error: %i", expected->errorCode, actual->errorCode);
		match = false;
	}
	if (strcmp(expected->ruleName, actual->ruleName)) {
		KSI_LOG_debug(ctx, "Expected rule name: %s", expected->ruleName);
		KSI_LOG_debug(ctx, "Actual rule name: %s", actual->ruleName);
		match = false;
	}

	return match;
}

static void TestCalendarBasedPolicy_OK_WithPublicationRecord(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PolicyResult expected = {
		VER_RES_OK,
		VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_FAIL,
		VER_ERR_CAL_1,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash"
	};
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_OK,
		VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_FAIL,
		VER_ERR_CAL_4,
		"KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_OK,
		VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	KSI_CalendarHashChain_free(context->userData.sig->calendarChain);
	context->userData.sig->calendarChain = NULL;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_FAIL,
		VER_ERR_CAL_2,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	KSI_CalendarHashChain_free(context->userData.sig->calendarChain);
	context->userData.sig->calendarChain = NULL;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_NA,
		VER_ERR_GEN_2,
		"KSI_VerificationRule_CalendarHashChainExistence"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	KSI_CalendarHashChain_free(context->userData.sig->calendarChain);
	context->userData.sig->calendarChain = NULL;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_NA,
		VER_ERR_GEN_2,
		"KSI_VerificationRule_CalendarAuthenticationRecordExistence"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-calendar-authentication-record-missing.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_FAIL,
		VER_ERR_INT_8,
		"KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-authentication-record-hash.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_FAIL,
		VER_ERR_KEY_1,
		"KSI_VerificationRule_CertificateExistence"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications-one-cert-one-publication-record-with-wrong-hash.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->userData.userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->userData.userPublicationsFile != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_FAIL,
		VER_ERR_KEY_2,
		"KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/signature-cal-auth-wrong-signing-value.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->userData.userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->userData.userPublicationsFile != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_OK,
		VER_ERR_NONE,
		"KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->userData.userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->userData.userPublicationsFile != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_OK,
		VER_ERR_NONE,
		"KSI_VerificationRule_PublicationsFileContainsSignaturePublication"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->userData.userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->userData.userPublicationsFile != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_NA,
		VER_ERR_GEN_2,
		"KSI_VerificationRule_SignatureDoesNotContainPublication"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->userData.userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->userData.userPublicationsFile != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_NA,
		VER_ERR_GEN_2,
		"KSI_VerificationRule_PublicationsFileContainsPublication"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->userData.userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->userData.userPublicationsFile != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_NA,
		VER_ERR_GEN_2,
		"KSI_VerificationRule_ExtendingPermittedVerification"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->userData.userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->userData.userPublicationsFile != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_OK,
		VER_ERR_NONE,
		"KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->userData.userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->userData.userPublicationsFile != NULL);

	context->userData.extendingAllowed = true;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

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
	KSI_PolicyResult expected = {
		VER_RES_FAIL,
		VER_ERR_PUB_1,
		"KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createPublicationsFileBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->userData.userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->userData.userPublicationsFile != NULL);

	context->userData.extendingAllowed = true;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestUserProvidedPublicationBasedPolicy_OK_WithPublicationRecord(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_PolicyResult expected = {
		VER_RES_OK,
		VER_ERR_NONE,
		"KSI_VerificationRule_UserProvidedPublicationVerification"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createUserProvidedPublicationBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_getPublicationRecord(context->userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &context->userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context->userData.userPublication != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
}

static void TestUserProvidedPublicationBasedPolicy_NA_WithSignatureAfterPublication(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Integer *mockTime = NULL;
	KSI_Signature *sig = NULL;
	KSI_PolicyResult expected = {
		VER_RES_NA,
		VER_ERR_GEN_2,
		"KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_TIMESTAMP      1396608816

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createUserProvidedPublicationBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getPublicationRecord(sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &context->userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context->userData.userPublication != NULL);

	res = KSI_Integer_new(ctx, TEST_TIMESTAMP, &mockTime);
	CuAssert(tc, "Unable to create publication time", res == KSI_OK && mockTime != NULL);

	KSI_Integer_free(context->userData.userPublication->time);
	res = KSI_PublicationData_setTime(context->userData.userPublication, mockTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_Signature_free(sig);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
#undef TEST_TIMESTAMP
}

static void TestUserProvidedPublicationBasedPolicy_NA_WithSignatureBeforePublication(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sig = NULL;
	KSI_PolicyResult expected = {
		VER_RES_NA,
		VER_ERR_GEN_2,
		"KSI_VerificationRule_ExtendingPermittedVerification"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createUserProvidedPublicationBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getPublicationRecord(sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &context->userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context->userData.userPublication != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_Signature_free(sig);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
}

static void TestUserProvidedPublicationBasedPolicy_OK_WithoutPublicationRecord(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sig = NULL;
	KSI_PolicyResult expected = {
		VER_RES_OK,
		VER_ERR_NONE,
		"KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createUserProvidedPublicationBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getPublicationRecord(sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &context->userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context->userData.userPublication != NULL);

	context->userData.extendingAllowed = true;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_Signature_free(sig);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
}

static void TestUserProvidedPublicationBasedPolicy_FAIL_AfterExtending(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sig = NULL;
	KSI_PolicyResult expected = {
		VER_RES_FAIL,
		VER_ERR_PUB_1,
		"KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createUserProvidedPublicationBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getPublicationRecord(sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &context->userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context->userData.userPublication != NULL);

	context->userData.extendingAllowed = true;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_Signature_free(sig);
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
}

static void TestFallbackPolicy_KeyBased_NA_CalendarBased_OK(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	KSI_Policy *fallbackPolicy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PolicyResult expected = {
		VER_RES_OK,
		VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_createCalendarBased(ctx, &fallbackPolicy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_setFallback(ctx, policy, fallbackPolicy);
	CuAssert(tc, "Fallback policy setup failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	KSI_CalendarHashChain_free(context->userData.sig->calendarChain);
	context->userData.sig->calendarChain = NULL;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	context->ctx->publicationsFile = NULL;
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
	KSI_Policy_free(fallbackPolicy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestFallbackPolicy_CalendarBased_OK_KeyBased_NA(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	KSI_Policy *fallbackPolicy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PolicyResult expected = {
		VER_RES_OK,
		VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_createKeyBased(ctx, &fallbackPolicy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_setFallback(ctx, policy, fallbackPolicy);
	CuAssert(tc, "Fallback policy setup failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	KSI_CalendarHashChain_free(context->userData.sig->calendarChain);
	context->userData.sig->calendarChain = NULL;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	context->ctx->publicationsFile = NULL;
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
	KSI_Policy_free(fallbackPolicy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestFallbackPolicy_KeyBased_NA_CalendarBased_FAIL(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	KSI_Policy *fallbackPolicy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PolicyResult expected = {
		VER_RES_FAIL,
		VER_ERR_CAL_2,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_createCalendarBased(ctx, &fallbackPolicy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_setFallback(ctx, policy, fallbackPolicy);
	CuAssert(tc, "Fallback policy setup failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	KSI_CalendarHashChain_free(context->userData.sig->calendarChain);
	context->userData.sig->calendarChain = NULL;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	context->ctx->publicationsFile = NULL;
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
	KSI_Policy_free(fallbackPolicy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestFallbackPolicy_CalendarBased_FAIL_KeyBased_NA(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	KSI_Policy *fallbackPolicy = NULL;
	VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PolicyResult expected = {
		VER_RES_NA,
		VER_ERR_GEN_2,
		"KSI_VerificationRule_CalendarHashChainExistence"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_createCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_createKeyBased(ctx, &fallbackPolicy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_setFallback(ctx, policy, fallbackPolicy);
	CuAssert(tc, "Fallback policy setup failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &context->tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->tempData.extendedSig != NULL);

	KSI_CalendarHashChain_free(context->userData.sig->calendarChain);
	context->userData.sig->calendarChain = NULL;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	context->ctx->publicationsFile = NULL;
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
	KSI_Policy_free(fallbackPolicy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

CuSuite* KSITest_Policy_getSuite(void) {
	CuSuite* suite = CuSuiteNew();
	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, TestInvalidParams);
	SUITE_ADD_TEST(suite, TestVerificationContext);
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
	SUITE_ADD_TEST(suite, TestUserProvidedPublicationBasedPolicy_OK_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestUserProvidedPublicationBasedPolicy_NA_WithSignatureAfterPublication);
	SUITE_ADD_TEST(suite, TestUserProvidedPublicationBasedPolicy_NA_WithSignatureBeforePublication);
	SUITE_ADD_TEST(suite, TestUserProvidedPublicationBasedPolicy_OK_WithoutPublicationRecord);
	SUITE_ADD_TEST(suite, TestUserProvidedPublicationBasedPolicy_FAIL_AfterExtending);
	/* TODO! Rewrite tests to test against cleanup of temporary verification context. */
#ifdef VERIFICATION_CONTEXT_CLEANUP
	SUITE_ADD_TEST(suite, TestFallbackPolicy_KeyBased_NA_CalendarBased_OK);
	SUITE_ADD_TEST(suite, TestFallbackPolicy_KeyBased_NA_CalendarBased_FAIL);
#endif
	SUITE_ADD_TEST(suite, TestFallbackPolicy_CalendarBased_OK_KeyBased_NA);
	SUITE_ADD_TEST(suite, TestFallbackPolicy_CalendarBased_FAIL_KeyBased_NA);
	return suite;
}
