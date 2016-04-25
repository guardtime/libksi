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
	const KSI_Rule *rule;
	int res;
	KSI_VerificationResultCode result;
	KSI_VerificationErrorCode error;
} TestRule;

static void TestInvalidParams(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_Policy *clone = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getCalendarBased(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getKeyBased(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getPublicationsFileBased(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getUserProvidedPublicationBased(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getInternal(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getGeneral(NULL, &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getCalendarBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getKeyBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getPublicationsFileBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getUserProvidedPublicationBased(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getInternal(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getGeneral(ctx, NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_getUserProvidedPublicationBased(ctx, &policy);
	CuAssert(tc, "Create policy failed", res == KSI_OK);

	res = KSI_Policy_clone(NULL, policy, &clone);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_clone(ctx, NULL, &clone);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_clone(ctx, policy, NULL);
	CuAssert(tc, "Clone policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_clone(ctx, policy, &clone);
	CuAssert(tc, "Policy cloning failed", res == KSI_OK);

	res = KSI_Policy_setFallback(NULL, clone, clone);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_setFallback(NULL, NULL, clone);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_setFallback(NULL, clone, NULL);
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

	res = KSI_VerificationContext_setExtendingAllowed(NULL, 1);
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
	KSI_VerificationContext_free(context);
	KSI_PolicyVerificationResult_free(result);
	KSI_Policy_free(clone);
}

static void TestVerificationContext(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_MOCK_IMPRINT   "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext *context = NULL;
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
			 context->userData.extendingAllowed == 0 &&
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

	res = KSI_VerificationContext_setExtendingAllowed(context, 1);
	CuAssert(tc, "Failed to set extending allowed flag", res == KSI_OK && context->userData.extendingAllowed == 1);

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
#define DUMMY_VERIFIER_NAME(name) #name
#define IMPLEMENT_DUMMY_VERIFIER(resValue, resultValue, errorValue) \
static int DUMMY_VERIFIER(resValue, resultValue, errorValue)(KSI_VerificationContext *context, KSI_RuleVerificationResult *result) {\
	result->resultCode = resultValue;\
	result->errorCode = errorValue;\
	result->ruleName = __FUNCTION__;\
	return resValue;\
}

IMPLEMENT_DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1);
IMPLEMENT_DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_2);
IMPLEMENT_DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_FAIL, KSI_VER_ERR_INT_1);
IMPLEMENT_DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_NA, KSI_VER_ERR_GEN_1);
IMPLEMENT_DUMMY_VERIFIER(KSI_INVALID_ARGUMENT, KSI_VER_RES_OK, KSI_VER_ERR_CAL_1);

static const KSI_Rule singleRules[5][2] = {
	{
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, NULL}
	},
	{
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_2)},
		{KSI_RULE_TYPE_BASIC, NULL}
	},
	{
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_FAIL, KSI_VER_ERR_INT_1)},
		{KSI_RULE_TYPE_BASIC, NULL}
	},
	{
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_NA, KSI_VER_ERR_GEN_1)},
		{KSI_RULE_TYPE_BASIC, NULL}
	},
	{
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_INVALID_ARGUMENT, KSI_VER_RES_OK, KSI_VER_ERR_CAL_1)},
		{KSI_RULE_TYPE_BASIC, NULL}
	}
};

static void TestPolicyCreation(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;

	res = KSI_Policy_create(NULL, singleRules[0], "PolicyName", &policy);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT && policy == NULL);

	res = KSI_Policy_create(ctx, NULL, "PolicyName", &policy);
	CuAssert(tc, "Rule NULL accepted", res == KSI_INVALID_ARGUMENT && policy == NULL);

	res = KSI_Policy_create(ctx, singleRules[0], NULL, &policy);
	CuAssert(tc, "Name NULL accepted", res == KSI_INVALID_ARGUMENT && policy == NULL);

	res = KSI_Policy_create(ctx, singleRules[0], "PolicyName", NULL);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT && policy == NULL);

	res = KSI_Policy_create(ctx, singleRules[0], "PolicyName", &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK && policy != NULL);

	KSI_Policy_free(policy);
}

static void TestSingleRulePolicy(CuTest* tc) {
	int res;
	int i;
	KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;

	TestRule rules[] = {
		{singleRules[0], KSI_OK,				KSI_VER_RES_OK,		KSI_VER_ERR_PUB_1},
		{singleRules[1], KSI_OK,				KSI_VER_RES_OK,		KSI_VER_ERR_PUB_2},
		{singleRules[2], KSI_OK,				KSI_VER_RES_FAIL,	KSI_VER_ERR_INT_1},
		{singleRules[3], KSI_OK,				KSI_VER_RES_NA,		KSI_VER_ERR_GEN_1},
		{singleRules[4], KSI_INVALID_ARGUMENT,	KSI_VER_RES_OK,		KSI_VER_ERR_CAL_1},
	};

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		res = KSI_Policy_create(ctx, rules[i].rule, "Single rules policy", &policy);
		CuAssert(tc, "Policy creation failed", res == KSI_OK);
		res = KSI_SignatureVerifier_verify(policy, context, &result);
		CuAssert(tc, "Policy verification failed", res == rules[i].res);
		CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == rules[i].result && result->finalResult.errorCode == rules[i].error);
		KSI_PolicyVerificationResult_free(result);
		KSI_Policy_free(policy);
	}

	KSI_VerificationContext_free(context);
}

static void TestBasicRulesPolicy(CuTest* tc) {
	int res;
	int i;
	KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;

	static const KSI_Rule basicRules1[] = {
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_2)},
		{KSI_RULE_TYPE_BASIC, NULL}
	};

	static const KSI_Rule basicRules2[] = {
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_FAIL, KSI_VER_ERR_INT_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_2)},
		{KSI_RULE_TYPE_BASIC, NULL}
	};

	static const KSI_Rule basicRules3[] = {
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_NA, KSI_VER_ERR_GEN_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_2)},
		{KSI_RULE_TYPE_BASIC, NULL}
	};

	static const KSI_Rule basicRules4[] = {
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_INVALID_ARGUMENT, KSI_VER_RES_OK, KSI_VER_ERR_CAL_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_2)},
		{KSI_RULE_TYPE_BASIC, NULL}
	};

	TestRule rules[] = {
		{basicRules1, KSI_OK,				KSI_VER_RES_OK,		KSI_VER_ERR_PUB_2},
		{basicRules2, KSI_OK,				KSI_VER_RES_FAIL,	KSI_VER_ERR_INT_1},
		{basicRules3, KSI_OK,				KSI_VER_RES_NA,		KSI_VER_ERR_GEN_1},
		{basicRules4, KSI_INVALID_ARGUMENT,	KSI_VER_RES_OK,		KSI_VER_ERR_CAL_1},
	};

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		res = KSI_Policy_create(ctx, rules[i].rule, "Basic rules policy", &policy);
		CuAssert(tc, "Policy creation failed", res == KSI_OK);
		res = KSI_SignatureVerifier_verify(policy, context, &result);
		CuAssert(tc, "Policy verification failed", res == rules[i].res);
		CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == rules[i].result && result->finalResult.errorCode == rules[i].error);
		KSI_PolicyVerificationResult_free(result);
		KSI_Policy_free(policy);
	}

	KSI_VerificationContext_free(context);
}

static void TestCompositeRulesPolicy(CuTest* tc) {
	int res;
	int i;
	KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;

	static const KSI_Rule compositeRule1[] = {
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[1]},
		{KSI_RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const KSI_Rule compositeRule2[] = {
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[1]},
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const KSI_Rule compositeRule3[] = {
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[1]},
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const KSI_Rule compositeRule4[] = {
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[1]},
		{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const KSI_Rule compositeRule5[] = {
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[2]},
		{KSI_RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const KSI_Rule compositeRule6[] = {
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[3]},
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const KSI_Rule compositeRule7[] = {
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[3]},
		{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const KSI_Rule compositeRule8[] = {
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[2]},
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const KSI_Rule compositeRule9[] = {
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[4]},
		{KSI_RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const KSI_Rule compositeRule10[] = {
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[4]},
		{KSI_RULE_TYPE_COMPOSITE_AND, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const KSI_Rule compositeRule11[] = {
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[4]},
		{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const KSI_Rule compositeRule12[] = {
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[4]},
		{KSI_RULE_TYPE_COMPOSITE_OR, singleRules[0]},
		{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
	};

	TestRule rules[] = {
		{compositeRule1,	KSI_OK,					KSI_VER_RES_OK,		KSI_VER_ERR_PUB_2},
		{compositeRule2,	KSI_OK,					KSI_VER_RES_OK,		KSI_VER_ERR_PUB_1},
		{compositeRule3,	KSI_OK,					KSI_VER_RES_OK,		KSI_VER_ERR_PUB_2},
		{compositeRule4,	KSI_OK,					KSI_VER_RES_OK,		KSI_VER_ERR_PUB_1},
		{compositeRule5,	KSI_OK,					KSI_VER_RES_FAIL,	KSI_VER_ERR_INT_1},
		{compositeRule6,	KSI_OK,					KSI_VER_RES_NA,		KSI_VER_ERR_GEN_1},
		{compositeRule7,	KSI_OK,					KSI_VER_RES_OK,		KSI_VER_ERR_PUB_1},
		{compositeRule8,	KSI_OK,					KSI_VER_RES_FAIL,	KSI_VER_ERR_INT_1},
		{compositeRule9,	KSI_INVALID_ARGUMENT,	KSI_VER_RES_OK,		KSI_VER_ERR_CAL_1},
		{compositeRule10,	KSI_INVALID_ARGUMENT,	KSI_VER_RES_OK,		KSI_VER_ERR_CAL_1},
		{compositeRule11,	KSI_OK,					KSI_VER_RES_OK,		KSI_VER_ERR_PUB_1},
		{compositeRule12,	KSI_INVALID_ARGUMENT,	KSI_VER_RES_OK,		KSI_VER_ERR_CAL_1}
	};

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		res = KSI_Policy_create(ctx, rules[i].rule, "Composite rules policy", &policy);
		CuAssert(tc, "Policy creation failed", res == KSI_OK);
		res = KSI_SignatureVerifier_verify(policy, context, &result);
		CuAssert(tc, "Policy verification failed", res == rules[i].res);
		CuAssert(tc, "Unexpected verification result", result->finalResult.resultCode == rules[i].result && result->finalResult.errorCode == rules[i].error);
		KSI_PolicyVerificationResult_free(result);
		KSI_Policy_free(policy);
	}

	KSI_VerificationContext_free(context);
}

bool ResultsMatch(KSI_RuleVerificationResult *expected, KSI_RuleVerificationResult *actual) {
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

bool SuccessfulProperty(KSI_RuleVerificationResult *result, size_t property) {
	size_t mask;
	mask = result->stepsPerformed & result->stepsSuccessful & ~result->stepsFailed;
	if ((mask & property) == property) {
		return true;
	} else {
		return false;
	}
}

bool FailedProperty(KSI_RuleVerificationResult *result, size_t property) {
	size_t mask;
	mask = result->stepsPerformed & result->stepsFailed & ~result->stepsSuccessful;
	if ((mask & property) == property) {
		return true;
	} else {
		return false;
	}
}

bool InconclusiveProperty(KSI_RuleVerificationResult *result, size_t property) {
	size_t mask;
	mask = result->stepsPerformed & ~result->stepsFailed & ~result->stepsSuccessful;
	if ((mask & property) == property) {
		return true;
	} else {
		return false;
	}
}

static void TestVerificationResult(CuTest* tc) {
	int res;
	size_t i;
	KSI_Policy policies[4];
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult *temp = NULL;
	KSI_RuleVerificationResult expected[4] = {
		{KSI_VER_RES_NA,	KSI_VER_ERR_GEN_1,	"DummyRule_Return_KSI_OK_KSI_VER_RES_NA_KSI_VER_ERR_GEN_1"},
		{KSI_VER_RES_FAIL,	KSI_VER_ERR_INT_1,	"DummyRule_Return_KSI_OK_KSI_VER_RES_FAIL_KSI_VER_ERR_INT_1"},
		{KSI_VER_RES_OK,	KSI_VER_ERR_PUB_2,	"DummyRule_Return_KSI_OK_KSI_VER_RES_OK_KSI_VER_ERR_PUB_2"},
		{KSI_VER_RES_OK,	KSI_VER_ERR_PUB_1,	"DummyRule_Return_KSI_OK_KSI_VER_RES_OK_KSI_VER_ERR_PUB_1"}
	};

	const char *names[4] = {
		"Single rules policy 3",
		"Single rules policy 2",
		"Single rules policy 1",
		"Single rules policy 0"
	};

	for (i = 0; i < 4; i++) {
		policies[i].rules = singleRules[3 - i];
		policies[i].fallbackPolicy = &policies[i + 1];
		policies[i].policyName = names[i];
	}
	policies[3].fallbackPolicy = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(&policies[0], context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected final verification result", ResultsMatch(&expected[2], &result->finalResult));
	CuAssert(tc, "Unexpected number of results", KSI_RuleVerificationResultList_length(result->policyResults) == 3);
	for (i = 0; i < KSI_RuleVerificationResultList_length(result->policyResults); i++) {
		res = KSI_RuleVerificationResultList_elementAt(result->policyResults, i, &temp);
		CuAssert(tc, "Could not retrieve result", res == KSI_OK);
		CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected[i], temp));
		CuAssert(tc, "Unexpected policy name", !strcmp(temp->policyName, names[i]));
	}

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
}

static void TestInternalPolicy_FAIL_WithInvalidRfc3161(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_1,
		"KSI_VerificationRule_AggregationChainInputHashVerification"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-rfc3161-output-hash.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidAggregationChain(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_1,
		"KSI_VerificationRule_AggregationHashChainConsistency"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/bad-aggregation-chain.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInconsistentAggregationChainTime(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_2,
		"KSI_VerificationRule_AggregationHashChainTimeConsistency"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-inconsistent-aggregation-chain-time.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_WithoutCalendarHashChain(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_DocumentHashDoesNotExist"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidCalendarHashChain(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_3,
		"KSI_VerificationRule_CalendarHashChainInputHashVerification"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-hash-chain.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidCalendarHashChainAggregationTime(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_4,
		"KSI_VerificationRule_CalendarHashChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-chain-aggregation-time.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_WithoutCalendarAuthenticationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_DocumentHashDoesNotExist"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidCalendarAuthenticationRecordHash(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_8,
		"KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-authentication-record-hash.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidCalendarAuthenticationRecordTime(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_6,
		"KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-authentication-record-publication-time.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_WithoutPublicationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_DocumentHashDoesNotExist"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidPublicationRecordHash(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_9,
		"KSI_VerificationRule_SignaturePublicationRecordPublicationHash"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-publication-record-publication-data-hash.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidPublicationRecordTime(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_7,
		"KSI_VerificationRule_SignaturePublicationRecordPublicationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-publication-record-publication-data-time.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_WithPublicationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_DocumentHashDoesNotExist"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_WithDocumentHash(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_DocumentHashVerification"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_Signature_getDocumentHash(context->userData.sig, &context->userData.documentHash);
	CuAssert(tc, "Unable to read signature document hash", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_DOCUMENT));

	KSI_PolicyVerificationResult_free(result);
	KSI_nofree(context->userData.documentHash);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithDocumentHash(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_GEN_1,
		"KSI_VerificationRule_DocumentHashVerification"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_MOCK_IMPRINT   "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getInternal(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &context->userData.documentHash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && context->userData.documentHash != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_DOCUMENT));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_MOCK_IMPRINT
}

static void TestCalendarBasedPolicy_NA_ExtenderErrors(CuTest* tc) {
	int res;
	size_t i;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainRightLinksMatch"
	};

	struct extErrResp_st {
		const char *name;
		int res;
	};
	struct extErrResp_st testArray[] = {
		{"resource/tlv/ok_extender_error_response_101.tlv", KSI_SERVICE_INVALID_REQUEST},
		{"resource/tlv/ok_extender_error_response_102.tlv", KSI_SERVICE_AUTHENTICATION_FAILURE},
		{"resource/tlv/ok_extender_error_response_103.tlv", KSI_SERVICE_INVALID_PAYLOAD},
		{"resource/tlv/ok_extender_error_response_104.tlv", KSI_SERVICE_EXTENDER_INVALID_TIME_RANGE},
		{"resource/tlv/ok_extender_error_response_105.tlv", KSI_SERVICE_EXTENDER_REQUEST_TIME_TOO_OLD},
		{"resource/tlv/ok_extender_error_response_106.tlv", KSI_SERVICE_EXTENDER_REQUEST_TIME_TOO_NEW},
		{"resource/tlv/ok_extender_error_response_107.tlv", KSI_SERVICE_EXTENDER_REQUEST_TIME_IN_FUTURE},
		{"resource/tlv/ok_extender_error_response_200.tlv", KSI_SERVICE_INTERNAL_ERROR},
		{"resource/tlv/ok_extender_error_response_201.tlv", KSI_SERVICE_EXTENDER_DATABASE_MISSING},
		{"resource/tlv/ok_extender_error_response_202.tlv", KSI_SERVICE_EXTENDER_DATABASE_CORRUPT},
		{"resource/tlv/ok_extender_error_response_300.tlv", KSI_SERVICE_UPSTREAM_ERROR},
		{"resource/tlv/ok_extender_error_response_301.tlv", KSI_SERVICE_UPSTREAM_TIMEOUT}
	};

#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-06-2.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getCalendarBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	for (i = 0; i < sizeof(testArray) / sizeof(testArray[0]); i++) {
		KSI_LOG_debug(ctx, "Extender error test no %d", i);
		res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(testArray[i].name), TEST_USER, TEST_PASS);
		CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

		res = KSI_SignatureVerifier_verify(policy, context, &result);
		CuAssert(tc, "Policy verification must not succeed.", res == testArray[i].res);
		CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
		CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
		CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

		KSI_PolicyVerificationResult_free(result);
	}

	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_OK_WithPublicationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getCalendarBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestCalendarBasedPolicy_FAIL_WithPublicationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_CAL_1,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash"
	};
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getCalendarBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_OK_WithoutPublicationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getCalendarBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_FAIL_WithoutPublicationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_CAL_4,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainRightLinksMatch"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getCalendarBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_OK_WithoutCalendarHashChain(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getCalendarBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_OK_WithAdditionalLeftLinks(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.2-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getCalendarBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_FAIL_WithoutCalendarHashChain(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_CAL_2,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getCalendarBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestKeyBasedPolicy_NA_WithoutCalendarHashChain(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_CalendarHashChainExistence"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestKeyBasedPolicy_NA_WithoutCalendarAuthenticationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_CalendarAuthenticationRecordExistence"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-calendar-authentication-record-missing.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestKeyBasedPolicy_FAIL_WithCalendarAuthenticationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_8,
		"KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-authentication-record-hash.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getKeyBased(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestKeyBasedPolicy_FAIL_WithoutCertificate(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_KEY_1,
		"KSI_VerificationRule_CertificateExistence"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications-one-cert-one-publication-record-with-wrong-hash.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getKeyBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestKeyBasedPolicy_FAIL_WithCertificate(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_KEY_2,
		"KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/signature-cal-auth-wrong-signing-value.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getKeyBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestKeyBasedPolicy_OK(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getKeyBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_OK_WithPublicationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_PublicationsFileContainsSignaturePublication"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getPublicationsFileBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_NA_WithPublicationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_SignatureDoesNotContainPublication"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getPublicationsFileBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_NA_WithoutSuitablePublication(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_PublicationsFileContainsPublication"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getPublicationsFileBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_NA_WithSuitablePublication(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_ExtendingPermittedVerification"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getPublicationsFileBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_OK_WithSuitablePublication(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getPublicationsFileBased(ctx, &policy);
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

	context->userData.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_FAIL_AfterExtending(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_PUB_1,
		"KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getPublicationsFileBased(ctx, &policy);
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

	context->userData.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestUserProvidedPublicationBasedPolicy_OK_WithPublicationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_UserProvidedPublicationVerification"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getUserProvidedPublicationBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestUserProvidedPublicationBasedPolicy_NA_WithSignatureAfterPublication(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Integer *mockTime = NULL;
	KSI_Signature *sig = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_TIMESTAMP      1396608816

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getUserProvidedPublicationBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_Signature_free(sig);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
#undef TEST_TIMESTAMP
}

static void TestUserProvidedPublicationBasedPolicy_NA_WithSignatureBeforePublication(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sig = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_ExtendingPermittedVerification"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getUserProvidedPublicationBased(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_Signature_free(sig);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
}

static void TestUserProvidedPublicationBasedPolicy_OK_WithoutPublicationRecord(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sig = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getUserProvidedPublicationBased(ctx, &policy);
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

	context->userData.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_Signature_free(sig);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
}

static void TestUserProvidedPublicationBasedPolicy_FAIL_AfterExtending(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sig = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_PUB_1,
		"KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getUserProvidedPublicationBased(ctx, &policy);
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

	context->userData.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_Signature_free(sig);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
}

static void TestGeneralPolicy_FAIL_WithInvalidAggregationChain(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_1,
		"KSI_VerificationRule_AggregationHashChainConsistency"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/bad-aggregation-chain.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getGeneral(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
}

static void TestGeneralPolicy_FAIL_WithCertificate(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_KEY_2,
		"KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/signature-cal-auth-wrong-signing-value.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getGeneral(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestGeneralPolicy_OK_WithCertificate(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification"
	};
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getGeneral(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestGeneralPolicy_FAIL_AfterExtendingToPublication(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_PUB_1,
		"KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getGeneral(ctx, &policy);
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

	context->userData.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestGeneralPolicy_OK_AfterExtendingToPublication(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getGeneral(ctx, &policy);
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

	context->userData.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestGeneralPolicy_FAIL_AfterExtendingToUserPublication(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sig = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_PUB_1,
		"KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getGeneral(ctx, &policy);
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

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getPublicationRecord(sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &context->userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context->userData.userPublication != NULL);

	context->userData.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_Signature_free(sig);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
#undef TEST_PUBLICATIONS_FILE
}

static void TestGeneralPolicy_OK_AfterExtendingToUserPublication(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sig = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash"
	};
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getGeneral(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &context->userData.userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && context->userData.userPublicationsFile != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getPublicationRecord(sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &context->userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context->userData.userPublication != NULL);

	context->userData.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	context->userData.userPublication = NULL;
	KSI_Signature_free(sig);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
#undef TEST_PUBLICATIONS_FILE
}

static void TestGeneralPolicy_FAIL_WithoutCalendarHashChain(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_CAL_2,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getGeneral(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestGeneralPolicy_OK_WithoutCalendarHashChain(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getGeneral(ctx, &policy);
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
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestGeneralPolicy_NA_ExtenderError(CuTest* tc) {
	int res;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash"
	};

#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok_extender_error_response_101.tlv"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getGeneral(ctx, &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_VerificationContext_create(ctx, &context);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &context->userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && context->userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	CuAssert(tc, "Policy verification must not succeed.", res == KSI_SERVICE_INVALID_REQUEST);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE | KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_free(context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestPolicyCloning(CuTest* tc) {
	int res;
	const KSI_Policy *org = NULL;
	KSI_Policy *policy = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getKeyBased(ctx, &org);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_clone(ctx, org, &policy);
	CuAssert(tc, "Policy cloning failed", res == KSI_OK && org != policy &&
			 policy->rules == org->rules &&
			 policy->fallbackPolicy == org->fallbackPolicy &&
			 !strcmp(policy->policyName, org->policyName));

	KSI_Policy_free(policy);
}

static void TestFallbackPolicy_CalendarBased_OK_KeyBased_NA(CuTest* tc) {
	int res;
	const KSI_Policy *org = NULL;
	KSI_Policy *policy = NULL;
	const KSI_Policy *fallbackPolicy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getCalendarBased(ctx, &org);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_clone(ctx, org, &policy);
	CuAssert(tc, "Policy cloning failed", res == KSI_OK);

	res = KSI_Policy_getKeyBased(ctx, &fallbackPolicy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_setFallback(ctx, policy, fallbackPolicy);
	CuAssert(tc, "Fallback policy setup failed", res == KSI_OK);

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
	context->ctx->publicationsFile = NULL;
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void TestFallbackPolicy_CalendarBased_FAIL_KeyBased_NA(CuTest* tc) {
	int res;
	const KSI_Policy *org = NULL;
	KSI_Policy *policy = NULL;
	const KSI_Policy *fallbackPolicy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_CalendarHashChainExistence"
	};
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_Policy_getCalendarBased(ctx, &org);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_clone(ctx, org, &policy);
	CuAssert(tc, "Policy cloning failed", res == KSI_OK);

	res = KSI_Policy_getKeyBased(ctx, &fallbackPolicy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_Policy_setFallback(ctx, policy, fallbackPolicy);
	CuAssert(tc, "Fallback policy setup failed", res == KSI_OK);

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
	context->ctx->publicationsFile = NULL;
	KSI_VerificationContext_free(context);
	KSI_Policy_free(policy);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}


CuSuite* KSITest_Policy_getSuite(void) {
	CuSuite* suite = CuSuiteNew();
	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, TestInvalidParams);
	SUITE_ADD_TEST(suite, TestVerificationContext);
	SUITE_ADD_TEST(suite, TestPolicyCreation);
	SUITE_ADD_TEST(suite, TestSingleRulePolicy);
	SUITE_ADD_TEST(suite, TestBasicRulesPolicy);
	SUITE_ADD_TEST(suite, TestCompositeRulesPolicy);
	SUITE_ADD_TEST(suite, TestVerificationResult);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidRfc3161);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidAggregationChain);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInconsistentAggregationChainTime);
	SUITE_ADD_TEST(suite, TestInternalPolicy_OK_WithoutCalendarHashChain);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidCalendarHashChain);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidCalendarHashChainAggregationTime);
	SUITE_ADD_TEST(suite, TestInternalPolicy_OK_WithoutCalendarAuthenticationRecord);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidCalendarAuthenticationRecordHash);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidCalendarAuthenticationRecordTime);
	SUITE_ADD_TEST(suite, TestInternalPolicy_OK_WithoutPublicationRecord);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidPublicationRecordHash);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidPublicationRecordTime);
	SUITE_ADD_TEST(suite, TestInternalPolicy_OK_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestInternalPolicy_OK_WithDocumentHash);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithDocumentHash);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_NA_ExtenderErrors);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_OK_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_FAIL_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_OK_WithoutPublicationRecord);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_FAIL_WithoutPublicationRecord);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_OK_WithoutCalendarHashChain);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_OK_WithAdditionalLeftLinks);
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
	SUITE_ADD_TEST(suite, TestGeneralPolicy_FAIL_WithInvalidAggregationChain);
	SUITE_ADD_TEST(suite, TestGeneralPolicy_FAIL_WithCertificate);
	SUITE_ADD_TEST(suite, TestGeneralPolicy_OK_WithCertificate);
	SUITE_ADD_TEST(suite, TestGeneralPolicy_FAIL_AfterExtendingToPublication);
	SUITE_ADD_TEST(suite, TestGeneralPolicy_OK_AfterExtendingToPublication);
	SUITE_ADD_TEST(suite, TestGeneralPolicy_FAIL_AfterExtendingToUserPublication);
	SUITE_ADD_TEST(suite, TestGeneralPolicy_OK_AfterExtendingToUserPublication);
	SUITE_ADD_TEST(suite, TestGeneralPolicy_FAIL_WithoutCalendarHashChain);
	SUITE_ADD_TEST(suite, TestGeneralPolicy_OK_WithoutCalendarHashChain);
	SUITE_ADD_TEST(suite, TestGeneralPolicy_NA_ExtenderError);
	SUITE_ADD_TEST(suite, TestPolicyCloning);
	SUITE_ADD_TEST(suite, TestFallbackPolicy_CalendarBased_OK_KeyBased_NA);
	SUITE_ADD_TEST(suite, TestFallbackPolicy_CalendarBased_FAIL_KeyBased_NA);

	return suite;
}
