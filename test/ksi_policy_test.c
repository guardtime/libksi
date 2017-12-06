/*
 * Copyright 2013-2017 Guardtime, Inc.
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

#include <string.h>
#include <ksi/hashchain.h>
#include <ksi/policy.h>

#include "cutest/CuTest.h"
#include "all_tests.h"

#include "../src/ksi/impl/ctx_impl.h"
#include "../src/ksi/impl/hash_impl.h"
#include "../src/ksi/impl/net_impl.h"
#include "../src/ksi/impl/policy_impl.h"
#include "../src/ksi/impl/publicationsfile_impl.h"
#include "../src/ksi/impl/signature_impl.h"
#include "../src/ksi/impl/verification_impl.h"

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
	KSI_Policy *clone = NULL;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Policy_clone(NULL, KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, &clone);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_clone(ctx, NULL, &clone);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_clone(ctx, KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, NULL);
	CuAssert(tc, "Clone policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_clone(ctx, KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, &clone);
	CuAssert(tc, "Policy cloning failed", res == KSI_OK);

	res = KSI_Policy_setFallback(NULL, clone, clone);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_setFallback(NULL, NULL, clone);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_Policy_setFallback(NULL, clone, NULL);
	CuAssert(tc, "Fallback policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_VerificationContext_init(&context, NULL);
	CuAssert(tc, "KSI context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(NULL, &context, &result);
	CuAssert(tc, "Policy NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, NULL, &result);
	CuAssert(tc, "Context NULL accepted", res == KSI_INVALID_ARGUMENT);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, &context, NULL);
	CuAssert(tc, "Result NULL accepted", res == KSI_INVALID_ARGUMENT);

	/* TODO: create signature for verification */
	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, &context, &result);
	CuAssert(tc, "Policy verification accepted empty context", res == KSI_INVALID_ARGUMENT);

	KSI_ERR_clearErrors(ctx);
	KSI_VerificationContext_clean(&context);
	KSI_PolicyVerificationResult_free(result);
	KSI_Policy_free(clone);
}

static void TestErrorStrings(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	/* Verify that the first, last and undefined error codes return expected error strings. */
	CuAssert(tc, "Unexpected verification error string.", strcmp(KSI_VerificationErrorCode_toString(KSI_VER_ERR_NONE), "") == 0);
	CuAssert(tc, "Unexpected verification error string.", strcmp(KSI_VerificationErrorCode_toString(KSI_VER_ERR_CAL_4), "CAL-04") == 0);
	CuAssert(tc, "Unexpected verification error string.", strcmp(KSI_VerificationErrorCode_toString(KSI_VER_ERR_INT_12), "INT-12") == 0);
	CuAssert(tc, "Unexpected verification error string.", strcmp(KSI_VerificationErrorCode_toString(__NOF_VER_ERRORS), "Unknown") == 0);
}

static void TestErrorDescription(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	/* Verify that the first, last and undefined error codes return expected error strings. */
	CuAssert(tc, "Unexpected verification error description.", strcmp(KSI_Policy_getErrorString(KSI_VER_ERR_NONE), "No verification errors") == 0);
	CuAssert(tc, "Unexpected verification error description.", strcmp(KSI_Policy_getErrorString(KSI_VER_ERR_CAL_4), "Calendar hash chain right links are inconsistent") == 0);
	CuAssert(tc, "Unexpected verification error description.", strcmp(KSI_Policy_getErrorString(__NOF_VER_ERRORS), "Unknown verification error code") == 0);
}

static void TestVerificationContext(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_MOCK_IMPRINT   "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_Signature *sig = NULL;
	KSI_DataHash *hash = NULL;
	KSI_DataHash *aggrHash = NULL;
	KSI_PublicationData *userPublication = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;
	KSI_PublicationsFile *publicationsFile = NULL;
	static const char publicationString[] = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";
	VerificationTempData tempData;

	memset(&tempData, 0, sizeof(tempData));

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Create verification context failed", res == KSI_OK  && context.ctx == ctx);
	CuAssert(tc, "Non-empty verification context created",
			 context.signature == NULL &&
			 context.documentHash == NULL &&
			 context.userPublication == NULL &&
			 context.userPublicationsFile == NULL &&
			 context.extendingAllowed == 0 &&
			 context.docAggrLevel == 0 &&
			 context.tempData == NULL);

	context.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

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

	context.signature = sig;
	context.documentHash = hash;
	context.userPublication = userPublication;
	context.userPublicationsFile = userPublicationsFile;
	context.extendingAllowed = 1;
	context.docAggrLevel = 10;

	tempData.calendarChain = NULL;
	tempData.aggregationOutputHash = aggrHash;
	tempData.publicationsFile = publicationsFile;

	KSI_VerificationContext_clean(&context);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(sig);
	KSI_DataHash_free(hash);
	KSI_PublicationData_free(userPublication);

	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_MOCK_IMPRINT
#undef TEST_PUBLICATIONS_FILE
}

#define DUMMY_VERIFIER(resValue, resultValue, errorValue) DummyRule_Return_##resValue##_##resultValue##_##errorValue
#define DUMMY_VERIFIER_STR(resValue, resultValue, errorValue) "DummyRule_Return_" #resValue "_" #resultValue "_" #errorValue
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
	KSI_VerificationContext context;
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
	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		res = KSI_Policy_create(ctx, rules[i].rule, "Single rules policy", &policy);
		CuAssert(tc, "Policy creation failed", res == KSI_OK);
		res = KSI_SignatureVerifier_verify(policy, &context, &result);
		CuAssert(tc, "Policy verification failed", res == rules[i].res);
		CuAssert(tc, "Unexpected verification result", res != KSI_OK || (result->finalResult.resultCode == rules[i].result && result->finalResult.errorCode == rules[i].error));
		KSI_PolicyVerificationResult_free(result);
		result = NULL;
		KSI_Policy_free(policy);
	}

	KSI_VerificationContext_clean(&context);
}

static void TestBasicRulesPolicy(CuTest* tc) {
	int res;
	int i;
	KSI_Policy *policy = NULL;
	KSI_VerificationContext context;
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
	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		res = KSI_Policy_create(ctx, rules[i].rule, "Basic rules policy", &policy);
		CuAssert(tc, "Policy creation failed", res == KSI_OK);
		res = KSI_SignatureVerifier_verify(policy, &context, &result);
		CuAssert(tc, "Policy verification failed", res == rules[i].res);
		CuAssert(tc, "Unexpected verification result", res != KSI_OK || (result->finalResult.resultCode == rules[i].result && result->finalResult.errorCode == rules[i].error));
		KSI_PolicyVerificationResult_free(result);
		result = NULL;
		KSI_Policy_free(policy);
	}

	KSI_VerificationContext_clean(&context);
}

static void TestCompositeRulesPolicy(CuTest* tc) {
	int res;
	int i;
	KSI_Policy *policy = NULL;
	KSI_VerificationContext context;
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
	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	for (i = 0; i < sizeof(rules) / sizeof(TestRule); i++) {
		KSI_ERR_clearErrors(ctx);
		res = KSI_Policy_create(ctx, rules[i].rule, "Composite rules policy", &policy);
		CuAssert(tc, "Policy creation failed", res == KSI_OK);
		res = KSI_SignatureVerifier_verify(policy, &context, &result);
		CuAssert(tc, "Policy verification failed", res == rules[i].res);
		CuAssert(tc, "Unexpected verification result", res != KSI_OK || (result->finalResult.resultCode == rules[i].result && result->finalResult.errorCode == rules[i].error));
		KSI_PolicyVerificationResult_free(result);
		result = NULL;
		KSI_Policy_free(policy);
	}

	KSI_VerificationContext_clean(&context);
}

static bool ResultsMatch(const KSI_RuleVerificationResult *expected, const KSI_RuleVerificationResult *actual) {
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

static bool SuccessfulProperty(KSI_RuleVerificationResult *result, size_t property) {
	size_t mask;
	mask = result->stepsPerformed & result->stepsSuccessful & ~result->stepsFailed;
	return (mask & property) == property;
}

static bool FailedProperty(KSI_RuleVerificationResult *result, size_t property) {
	size_t mask;
	mask = result->stepsPerformed & result->stepsFailed & ~result->stepsSuccessful;
	return (mask & property) == property;
}

static bool InconclusiveProperty(KSI_RuleVerificationResult *result, size_t property) {
	size_t mask;
	mask = result->stepsPerformed & ~result->stepsFailed & ~result->stepsSuccessful;
	return (mask & property) == property;
}

static void TestVerificationResult(CuTest* tc) {
	int res;
	size_t i;
	KSI_Policy policies[4];
	KSI_VerificationContext context;
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
	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(&policies[0], &context, &result);
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
	KSI_VerificationContext_clean(&context);
}

static void TestDuplicateResults(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	size_t i;

	static const KSI_Rule okNaRule1[] = {
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_NA, KSI_VER_ERR_GEN_1)},
		{KSI_RULE_TYPE_BASIC, NULL}
	};

	static const KSI_Rule okNaRule2[] = {
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_NA, KSI_VER_ERR_GEN_1)},
		{KSI_RULE_TYPE_BASIC, NULL}
	};

	static const KSI_Rule okNaRule3[] = {
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_2)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_NA, KSI_VER_ERR_GEN_1)},
		{KSI_RULE_TYPE_BASIC, NULL}
	};

	static const KSI_Rule rules[] = {
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_2)},
		{KSI_RULE_TYPE_COMPOSITE_OR, okNaRule1},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_2)},
		{KSI_RULE_TYPE_COMPOSITE_OR, okNaRule2},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_2)},
		{KSI_RULE_TYPE_COMPOSITE_OR, okNaRule3},
		{KSI_RULE_TYPE_BASIC, DUMMY_VERIFIER(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_RULE_TYPE_BASIC, NULL}
	};

	static const KSI_RuleVerificationResult expected[] = {
		{KSI_VER_RES_OK, KSI_VER_ERR_PUB_1, DUMMY_VERIFIER_STR(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_1)},
		{KSI_VER_RES_OK, KSI_VER_ERR_PUB_2, DUMMY_VERIFIER_STR(KSI_OK, KSI_VER_RES_OK, KSI_VER_ERR_PUB_2)},
		{KSI_VER_RES_NA, KSI_VER_ERR_GEN_1, DUMMY_VERIFIER_STR(KSI_OK, KSI_VER_RES_NA, KSI_VER_ERR_GEN_1)}
	};

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Create verification context failed", res == KSI_OK);

	res = KSI_Policy_create(ctx, rules, "Duplicate rules policy", &policy);
	CuAssert(tc, "Policy creation failed", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(policy, &context, &result);
	CuAssert(tc, "Policy verification failed.", res == KSI_OK);
	CuAssert(tc, "Too many results in result list.", KSI_RuleVerificationResultList_length(result->ruleResults) == 3);
	CuAssert(tc, "Unexpected final result.", result->finalResult.errorCode == KSI_VER_ERR_PUB_1);

	for (i = 0; i < KSI_RuleVerificationResultList_length(result->ruleResults); i++) {
		KSI_RuleVerificationResult *tmpRes = NULL;

		res = KSI_RuleVerificationResultList_elementAt(result->ruleResults, i, &tmpRes);
		CuAssert(tc, "Could not retrieve result", res == KSI_OK);
		CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected[i], tmpRes));
	}

	KSI_PolicyVerificationResult_free(result);
	KSI_VerificationContext_clean(&context);
	KSI_Policy_free(policy);
}

static void TestInternalPolicy_FAIL_WithInvalidRfc3161(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-rfc3161-output-hash.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_1,
		"KSI_VerificationRule_AggregationChainInputHashVerification"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidRfc3161AggrTime(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok-changed-aggregation-time.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_2,
		"KSI_VerificationRule_AggregationHashChainTimeConsistency"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidRfc3161ChainIndex(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok-changed-chain-index.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_12,
		"KSI_VerificationRule_AggregationHashChainIndexContinuation"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidAggrChainIndex(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-2014-08-01.1.same-chain-index.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_12,
		"KSI_VerificationRule_AggregationHashChainIndexContinuation"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_MetaDataWithPadding(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-metadata-with-padding.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarHashChainDoesNotExist"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_MetaDataWithoutPadding(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-metadata-without-padding.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarHashChainDoesNotExist"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidMetaDataPadding(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-metadata-padding-flags-not-set.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_11,
		"KSI_VerificationRule_AggregationChainMetaDataVerification"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithoutMetaDataPadding(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-metadata-padding-missing.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_11,
		"KSI_VerificationRule_AggregationChainMetaDataVerification"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidAggregationChain(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/bad-aggregation-chain.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_1,
		"KSI_VerificationRule_AggregationHashChainConsistency"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInconsistentAggregationChainTime(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-inconsistent-aggregation-chain-time.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_2,
		"KSI_VerificationRule_AggregationHashChainTimeConsistency"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);
	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_WithoutCalendarHashChain(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarHashChainDoesNotExist"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidCalendarHashChain(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-hash-chain.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_3,
		"KSI_VerificationRule_CalendarHashChainInputHashVerification"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidCalendarHashChainAggregationTime(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-chain-aggregation-time.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_4,
		"KSI_VerificationRule_CalendarHashChainAggregationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_WithoutCalendarAuthenticationRecord(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarAuthenticationRecordDoesNotExist"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidCalendarAuthenticationRecordHash(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-authentication-record-hash.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_8,
		"KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidCalendarAuthenticationRecordTime(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-authentication-record-publication-time.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_6,
		"KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_WithoutPublicationRecord(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidPublicationRecordHash(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-publication-record-publication-data-hash.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_9,
		"KSI_VerificationRule_SignaturePublicationRecordPublicationHash"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithInvalidPublicationRecordTime(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-publication-record-publication-data-time.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_7,
		"KSI_VerificationRule_SignaturePublicationRecordPublicationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_WithPublicationRecord(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_SignaturePublicationRecordPublicationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_OK_WithDocumentHash(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_SignaturePublicationRecordPublicationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_Signature_getDocumentHash(context.signature, (KSI_DataHash**)&context.documentHash);
	CuAssert(tc, "Unable to read signature document hash", res == KSI_OK && context.documentHash != NULL);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_DOCUMENT));

	KSI_PolicyVerificationResult_free(result);
	KSI_nofree(context.documentHash);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_WithDocumentHash(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_MOCK_IMPRINT   "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_GEN_1,
		"KSI_VerificationRule_DocumentHashVerification"
	};
	KSI_Signature *signature = NULL;
	KSI_DataHash *documentHash = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &documentHash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && documentHash != NULL);
	context.documentHash = documentHash;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_NONE));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_DOCUMENT));

	KSI_DataHash_free(documentHash);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_MOCK_IMPRINT
}

static void TestInternalPolicy_OK_WithInputLevel(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2017-04-21.1-input-hash-level-5.ksig"
#define TEST_AGGR_LEVEL 5

	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	context.docAggrLevel = TEST_AGGR_LEVEL;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed.", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result.", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property.", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property.", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_AGGR_LEVEL
}

static void TestInternalPolicy_FAIL_WithInputLevelTooLarge(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2017-04-21.1-input-hash-level-5.ksig"
#define TEST_AGGR_LEVEL 5

	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_GEN_3,
		"KSI_VerificationRule_AggregationChainInputLevelVerification"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	context.docAggrLevel = TEST_AGGR_LEVEL + 1;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification must not succeed.", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result.", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property.", SuccessfulProperty(&result->finalResult, KSI_VERIFY_NONE));
	CuAssert(tc, "Unexpected verification property.", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_AGGR_LEVEL
}

static void TestInternalPolicy_FAIL_SignatureAggreChainSameIndex(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-aggr-chain-multiple-chains-changed-order-chain-index-are-same.1.tlv"

	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_12,
		"KSI_VerificationRule_AggregationHashChainIndexContinuation"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestInternalPolicy_FAIL_SignatureAggreChainSameIndexChangedChainOrder(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-aggr-chain-multiple-chains-changed-order-chain-index-are-same.2.tlv"

	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_12,
		"KSI_VerificationRule_AggregationHashChainIndexContinuation"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_INTERNAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_NA_ExtenderErrors(CuTest* tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-06-2.ksig"
	int res;
	size_t i;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainRightLinksMatch"
	};
	KSI_Signature *signature = NULL;

	struct extErrResp_st {
		const char *name;
		int res;
	};
	struct extErrResp_st testArray[] = {
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_101.tlv", KSI_SERVICE_INVALID_REQUEST},
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_102.tlv", KSI_SERVICE_AUTHENTICATION_FAILURE},
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_103.tlv", KSI_SERVICE_INVALID_PAYLOAD},
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_104.tlv", KSI_SERVICE_EXTENDER_INVALID_TIME_RANGE},
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_105.tlv", KSI_SERVICE_EXTENDER_REQUEST_TIME_TOO_OLD},
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_106.tlv", KSI_SERVICE_EXTENDER_REQUEST_TIME_TOO_NEW},
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_107.tlv", KSI_SERVICE_EXTENDER_REQUEST_TIME_IN_FUTURE},
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_200.tlv", KSI_SERVICE_INTERNAL_ERROR},
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_201.tlv", KSI_SERVICE_EXTENDER_DATABASE_MISSING},
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_202.tlv", KSI_SERVICE_EXTENDER_DATABASE_CORRUPT},
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_300.tlv", KSI_SERVICE_UPSTREAM_ERROR},
		{"resource/tlv/" TEST_RESOURCE_EXT_VER "/ok_extender_error_response_301.tlv", KSI_SERVICE_UPSTREAM_TIMEOUT}
	};

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	for (i = 0; i < sizeof(testArray) / sizeof(testArray[0]); i++) {
		KSI_LOG_debug(ctx, "Extender error test no %llu", (unsigned long long)i);
		res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(testArray[i].name), TEST_USER, TEST_PASS);
		CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

		res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_CALENDAR_BASED, &context, &result);
		CuAssert(tc, "Policy verification must not succeed.", res == testArray[i].res);
		if (res == KSI_OK) {
			CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
			CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
					KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
			CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));
		}
		KSI_PolicyVerificationResult_free(result);
	}

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestCalendarBasedPolicy_OK_WithPublicationRecord(CuTest* tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_CALENDAR_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestCalendarBasedPolicy_FAIL_WithPublicationRecord(CuTest* tc) {
	#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
	#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-nok-extend_response-1.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_CAL_1,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), "anon", "anon");
	CuAssert(tc, "Unable to set extender response.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_CALENDAR_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestCalendarBasedPolicy_OK_WithoutPublicationRecord(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), "anon", "anon");
	CuAssert(tc, "Unable to set extender response.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_CALENDAR_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
			KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestCalendarBasedPolicy_OK_WithoutCalendarHashChain(CuTest* tc) {
	#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
	#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), "anon", "anon");
	CuAssert(tc, "Unable to set extender response.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_CALENDAR_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestCalendarBasedPolicy_FAIL_WithoutCalendarHashChain(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-nok-extend_response-3.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_CAL_2,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), "anon", "anon");
	CuAssert(tc, "Unable to set extender response.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_CALENDAR_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestCalendarBasedPolicy_OK_WithAlgoChange(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/cal_algo_switch.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/cal_algo_switch-extend_resposne.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), "anon", "anon");
	CuAssert(tc, "Unable to set extender response.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_CALENDAR_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_ONLINE));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestKeyBasedPolicy_NA_WithoutCalendarHashChain(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_CalendarHashChainPresenceVerification"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_KEY_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestKeyBasedPolicy_NA_WithoutCalendarAuthenticationRecord(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-calendar-authentication-record-missing.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarAuthenticationRecordExistence"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_KEY_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestKeyBasedPolicy_FAIL_WithCalendarAuthenticationRecord(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-authentication-record-hash.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_8,
		"KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && context.signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_KEY_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestKeyBasedPolicy_FAIL_WithoutCertificate(CuTest* tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications-one-cert-one-publication-record-with-wrong-hash.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_KEY_1,
		"KSI_VerificationRule_CertificateExistence"
	};
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_KEY_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestKeyBasedPolicy_FAIL_WithCertificate(CuTest* tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/signature-cal-auth-wrong-signing-value.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_KEY_2,
		"KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_ERR_clearErrors(ctx);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_KEY_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestKeyBasedPolicy_FAIL_CertificateValidity(CuTest* tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/nok-sig-2017-08-23.1.invalid-cert-timespan.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/ksi-publications.invalid-cert.validity.bin"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_KEY_3,
		"KSI_VerificationRule_CertificateValidity"
	};
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_KEY_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestKeyBasedPolicy_OK(CuTest* tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_KEY_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_OK_WithPublicationRecord(CuTest* tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_PublicationsFileSignatureCalendarChainHashAlgorithmDeprecatedAtPubTime"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFileWithPolicy(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), KSI_VERIFICATION_POLICY_EMPTY, NULL, &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_PUBLICATIONS_FILE_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_NA_DeprecatedAlgInCalendar(CuTest* tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/signature-deprecated-algorithm-in-calendar-chain-for-publications-file.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications-file-for-deprecated-algorithm-in-calendar-chain.bin"

	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expectedFinal = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_SignaturePublicationRecordMissing"
	};
	KSI_RuleVerificationResult expectedFail = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_PublicationsFileSignatureCalendarChainHashAlgorithmDeprecatedAtPubTime"
	};
	KSI_RuleVerificationResult *lastFailed = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFileWithPolicy(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), KSI_VERIFICATION_POLICY_EMPTY, NULL, &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_PUBLICATIONS_FILE_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expectedFinal, &result->finalResult));

	res = KSI_RuleVerificationResultList_elementAt(result->ruleResults, KSI_RuleVerificationResultList_length(result->ruleResults) - 1, &lastFailed);
	CuAssert(tc, "Failed to get last rule result.", res == KSI_OK && lastFailed != NULL);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expectedFail, lastFailed));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(lastFailed,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(lastFailed, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_NA_WithPublicationRecord(CuTest* tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expectedFinal = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_SignaturePublicationRecordMissing"
	};
	KSI_RuleVerificationResult expectedFail = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_PublicationsFileContainsSuitablePublication"
	};
	KSI_RuleVerificationResult *lastFailed = NULL;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFileWithPolicy(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), KSI_VERIFICATION_POLICY_EMPTY, NULL, &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_PUBLICATIONS_FILE_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expectedFinal, &result->finalResult));

	res = KSI_RuleVerificationResultList_elementAt(result->ruleResults, KSI_RuleVerificationResultList_length(result->ruleResults) - 1, &lastFailed);
	CuAssert(tc, "Failed to get last rule result.", res == KSI_OK && lastFailed != NULL);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expectedFail, lastFailed));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(lastFailed,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(lastFailed, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_NA_WithoutSuitablePublication(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_PublicationsFileContainsSuitablePublication"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFileWithPolicy(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), KSI_VERIFICATION_POLICY_EMPTY, NULL, &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_PUBLICATIONS_FILE_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_NA_WithSuitablePublication(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_PublicationsFileExtendingPermittedVerification"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFileWithPolicy(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), KSI_VERIFICATION_POLICY_EMPTY, NULL, &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_PUBLICATIONS_FILE_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_OK_WithSuitablePublication(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	context.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_PUBLICATIONS_FILE_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestPublicationsFileBasedPolicy_FAIL_AfterExtending(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-nok-extend_response-1.tlv"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_PUB_1,
		"KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	context.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_PUBLICATIONS_FILE_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestUserProvidedPublicationBasedPolicy_OK_WithPublicationRecord(CuTest* tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_UserProvidedPublicationSignatureCalendarChainHashAlgorithmDeprecatedAtPubTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed.", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_Signature_getPublicationRecord(context.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record.", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData**)&context.userPublication);
	CuAssert(tc, "Unable to read signature publication data.", res == KSI_OK && context.userPublication != NULL);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed.", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result.", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property.", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property.", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	KSI_nofree(context.userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestUserProvidedPublicationBasedPolicy_NA_DeprecatedAlgInCalendar(CuTest* tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/signature-deprecated-algorithm-in-calendar-chain.ksig"
#define TEST_USER_PUB_STRING "AAAAAA-CXOXMZ-AANVAP-PA2NRR-Z2R4MI-RT6GA3-7IC5H5-PFKUDQ-Q2QWOR-GZKWBF-BXF5VU-UTE3BL"

	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expectedFinal = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_SignaturePublicationRecordMissing"
	};
	KSI_RuleVerificationResult expectedFail = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_UserProvidedPublicationSignatureCalendarChainHashAlgorithmDeprecatedAtPubTime"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationData *userPublication = NULL;
	KSI_RuleVerificationResult *lastFailed = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFileWithPolicy(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), KSI_VERIFICATION_POLICY_EMPTY, NULL, &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationData_fromBase32(ctx, TEST_USER_PUB_STRING, &userPublication);
	CuAssert(tc, "Unable to get publication from base 32.", res == KSI_OK && userPublication != NULL);
	context.userPublication = userPublication;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expectedFinal, &result->finalResult));

	res = KSI_RuleVerificationResultList_elementAt(result->ruleResults, KSI_RuleVerificationResultList_length(result->ruleResults) - 1, &lastFailed);
	CuAssert(tc, "Failed to get last rule result.", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expectedFail, lastFailed));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(lastFailed,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_PUBLICATION));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(lastFailed, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));


	KSI_PublicationData_free(userPublication);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_USER_PUB_STRING
}

static void TestUserProvidedPublicationBasedPolicy_NA_WithSignatureAfterPublication(CuTest* tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_TIMESTAMP      1396608816
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Integer *mockTime = NULL;
	KSI_Signature *sigWithPub = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification"
	};
	KSI_Signature *signature = NULL;
	KSI_PublicationData *userPublication = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sigWithPub);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sigWithPub != NULL);

	res = KSI_Signature_getPublicationRecord(sigWithPub, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && userPublication != NULL);
	context.userPublication = userPublication;

	res = KSI_Integer_new(ctx, TEST_TIMESTAMP, &mockTime);
	CuAssert(tc, "Unable to create publication time", res == KSI_OK && mockTime != NULL);

	KSI_Integer_free(userPublication->time);
	res = KSI_PublicationData_setTime(userPublication, mockTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	KSI_nofree(context.userPublication);
	KSI_Signature_free(sigWithPub);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
#undef TEST_TIMESTAMP
}

static void TestUserProvidedPublicationBasedPolicy_NA_WithSignatureBeforePublication(CuTest* tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sigWithPub = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_UserProvidedPublicationExtendingPermittedVerification"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sigWithPub);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sigWithPub != NULL);

	res = KSI_Signature_getPublicationRecord(sigWithPub, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData**)&context.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context.userPublication != NULL);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", InconclusiveProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	KSI_nofree(context.userPublication);
	KSI_Signature_free(sigWithPub);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
}

static void TestUserProvidedPublicationBasedPolicy_OK_WithoutPublicationRecord(CuTest* tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sigWithPub = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sigWithPub);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sigWithPub != NULL);

	res = KSI_Signature_getPublicationRecord(sigWithPub, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData**)&context.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context.userPublication != NULL);

	context.extendingAllowed = 1;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	KSI_nofree(context.userPublication);
	KSI_Signature_free(sigWithPub);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
#undef TEST_EXT_RESPONSE_FILE

}

static void TestUserProvidedPublicationBasedPolicy_FAIL_AfterExtending(CuTest* tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-nok-extend_response-1.tlv"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sigWithPub = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_PUB_1,
		"KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sigWithPub);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sigWithPub != NULL);

	res = KSI_Signature_getPublicationRecord(sigWithPub, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData**)&context.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context.userPublication != NULL);

	context.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(sigWithPub);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
}

static void TestGeneralPolicy_FAIL_WithInvalidAggregationChain(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/bad-aggregation-chain.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_INT_1,
		"KSI_VerificationRule_AggregationHashChainConsistency"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

static void TestGeneralPolicy_FAIL_WithCertificate(CuTest* tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/signature-cal-auth-wrong-signing-value.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_KEY_2,
		"KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);
#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestGeneralPolicy_OK_WithCertificate(CuTest* tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY | KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestGeneralPolicy_FAIL_AfterExtendingToPublication(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-nok-extend_response-1.tlv"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_PUB_1,
		"KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	context.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestGeneralPolicy_OK_AfterExtendingToPublication(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	context.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBFILE));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_CTX_free(ctx);
#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void TestGeneralPolicy_FAIL_AfterExtendingToUserPublication(CuTest* tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-nok-extend_response-1.tlv"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sigWithPub = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_PUB_1,
		"KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sigWithPub);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sigWithPub != NULL);

	res = KSI_Signature_getPublicationRecord(sigWithPub, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData**)&context.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context.userPublication != NULL);

	context.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_nofree(context.userPublication);
	KSI_Signature_free(sigWithPub);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
#undef TEST_PUBLICATIONS_FILE
}

static void TestGeneralPolicy_OK_AfterExtendingToUserPublication(CuTest* tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *sigWithPub = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash"
	};
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	context.userPublicationsFile = userPublicationsFile;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sigWithPub);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sigWithPub != NULL);

	res = KSI_Signature_getPublicationRecord(sigWithPub, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData**)&context.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context.userPublication != NULL);

	context.extendingAllowed = 1;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_PolicyVerificationResult_free(result);
	KSI_nofree(context.userPublication);
	KSI_Signature_free(sigWithPub);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
#undef TEST_PUBLICATIONS_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestGeneralPolicy_FAIL_WithoutCalendarHashChain(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-nok-extend_response-3.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_CalendarHashChainPresenceVerification"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFileWithPolicy(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), KSI_VERIFICATION_POLICY_EMPTY, NULL, &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestGeneralPolicy_OK_WithoutCalendarHashChain(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_CalendarHashChainPresenceVerification"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFileWithPolicy(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), KSI_VERIFICATION_POLICY_EMPTY, NULL, &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&result->finalResult, KSI_VERIFY_AGGRCHAIN_INTERNALLY));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestPolicyCloning(CuTest* tc) {
	int res;
	KSI_Policy *policy = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_Policy_clone(ctx, KSI_VERIFICATION_POLICY_KEY_BASED, &policy);
	CuAssert(tc, "Policy cloning failed", res == KSI_OK && KSI_VERIFICATION_POLICY_KEY_BASED != policy &&
			 policy->rules == KSI_VERIFICATION_POLICY_KEY_BASED->rules &&
			 policy->fallbackPolicy == KSI_VERIFICATION_POLICY_KEY_BASED->fallbackPolicy &&
			 !strcmp(policy->policyName, KSI_VERIFICATION_POLICY_KEY_BASED->policyName));

	KSI_Policy_free(policy);
}

static void TestFallbackPolicy_CalendarBased_OK_KeyBased_NA(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
	int res;
	KSI_Policy *policy = NULL;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_OK,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_Policy_clone(ctx, KSI_VERIFICATION_POLICY_CALENDAR_BASED, &policy);
	CuAssert(tc, "Policy cloning failed", res == KSI_OK);

	res = KSI_Policy_setFallback(ctx, policy, KSI_VERIFICATION_POLICY_KEY_BASED);
	CuAssert(tc, "Fallback policy setup failed", res == KSI_OK);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(policy, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_Policy_free(policy);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestFallbackPolicy_CalendarBased_FAIL_KeyBased_NA(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response-input_hash_null.tlv"
	int res;
	KSI_Policy *policy = NULL;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_GEN_2,
		"KSI_VerificationRule_CalendarHashChainPresenceVerification"
	};
	KSI_Signature *signature = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_Policy_clone(ctx, KSI_VERIFICATION_POLICY_CALENDAR_BASED, &policy);
	CuAssert(tc, "Policy cloning failed", res == KSI_OK);

	res = KSI_Policy_setFallback(ctx, policy, KSI_VERIFICATION_POLICY_KEY_BASED);
	CuAssert(tc, "Fallback policy setup failed", res == KSI_OK);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_SignatureVerifier_verify(policy, &context, &result);
	CuAssert(tc, "Policy verification failed", res == KSI_OK);
	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &result->finalResult));

	KSI_PolicyVerificationResult_free(result);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
	KSI_Policy_free(policy);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void TestUserPublicationWithBadCalAuthRec(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-2015-09-13_21-34-00.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/nok-sig-2015-09-13_21-34-00-extend_responce.tlv"
	int res;
	KSI_Signature *sig = NULL;
	KSI_VerificationContext ver;
	KSI_PublicationData *pub = NULL;
	KSI_PolicyVerificationResult *result = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&ver, ctx);
	CuAssert(tc, "Unable to initialise verification context.", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature file.", res == KSI_OK && sig != NULL);

	res = KSI_PublicationData_fromBase32(ctx, "AAAAAA-CWEA7A-AANGA4-GYCQU4-LMHD4Z-H2SAWX-ZKIL6A-3UKFW5-FSX34D-6GZQJ5-TDA33K-T3FMOK", &pub);
	CuAssert(tc, "Unable to get publication from base 32.", res == KSI_OK && pub != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	ver.signature = sig;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &ver, &result);
	CuAssert(tc, "Unable to verify signature.", res == KSI_OK && result != NULL);
	CuAssert(tc, "Signature must fail with default configuration", result->resultCode == KSI_VER_RES_FAIL);

	KSI_PolicyVerificationResult_free(result);
	result = NULL;

	ver.userPublication = pub;
	ver.extendingAllowed = 1;

	res = KSI_SignatureVerifier_verify(KSI_VERIFICATION_POLICY_GENERAL, &ver, &result);
	CuAssert(tc, "Unable to verify signature.", res == KSI_OK && result != NULL);
	CuAssert(tc, "Signature must verify with user publication", result->resultCode == KSI_VER_RES_OK);

	KSI_PublicationData_free(pub);
	KSI_Signature_free(sig);
	KSI_PolicyVerificationResult_free(result);
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_SIGNATURE_FILE
}

static void TestBackgroundVerificationWithUserPublicationBasedPolicy(CuTest* tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-nok-extend_response-1.tlv"
#define TEST_SIGNATURE_FILE_WITH_PUBLICATION  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_Signature *signature = NULL;
	KSI_Signature *sigWithPub = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_FAIL,
		KSI_VER_ERR_PUB_1,
		"KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse"
	};

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE_WITH_PUBLICATION), &sigWithPub);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sigWithPub != NULL);

	res = KSI_Signature_getPublicationRecord(sigWithPub, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData**)&context.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && context.userPublication != NULL);

	context.extendingAllowed = 1;

	res = KSI_Signature_fromFileWithPolicy(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED, &context, &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);

	CuAssert(tc, "Unexpected verification result", ResultsMatch(&expected, &signature->policyVerificationResult->finalResult));
	CuAssert(tc, "Unexpected verification property", SuccessfulProperty(&signature->policyVerificationResult->finalResult,
				KSI_VERIFY_AGGRCHAIN_INTERNALLY | KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN | KSI_VERIFY_CALCHAIN_INTERNALLY));
	CuAssert(tc, "Unexpected verification property", FailedProperty(&signature->policyVerificationResult->finalResult, KSI_VERIFY_PUBLICATION_WITH_PUBSTRING));

	KSI_PolicyVerificationResult_free(result);
	KSI_nofree(context.userPublication);
	KSI_Signature_free(sigWithPub);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_SIGNATURE_FILE_WITH_PUBLICATION
}

static void TestBackgroundVerificationWithKeyBasedPolicy(CuTest* tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
	int res;
	KSI_VerificationContext context;
	KSI_Signature *signature = NULL;
	KSI_RuleVerificationResult expected = {
		KSI_VER_RES_NA,
		KSI_VER_ERR_NONE,
		"KSI_VerificationRule_CalendarAuthenticationRecordExistence"
	};

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Verification context creation failed", res == KSI_OK);

	res = KSI_Signature_fromFileWithPolicy(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), KSI_VERIFICATION_POLICY_KEY_BASED, &context, &signature);
	CuAssert(tc, "Background verification should fail.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);

	CuAssert(tc, "Unexpected verification result.", ResultsMatch(&expected, &signature->policyVerificationResult->finalResult));

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);

#undef TEST_SIGNATURE_FILE
}

CuSuite* KSITest_Policy_getSuite(void) {
	CuSuite* suite = CuSuiteNew();
	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, TestInvalidParams);
	SUITE_ADD_TEST(suite, TestErrorStrings);
	SUITE_ADD_TEST(suite, TestErrorDescription);
	SUITE_ADD_TEST(suite, TestVerificationContext);
	SUITE_ADD_TEST(suite, TestPolicyCreation);
	SUITE_ADD_TEST(suite, TestSingleRulePolicy);
	SUITE_ADD_TEST(suite, TestBasicRulesPolicy);
	SUITE_ADD_TEST(suite, TestCompositeRulesPolicy);
	SUITE_ADD_TEST(suite, TestVerificationResult);
	SUITE_ADD_TEST(suite, TestDuplicateResults);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidRfc3161);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidRfc3161AggrTime);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidRfc3161ChainIndex);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidAggrChainIndex);
	SUITE_ADD_TEST(suite, TestInternalPolicy_OK_MetaDataWithPadding);
	SUITE_ADD_TEST(suite, TestInternalPolicy_OK_MetaDataWithoutPadding);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInvalidMetaDataPadding);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithoutMetaDataPadding);
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
	SUITE_ADD_TEST(suite, TestInternalPolicy_OK_WithInputLevel);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_WithInputLevelTooLarge);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_SignatureAggreChainSameIndex);
	SUITE_ADD_TEST(suite, TestInternalPolicy_FAIL_SignatureAggreChainSameIndexChangedChainOrder);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_NA_ExtenderErrors);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_OK_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_FAIL_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_OK_WithoutPublicationRecord);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_OK_WithoutCalendarHashChain);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_FAIL_WithoutCalendarHashChain);
	SUITE_ADD_TEST(suite, TestCalendarBasedPolicy_OK_WithAlgoChange);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_NA_WithoutCalendarHashChain);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_NA_WithoutCalendarAuthenticationRecord);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_FAIL_WithCalendarAuthenticationRecord);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_FAIL_WithoutCertificate);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_FAIL_WithCertificate);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_FAIL_CertificateValidity);
	SUITE_ADD_TEST(suite, TestKeyBasedPolicy_OK);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_OK_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_NA_DeprecatedAlgInCalendar);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_NA_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_NA_WithoutSuitablePublication);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_NA_WithSuitablePublication);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_OK_WithSuitablePublication);
	SUITE_ADD_TEST(suite, TestPublicationsFileBasedPolicy_FAIL_AfterExtending);
	SUITE_ADD_TEST(suite, TestUserProvidedPublicationBasedPolicy_OK_WithPublicationRecord);
	SUITE_ADD_TEST(suite, TestUserProvidedPublicationBasedPolicy_NA_DeprecatedAlgInCalendar);
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
	SUITE_ADD_TEST(suite, TestPolicyCloning);
	SUITE_ADD_TEST(suite, TestFallbackPolicy_CalendarBased_OK_KeyBased_NA);
	SUITE_ADD_TEST(suite, TestFallbackPolicy_CalendarBased_FAIL_KeyBased_NA);
	SUITE_ADD_TEST(suite, TestUserPublicationWithBadCalAuthRec);
	SUITE_ADD_TEST(suite, TestBackgroundVerificationWithUserPublicationBasedPolicy);
	SUITE_ADD_TEST(suite, TestBackgroundVerificationWithKeyBasedPolicy);
	return suite;
}
