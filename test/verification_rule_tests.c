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

#include <string.h>
#include "all_tests.h"
#include "../src/ksi/verification_rule.h"
#include "../src/ksi/policy_impl.h"
#include "../src/ksi/policy.h"
#include "../src/ksi/verification_impl.h"
#include "../src/ksi/verification.h"
#include "../src/ksi/signature_impl.h"
#include "../src/ksi/signature.h"
#include "../src/ksi/ctx_impl.h"
#include "../src/ksi/net_impl.h"
#include "../src/ksi/hashchain.h"
#include "../src/ksi/publicationsfile.h"
#include "../src/ksi/pkitruststore.h"

extern KSI_CTX *ctx;

#define TEST_USER "anon"
#define TEST_PASS "anon"

#define TEST_VERIFICATION_STEP_INIT\
	verRes.stepsPerformed = KSI_VERIFY_NONE;\
	verRes.stepsFailed = KSI_VERIFY_NONE;\
	verRes.stepsSuccessful = KSI_VERIFY_NONE\

#define TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(step) \
	CuAssert(tc, "Invalid performed step.", verRes.stepsPerformed  == (step)); \
	CuAssert(tc, "Invalid success step.",   verRes.stepsSuccessful == (step)); \
	CuAssert(tc, "Invalid fail step.",      verRes.stepsFailed     == KSI_VERIFY_NONE) \

#define TEST_ASSERT_VERIFICATION_STEP_FAILED(step) \
	CuAssert(tc, "Invalid performed step.", verRes.stepsPerformed  == (step)); \
	CuAssert(tc, "Invalid success step.",   verRes.stepsSuccessful == KSI_VERIFY_NONE); \
	CuAssert(tc, "Invalid fail step.",      verRes.stepsFailed     == (step)) \

#define TEST_ASSERT_VERIFICATION_STEP_NA(step) \
	CuAssert(tc, "Invalid performed step.", verRes.stepsPerformed  == (step)); \
	CuAssert(tc, "Invalid success step.",   verRes.stepsSuccessful == KSI_VERIFY_NONE); \
	CuAssert(tc, "Invalid fail step.",      verRes.stepsFailed     == KSI_VERIFY_NONE) \

static void preTest(void) {
	ctx->netProvider->requestCount = 0;
}

static void testRule_AggregationChainInputHashVerification_validRfc3161(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain valid RFC3161 record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainInputHashVerification_invalidRfc3161_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-rfc3161-output-hash.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_1);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainInputHashVerification_missingRfc3161(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain RFC3161 record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainMetaDataVerification_validMetaData(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-metadata-with-padding.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainMetaDataVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain valid metadata record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainMetaDataVerification_validMetaDataNoPadding(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-metadata-without-padding.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainMetaDataVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain valid metadata record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainMetaDataVerification_invalidMetaDataPaddingNotFirst(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-metadata-padding-not-first.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainMetaDataVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain an invalid metadata record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_11);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainMetaDataVerification_invalidMetaDataPaddingNotTlv8(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-metadata-padding-not-tlv8.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainMetaDataVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain an invalid metadata record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_11);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainMetaDataVerification_invalidMetaDataPaddingFlagsNotSet(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-metadata-padding-flags-not-set.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainMetaDataVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain an invalid metadata record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_11);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainMetaDataVerification_invalidMetaDataPaddingValueNot01(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-metadata-padding-value-not-01.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainMetaDataVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain an invalid metadata record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_11);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainMetaDataVerification_invalidMetaDataPaddingValueNot0101(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-metadata-padding-value-not-0101.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainMetaDataVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain an invalid metadata record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_11);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainMetaDataVerification_invalidMetaDataLengthNotEven(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-metadata-length-not-even.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainMetaDataVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain an invalid metadata record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_11);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainMetaDataVerification_invalidMetaDataNoPadding(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-metadata-padding-missing.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainMetaDataVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain an invalid metadata record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_11);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainMetaDataVerification_missingMetaData(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationChainMetaDataVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain a metadata record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainConsistency(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationHashChainConsistency(&verCtx, &verRes);
	CuAssert(tc, "Signature aggregation hash chain inconsistent.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainConsistency_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/bad-aggregation-chain.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationHashChainConsistency(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_1);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainTimeConsistencyOk(CuTest *tc, const char *sigFile) {
	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(sigFile), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationHashChainTimeConsistency(&verCtx, &verRes);
	CuAssert(tc, "Signature aggregation hash chain time inconsistent.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);
}

static void testRule_AggregationHashChainTimeConsistency(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	testRule_AggregationHashChainTimeConsistencyOk(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainTimeConsistency_validRfc3161(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok.ksig"

	testRule_AggregationHashChainTimeConsistencyOk(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainTimeConsistencyFail(CuTest *tc, const char *sigFile) {
	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(sigFile), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationHashChainTimeConsistency(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_2);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);
}

static void testRule_AggregationHashChainTimeConsistency_inconsistentAggrTime_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-inconsistent-aggregation-chain-time.ksig"

	testRule_AggregationHashChainTimeConsistencyFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainTimeConsistency_rfc3161AggrTimeChanged_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok-changed-aggregation-time.ksig"

	testRule_AggregationHashChainTimeConsistencyFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainTimeConsistency_rfc3161ChainIndexAndAggrTimeChanged_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok-changed-chain-index-and-aggr-time.ksig"

	testRule_AggregationHashChainTimeConsistencyFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexConsistencyOk(CuTest *tc, const char *sigFile) {
	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(sigFile), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationHashChainIndexConsistency(&verCtx, &verRes);
	CuAssert(tc, "Signature aggregation hash chain index inconsistent.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);
}

static void testRule_AggregationHashChainIndexConsistency(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-08-01.1.ksig"

	testRule_AggregationHashChainIndexConsistencyOk(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexConsistency_validRfc3161(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok.ksig"

	testRule_AggregationHashChainIndexConsistencyOk(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexConsistencyFail(CuTest *tc, const char *sigFile) {
	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(sigFile), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationHashChainIndexConsistency(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_10);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);
}

static void testRule_AggregationHashChainIndexConsistency_prefixChanged_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/chain-index-prefix.ksig"

	testRule_AggregationHashChainIndexConsistencyFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexConsistency_prefixesChanged_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/chain-index-prefixes.ksig"

	testRule_AggregationHashChainIndexConsistencyFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexConsistency_suffixChanged_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/chain-index-suffix.ksig"

	testRule_AggregationHashChainIndexConsistencyFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexContinuationOk(CuTest *tc, const char *sigFile) {
	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(sigFile), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationHashChainIndexContinuation(&verCtx, &verRes);
	CuAssert(tc, "Signature aggregation hash chain index inconsistent.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);
}

static void testRule_AggregationHashChainIndexContinuation(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-08-01.1.ksig"

	testRule_AggregationHashChainIndexContinuationOk(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexContinuation_validRfc3161(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok.ksig"

	testRule_AggregationHashChainIndexContinuationOk(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexContinuationFail(CuTest *tc, const char *sigFile) {
	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(sigFile), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_AggregationHashChainIndexContinuation(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_12);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);
}

static void testRule_AggregationHashChainIndexContinuation_rfc3161ChainIndexChanged_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok-changed-chain-index.ksig"

	testRule_AggregationHashChainIndexContinuationFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexContinuation_rfc3161ChainIndexAndAggrTimeChanged_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok-changed-chain-index-and-aggr-time.ksig"

	testRule_AggregationHashChainIndexContinuationFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexContinuation_doubleAggrChain_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-2014-08-01.1.double-aggr-chain.ksig"

	testRule_AggregationHashChainIndexContinuationFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexContinuation_sameChainIndex_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-2014-08-01.1.same-chain-index.ksig"

	testRule_AggregationHashChainIndexContinuationFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainIndexContinuation_wrongChainIndex_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-2014-08-01.1.wrong-chain-index.ksig"

	testRule_AggregationHashChainIndexContinuationFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainInputHashVerification_sigWithCalHashChain(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarHashChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain correct calendar hash chain.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainInputHashVerification_sigWithoutCalHashChain(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarHashChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain calendar hash chain", res != KSI_OK && verRes.resultCode == KSI_VER_RES_NA);

	TEST_ASSERT_VERIFICATION_STEP_NA(KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainInputHashVerification_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-hash-chain.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarHashChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_3);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainAggregationTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarHashChainAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain correct calendar hash chain.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainAggregationTime_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-chain-aggregation-time.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarHashChainAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_4);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainRegistrationTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarHashChainRegistrationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain correct calendar hash chain.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALCHAIN_INTERNALLY);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainRegistrationTime_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-chain-aggregation-time.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarHashChainRegistrationTime(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_5);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALCHAIN_INTERNALLY);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain correct calendar authentication record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationHash_missingAutRec(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-without-calendar-authentication-record.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain contain authentication record.", res != KSI_OK && verRes.resultCode == KSI_VER_RES_NA);

	TEST_ASSERT_VERIFICATION_STEP_NA(KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-authentication-record-hash.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_8);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain correct calendar hash chain.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationTime_missingAutRec(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-without-calendar-authentication-record.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain contain authentication record.", res != KSI_OK && verRes.resultCode == KSI_VER_RES_NA);

	TEST_ASSERT_VERIFICATION_STEP_NA(KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationTime_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-authentication-record-publication-time.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_6);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain publication record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALCHAIN_WITH_PUBLICATION);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationHash_missingPubRec(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain publication record.", res != KSI_OK && verRes.resultCode == KSI_VER_RES_NA);

	TEST_ASSERT_VERIFICATION_STEP_NA(KSI_VERIFY_CALCHAIN_WITH_PUBLICATION);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-publication-record-publication-data-hash.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_9);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALCHAIN_WITH_PUBLICATION);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain publication record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALCHAIN_WITH_PUBLICATION);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationTime_missingPubRec(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain publication record.", res != KSI_OK && verRes.resultCode == KSI_VER_RES_NA);

	TEST_ASSERT_VERIFICATION_STEP_NA(KSI_VERIFY_CALCHAIN_WITH_PUBLICATION);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationTime_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-publication-record-publication-data-time.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &signature);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationTime(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_INT_7);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALCHAIN_WITH_PUBLICATION);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_DocumentHashDoesNotExist(CuTest *tc) {
	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_VerificationRule_DocumentHashDoesNotExist(&verCtx, &verRes);
	CuAssert(tc, "Document hash should not be provided.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK && verCtx.documentHash == NULL);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);
}

static void testRule_DocumentHashDoesNotExist_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_getDocumentHash(verCtx.signature, (KSI_DataHash **)&verCtx.documentHash);
	CuAssert(tc, "Unable to read signature document hash", res == KSI_OK && verCtx.documentHash != NULL);

	res = KSI_VerificationRule_DocumentHashDoesNotExist(&verCtx, &verRes);
	CuAssert(tc, "Document hash not found.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verCtx.documentHash != NULL);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_DocumentHashExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_getDocumentHash(verCtx.signature, (KSI_DataHash **)&verCtx.documentHash);
	CuAssert(tc, "Unable to read signature document hash", res == KSI_OK && verCtx.documentHash != NULL);

	res = KSI_VerificationRule_DocumentHashExistence(&verCtx, &verRes);
	CuAssert(tc, "Document hash not found.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK && verCtx.documentHash != NULL);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_DocumentHashExistence_verifyErrorResult(CuTest *tc) {
	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_VerificationRule_DocumentHashExistence(&verCtx, &verRes);
	CuAssert(tc, "Document hash should not be provided.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verCtx.documentHash == NULL);

	KSI_VerificationContext_clean(&verCtx);
}

static void testRule_DocumentHashVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_getDocumentHash(verCtx.signature, (KSI_DataHash **)&verCtx.documentHash);
	CuAssert(tc, "Unable to read signature document hash", res == KSI_OK && verCtx.documentHash != NULL);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_DocumentHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature document hash and provided hash should be equal", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_DOCUMENT);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_DocumentHashVerification_missingDocHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_DocumentHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Document hash should not be provided.", res == KSI_INVALID_ARGUMENT && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2 && verCtx.documentHash == NULL);

	TEST_ASSERT_VERIFICATION_STEP_NA(KSI_VERIFY_DOCUMENT);

	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_DocumentHashVerification_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_MOCK_IMPRINT   "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_DataHash *documentHash = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &documentHash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && documentHash != NULL);
	verCtx.documentHash = documentHash;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_DocumentHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_GEN_1);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_DOCUMENT);

	KSI_DataHash_free(documentHash);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_MOCK_IMPRINT
}

static void testRule_DocumentHashVerification_rfc3161(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_RFC3161_getInputHash(verCtx.signature->rfc3161, (KSI_DataHash **)&verCtx.documentHash);
	CuAssert(tc, "Unable to read signature RFC3161 input hash", res == KSI_OK && verCtx.documentHash != NULL);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_DocumentHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature RFC3161 input hash should be ok.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_DOCUMENT);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_DocumentHashVerification_rfc3161_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok.ksig"
#define TEST_MOCK_IMPRINT   "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_DataHash *documentHash = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &documentHash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && documentHash != NULL);
	verCtx.documentHash = documentHash;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_DocumentHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_GEN_1);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_DOCUMENT);

	KSI_DataHash_free(documentHash);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_MOCK_IMPRINT
}

static void testRule_SignatureDoesNotContainPublication(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_SignatureDoesNotContainPublication(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain publication record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignatureDoesNotContainPublication_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_SignatureDoesNotContainPublication(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureCalendarChainRightLinksMatch(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainRightLinksMatch(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain publication record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALCHAIN_ONLINE);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_ExtendedSignatureCalendarChainRightLinksMatchWithAdditionalLeftLinks(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.2-extended.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *extendedSig = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && extendedSig != NULL);

	tempData.calendarChain = KSI_CalendarHashChain_ref(extendedSig->calendarChain);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainRightLinksMatch(&verCtx, &verRes);
	CuAssert(tc, "Calendar chain right link sequence should match with extended calendar chain right link sequence.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALCHAIN_ONLINE);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureCalendarChainRightLinksMatch_linkCountMismatch_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *extendedSig = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && extendedSig != NULL);

	tempData.calendarChain = KSI_CalendarHashChain_ref(extendedSig->calendarChain);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainRightLinksMatch(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_CAL_4);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALCHAIN_ONLINE);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureCalendarChainRightLinksMatch_rightLinksDiffer_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/signature-invalid-calendar-right-link-sig-2014-04-30.1-extended.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *extendedSig = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_VERIFICATION_FAILURE && extendedSig == NULL);

	res = KSI_CTX_getLastFailedSignature(ctx, &extendedSig);
	CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && extendedSig != NULL);

	tempData.calendarChain = KSI_CalendarHashChain_ref(extendedSig->calendarChain);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainRightLinksMatch(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_CAL_4);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALCHAIN_ONLINE);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_SignaturePublicationRecordExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain publication record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordExistence_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_SignaturePublicationRecordExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureCalendarChainRootHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain calendar hash chain.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALCHAIN_ONLINE);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_ExtendedSignatureCalendarChainRootHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *extendedSig = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && extendedSig != NULL);

	tempData.calendarChain = KSI_CalendarHashChain_ref(extendedSig->calendarChain);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_CAL_1);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALCHAIN_ONLINE);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_CalendarHashChainDoesNotExist(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_CalendarHashChainDoesNotExist(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain calendar hash chain.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainDoesNotExist_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_CalendarHashChainDoesNotExist(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureCalendarChainInputHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"

	int res;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain calendar hash chain.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALCHAIN_ONLINE);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_ExtendedSignatureCalendarChainInputHash_nokAggrOutHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"

	int res;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;


	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getDocumentHash(verCtx.signature, &((VerificationTempData *)verCtx.tempData)->aggregationOutputHash);
	CuAssert(tc, "Unable to read signature document hash", res == KSI_OK && ((VerificationTempData *)verCtx.tempData)->aggregationOutputHash != NULL);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_CAL_2);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALCHAIN_ONLINE);

	KSI_nofree(tempData.aggregationOutputHash);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_ExtendedSignatureCalendarChainInputHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *extendedSig = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && extendedSig != NULL);

	tempData.calendarChain = KSI_CalendarHashChain_ref(extendedSig->calendarChain);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_CAL_2);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALCHAIN_ONLINE);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureCalendarChainAggregationTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"

	int res;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain calendar hash chain.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALCHAIN_ONLINE);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_ExtendedSignatureCalendarChainAggregationTime_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *extendedSig = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && extendedSig != NULL);

	tempData.calendarChain = KSI_CalendarHashChain_ref(extendedSig->calendarChain);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_CAL_3);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALCHAIN_ONLINE);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_CalendarHashChainExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_CalendarHashChainExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain calendar hash chain.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainExistence_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"

	int res;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_CalendarHashChainExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.",  res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_CalendarAuthenticationRecordExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain calendar authentication record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordExistence_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-calendar-authentication-record-missing.ksig"

	int res;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_CalendarAuthenticationRecordExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordDoesNotExist(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-calendar-authentication-record-missing.ksig"

	int res;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_CalendarAuthenticationRecordDoesNotExist(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain calendar authentication record.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordDoesNotExist_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_CalendarAuthenticationRecordDoesNotExist(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CertificateExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
#define TEST_CERT_FILE         "resource/crt/mock.crt"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PKITruststore *pki = NULL;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, NULL);
	CuAssert(tc, "Unable to set clear PKI truststrore for KSI context.", res == KSI_OK);

	/* Configure expected PKI cert and constraints for pub. file. */
	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CERT_FILE));
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new PKI truststrore for KSI context.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CertificateExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature autentication record certificate not found", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
#undef TEST_CERT_FILE
}

static void testRule_CertificateExistence_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications-one-cert-one-publication-record-with-wrong-hash.tlv"
#define TEST_CERT_FILE         "resource/crt/mock.crt"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PKITruststore *pki = NULL;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file.", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints for email.", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, NULL);
	CuAssert(tc, "Unable to set clear PKI truststrore for KSI context.", res == KSI_OK);

	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CERT_FILE));
	CuAssert(tc, "Unable to read certificat.e", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new PKI truststrore for KSI context.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CertificateExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_KEY_1);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
#undef TEST_CERT_FILE
}

static void testRule_CertificateValidity(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
#define TEST_CERT_FILE         "resource/crt/mock.crt"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PKITruststore *pki = NULL;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file.", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints.", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, NULL);
	CuAssert(tc, "Unable to set clear PKI truststrore for KSI context.", res == KSI_OK);

	/* Configure expected PKI cert and constraints for pub. file. */
	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CERT_FILE));
	CuAssert(tc, "Unable to read certificate.", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new PKI truststrore for KSI context.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CertificateValidity(&verCtx, &verRes);
	CuAssert(tc, "Signature autentication record certificate is ok.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
#undef TEST_CERT_FILE
}

static void testRule_CertificateValidity_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/nok-sig-2017-08-23.1.invalid-cert-timespan.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/ksi-publications.invalid-cert.validity.bin"
#define TEST_CERT_FILE         "resource/crt/short-timespan.pem"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PKITruststore *pki = NULL;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file.", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints.", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, NULL);
	CuAssert(tc, "Unable to set clear PKI truststrore for KSI context.", res == KSI_OK);

	/* Configure expected PKI cert and constraints for pub. file. */
	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CERT_FILE));
	CuAssert(tc, "Unable to read certificate.", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new PKI truststrore for KSI context.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CertificateValidity(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.",
			res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_KEY_3);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
#undef TEST_CERT_FILE
}

static void testRule_CalendarAuthenticationRecordSignatureVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
#define TEST_CERT_FILE         "resource/crt/mock.crt"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PKITruststore *pki = NULL;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, NULL);
	CuAssert(tc, "Unable to set clear PKI truststrore for KSI context.", res == KSI_OK);

	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CERT_FILE));
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new PKI truststrore for KSI context.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify calendar authentication record signature", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
#undef TEST_CERT_FILE
}

static void testRule_CalendarAuthenticationRecordSignatureVerification_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/signature-cal-auth-wrong-signing-value.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
#define TEST_CERT_FILE         "resource/crt/mock.crt"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PKITruststore *pki = NULL;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, NULL);
	CuAssert(tc, "Unable to set clear PKI truststrore for KSI context.", res == KSI_OK);

	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CERT_FILE));
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new PKI truststrore for KSI context.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_KEY_2);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
#undef TEST_CERT_FILE
}

static void testRule_PublicationsFileContainsSignaturePublication(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;
	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_PublicationsFileContainsSignaturePublication(&verCtx, &verRes);
	CuAssert(tc, "Publications file should contain signature publication", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_PUBLICATION_WITH_PUBFILE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFileContainsSignaturePublication_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_PublicationsFileContainsSignaturePublication(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	TEST_ASSERT_VERIFICATION_STEP_NA(KSI_VERIFY_PUBLICATION_WITH_PUBFILE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFileContainsPublication(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_PublicationsFileContainsSuitablePublication(&verCtx, &verRes);
	CuAssert(tc, "Publications file should contain signature publication", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_PUBLICATION_WITH_PUBFILE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFileContainsPublication_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_PublicationsFileContainsSuitablePublication(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	TEST_ASSERT_VERIFICATION_STEP_NA(KSI_VERIFY_PUBLICATION_WITH_PUBFILE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_ExtendingPermittedVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	verCtx.extendingAllowed = 1;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_PublicationsFileExtendingPermittedVerification(&verCtx, &verRes);
	CuAssert(tc, "Extending should be permitted", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_ExtendingPermittedVerification_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	verCtx.extendingAllowed = 0;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_PublicationsFileExtendingPermittedVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
}

static void testRule_PublicationsFilePublicationHashMatchesExtenderResponse(CuTest *tc, char *testSignatureFile) {
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(testSignatureFile), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse(&verCtx, &verRes);
	CuAssert(tc, "Extender response hash should match publications file publication hash", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_PUBLICATION_WITH_PUBFILE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_EXT_RESPONSE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFilePublicationHashMatchesExtenderResponse_notExtended(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
	testRule_PublicationsFilePublicationHashMatchesExtenderResponse(tc, TEST_SIGNATURE_FILE);
#undef TEST_SIGNATURE_FILE
}

static void testRule_PublicationsFilePublicationHashMatchesExtenderResponse_extended(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
	testRule_PublicationsFilePublicationHashMatchesExtenderResponse(tc, TEST_SIGNATURE_FILE);
#undef TEST_SIGNATURE_FILE
}

static void testRule_PublicationsFilePublicationHashMatchesExtenderResponse_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_PUBLICATIONS_FILE  "resource/tlv/publications.tlv"
	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *extendedSig = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && extendedSig != NULL);

	tempData.calendarChain = KSI_CalendarHashChain_ref(extendedSig->calendarChain);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);


	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_PUB_1);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_PUBLICATION_WITH_PUBFILE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(extendedSig);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFilePublicationTimeMatchesExtenderResponse(CuTest *tc, char *testSignatureFile) {
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(testSignatureFile), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_PublicationsFilePublicationTimeMatchesExtenderResponse(&verCtx, &verRes);
	CuAssert(tc, "Extender response time should match publications file publication time", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_PUBLICATION_WITH_PUBFILE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);

#undef TEST_EXT_RESPONSE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFilePublicationTimeMatchesExtenderResponse_notExtended(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
	testRule_PublicationsFilePublicationTimeMatchesExtenderResponse(tc, TEST_SIGNATURE_FILE);
#undef TEST_SIGNATURE_FILE
}

static void testRule_PublicationsFilePublicationTimeMatchesExtenderResponse_extended(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
	testRule_PublicationsFilePublicationTimeMatchesExtenderResponse(tc, TEST_SIGNATURE_FILE);
#undef TEST_SIGNATURE_FILE
}

static void testRule_PublicationsFilePublicationTimeMatchesExtenderResponse_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_PUBLICATIONS_FILE  "resource/tlv/publications.tlv"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *extendedSig = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && extendedSig != NULL);

	tempData.calendarChain = KSI_CalendarHashChain_ref(extendedSig->calendarChain);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_PublicationsFilePublicationTimeMatchesExtenderResponse(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_PUB_2);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_PUBLICATION_WITH_PUBFILE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(extendedSig);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFileExtendedSignatureInputHash(CuTest *tc, char *testSignatureFile) {
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(testSignatureFile), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash(&verCtx, &verRes);
	CuAssert(tc, "Extender response time should match publications file publication time", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_PUBLICATION_WITH_PUBFILE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_CTX_free(ctx);
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFileExtendedSignatureInputHash_notExtended(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
	testRule_PublicationsFileExtendedSignatureInputHash(tc, TEST_SIGNATURE_FILE);
#undef TEST_SIGNATURE_FILE
}

static void testRule_PublicationsFileExtendedSignatureInputHash_extended(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
	testRule_PublicationsFileExtendedSignatureInputHash(tc, TEST_SIGNATURE_FILE);
#undef TEST_SIGNATURE_FILE
}

static void testRule_PublicationsFileExtendedSignatureInputHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_PUBLICATIONS_FILE  "resource/tlv/publications.tlv"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};
	VerificationTempData tempData;
	KSI_CTX *ctx = NULL;
	KSI_Signature *extendedSig = NULL;
	KSI_Signature *signature = NULL;
	KSI_PublicationsFile *userPublicationsFile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_CTX_clone(&ctx);
	CuAssert(tc, "Unable to create new context.", res == KSI_OK && ctx != NULL);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && extendedSig != NULL);

	tempData.calendarChain = KSI_CalendarHashChain_ref(extendedSig->calendarChain);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &userPublicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && userPublicationsFile != NULL);
	verCtx.userPublicationsFile = userPublicationsFile;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_PUB_3);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_PUBLICATION_WITH_PUBFILE);

	KSI_PublicationsFile_free(userPublicationsFile);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(extendedSig);
	KSI_CTX_free(ctx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_UserProvidedPublicationExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext context;
	KSI_RuleVerificationResult verRes;
	KSI_PublicationRecord *tempRec = NULL;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&context, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	context.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	context.signature = signature;

	res = KSI_Signature_getPublicationRecord(context.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record.", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData **)&context.userPublication);
	CuAssert(tc, "Unable to read signature publication data.", res == KSI_OK && context.userPublication != NULL);

	res = KSI_VerificationRule_UserProvidedPublicationExistence(&context, &verRes);
	CuAssert(tc, "User publication data should be provided", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	KSI_nofree(context.userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&context);
#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationExistence_pubDataMissing_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_VerificationRule_UserProvidedPublicationExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationExistence_pubHashMissing_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_PublicationData *tempPubData = NULL;
	KSI_Integer *pubTime = NULL;
	VerificationTempData tempData;
	KSI_PublicationData *userPublication = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationData_new(ctx, &userPublication);
	CuAssert(tc, "Unable to create publication data.", res == KSI_OK && userPublication != NULL);
	verCtx.userPublication = userPublication;

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record.", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &tempPubData);
	CuAssert(tc, "Unable to read signature publication data.", res == KSI_OK && tempPubData != NULL);

	res = KSI_PublicationData_getTime(tempPubData, &pubTime);
	CuAssert(tc, "Unable to read signature publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_setTime(userPublication, KSI_Integer_ref(pubTime));
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSI_VerificationRule_UserProvidedPublicationExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	KSI_PublicationData_free(userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationExistence_pubTimeMissing_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_PublicationData *tempPubData = NULL;
	KSI_DataHash *pubHash = NULL;
	VerificationTempData tempData;
	KSI_PublicationData *userPublication = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationData_new(ctx, &userPublication);
	CuAssert(tc, "Unable to create publication data.", res == KSI_OK && userPublication != NULL);
	verCtx.userPublication = userPublication;

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record.", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &tempPubData);
	CuAssert(tc, "Unable to read signature publication data.", res == KSI_OK && tempPubData != NULL);

	res = KSI_PublicationData_getImprint(tempPubData, &pubHash);
	CuAssert(tc, "Unable to read signature publication hash", res == KSI_OK && pubHash != NULL);

	res = KSI_PublicationData_setImprint(userPublication, KSI_DataHash_ref(pubHash));
	CuAssert(tc, "Unable to set publication hash.", res == KSI_OK);

	res = KSI_VerificationRule_UserProvidedPublicationExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	KSI_PublicationData_free(userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationTimeVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PublicationRecord *tempRec = NULL;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData **)&verCtx.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userPublication != NULL);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationTimeVerification(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify signature publication data", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationHashVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PublicationRecord *tempRec = NULL;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData **)&verCtx.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userPublication != NULL);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify signature publication data", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_nofree(verCtx.userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationVerification_timeMismatch_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_TIMESTAMP      1396608816

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *pubHash = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_PublicationData *tempPubData = NULL;
	VerificationTempData tempData;
	KSI_PublicationData *userPublication = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &tempPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && tempPubData != NULL);

	res = KSI_PublicationData_new(ctx, &userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && userPublication != NULL);
	verCtx.userPublication = userPublication;

	res = KSI_Integer_new(ctx, TEST_TIMESTAMP, &pubTime);
	CuAssert(tc, "Unable to create publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_setTime(userPublication, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSI_PublicationData_getImprint(tempPubData, &pubHash);
	CuAssert(tc, "Unable to read signature publication hash", res == KSI_OK && pubHash != NULL);

	/* Make a virtual copy of the hash object. */
	KSI_DataHash_ref(pubHash);

	res = KSI_PublicationData_setImprint(userPublication, pubHash);
	CuAssert(tc, "Unable to set publication hash.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationTimeVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	TEST_ASSERT_VERIFICATION_STEP_NA(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_PublicationData_free(userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
#undef TEST_SIGNATURE_FILE
#undef TEST_TIMESTAMP
}

static void testRule_UserProvidedPublicationVerification_hashMismatch_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_MOCK_IMPRINT   "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_Integer *pubTime = NULL;
	KSI_PublicationRecord *sigPubRec = NULL;
	KSI_PublicationData *sigPubData = NULL;
	KSI_DataHash *mockPubHash = NULL;
	VerificationTempData tempData;
	KSI_PublicationData *userPublication = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &sigPubRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && sigPubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(sigPubRec, &sigPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && sigPubData != NULL);

	res = KSI_PublicationData_new(ctx, &userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && userPublication != NULL);
	verCtx.userPublication = userPublication;

	res = KSI_PublicationData_getTime(sigPubData, &pubTime);
	CuAssert(tc, "Unable to read signature publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_setTime(userPublication, KSI_Integer_ref(pubTime));
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &mockPubHash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && mockPubHash != NULL);

	res = KSI_PublicationData_setImprint(userPublication, mockPubHash);
	CuAssert(tc, "Unable to set publication mock hash.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_PUB_4);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_PublicationData_free(userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
#undef TEST_SIGNATURE_FILE
#undef TEST_MOCK_IMPRINT
}

static void testRule_UserProvidedPublicationCreationTimeVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PublicationRecord *tempRec = NULL;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData **)&verCtx.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userPublication != NULL);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify creation time", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_nofree(verCtx.userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationCreationTimeVerification_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_TIMESTAMP      1396608816

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_Integer *mockTime = NULL;
	VerificationTempData tempData;
	KSI_PublicationData *userPublication = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_PublicationData_new(ctx, &userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && userPublication != NULL);
	verCtx.userPublication = userPublication;

	res = KSI_Integer_new(ctx, TEST_TIMESTAMP, &mockTime);
	CuAssert(tc, "Unable to create publication time", res == KSI_OK && mockTime != NULL);

	res = KSI_PublicationData_setTime(userPublication, mockTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);

	TEST_ASSERT_VERIFICATION_STEP_NA(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_PublicationData_free(userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
#undef TEST_SIGNATURE_FILE
#undef TEST_TIMESTAMP
}

static void testRule_UserProvidedPublicationHashMatchesExtendedResponse(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PublicationRecord *tempRec = NULL;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData **)&verCtx.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userPublication != NULL);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify extender response with user publication", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_nofree(verCtx.userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_UserProvidedPublicationHashMatchesExtendedResponse_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_MOCK_IMPRINT      "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *mockPubHash = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_PublicationData *tempPubData = NULL;
	VerificationTempData tempData;
	KSI_PublicationData *userPublication = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &tempPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && tempPubData != NULL);

	res = KSI_PublicationData_new(ctx, &userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && userPublication != NULL);
	verCtx.userPublication = userPublication;

	res = KSI_PublicationData_getTime(tempPubData, &pubTime);
	CuAssert(tc, "Unable to read signature publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_setTime(userPublication, KSI_Integer_ref(pubTime));
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &mockPubHash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && mockPubHash != NULL);

	res = KSI_PublicationData_setImprint(userPublication, KSI_DataHash_ref(mockPubHash));
	CuAssert(tc, "Unable to set publication mock hash.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_PUB_1);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_DataHash_free(mockPubHash);
	KSI_PublicationData_free(userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_MOCK_IMPRINT
}

static void testRule_UserProvidedPublicationHashMatchesExtendedResponse_wrongCore_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/all-wrong-hash-chains-in-signature.ksig"
#define TEST_EXT_RESPONSE_FILE  "resource/tlv/" TEST_RESOURCE_EXT_VER "/all-wrong-hash-chains-in-signature-extend_response.tlv"
#define TEST_PUB_STRING_FROM_DIFFERENT_CORE "AAAAAA-CT5VGY-AAJXGM-OSRUAE-MOQ6RW-BMQ2ZJ-CNIE5V-6HCC5D-UUXKB5-I5EKSS-MVD7PJ-MA2QLD"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_PublicationData *userPublication = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_PublicationData_fromBase32(ctx, TEST_PUB_STRING_FROM_DIFFERENT_CORE, &userPublication);
	CuAssert(tc, "Failed decoding publication string.", res == KSI_OK && userPublication != NULL);
	verCtx.userPublication = userPublication;

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_PUB_1);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_PublicationData_free(userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_PUB_STRING_FROM_DIFFERENT_CORE
}

static void testRule_UserProvidedPublicationTimeMatchesExtendedResponse(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PublicationRecord *tempRec = NULL;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData **)&verCtx.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userPublication != NULL);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify extender response with user publication", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_nofree(verCtx.userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_UserProvidedPublicationTimeMatchesExtendedResponse_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_TIMESTAMP          1396608816

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_Integer *mockPubTime = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_PublicationData *tempPubData = NULL;
	KSI_DataHash *pubHash = NULL;
	VerificationTempData tempData;
	KSI_Signature *extendedSig = NULL;
	KSI_PublicationData *userPublication = NULL;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && extendedSig != NULL);

	tempData.calendarChain = KSI_CalendarHashChain_ref(extendedSig->calendarChain);

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &tempPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && tempPubData != NULL);

	res = KSI_PublicationData_new(ctx, &userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && userPublication != NULL);
	verCtx.userPublication = userPublication;

	res = KSI_Integer_new(ctx, TEST_TIMESTAMP, &mockPubTime);
	CuAssert(tc, "Unable to create mock time", res == KSI_OK && mockPubTime != NULL);

	res = KSI_PublicationData_setTime(userPublication, mockPubTime);
	CuAssert(tc, "Unable to set publication mock time.", res == KSI_OK);

	res = KSI_PublicationData_getImprint(tempPubData, &pubHash);
	CuAssert(tc, "Unable to read signature publication hash", res == KSI_OK && pubHash != NULL);

	/* Make a virtual copy of the hash object. */
	KSI_DataHash_ref(pubHash);

	res = KSI_PublicationData_setImprint(userPublication, pubHash);
	CuAssert(tc, "Unable to set publication hash.", res == KSI_OK);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_PUB_2);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_PublicationData_free(userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);
	KSI_Signature_free(extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_TIMESTAMP
}

static void testRule_UserProvidedPublicationExtendedSignatureInputHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PublicationRecord *tempRec = NULL;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData **)&verCtx.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userPublication != NULL);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify extended signature input hash", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);

	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_nofree(verCtx.userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_UserProvidedPublicationExtendedSignatureInputHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/" TEST_RESOURCE_EXT_VER "/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_MOCK_IMPRINT      "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	KSI_PublicationRecord *tempRec = NULL;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.signature, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, (KSI_PublicationData **)&verCtx.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userPublication != NULL);

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &((VerificationTempData *)verCtx.tempData)->aggregationOutputHash);
	CuAssert(tc, "Unable to create mock hash", res == KSI_OK && ((VerificationTempData *)verCtx.tempData)->aggregationOutputHash != NULL);

	TEST_VERIFICATION_STEP_INIT;

	res = KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_PUB_3);

	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_PUBLICATION_WITH_PUBSTRING);

	KSI_nofree(verCtx.userPublication);
	KSI_Signature_free(signature);
	KSI_VerificationContext_clean(&verCtx);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_MOCK_IMPRINT
}

static void testRule_AggregationChainInputLevelVerification_sigWithRfc3161(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok.ksig"

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;
	verCtx.docAggrLevel = 0;
	res = KSI_VerificationRule_AggregationChainInputLevelVerification(&verCtx, &verRes);
	CuAssert(tc, "Input level is valid.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);
	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	TEST_VERIFICATION_STEP_INIT;
	verCtx.docAggrLevel = 1;
	res = KSI_VerificationRule_AggregationChainInputLevelVerification(&verCtx, &verRes);
	CuAssert(tc, "Input level is invalid.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_GEN_3);
	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	TEST_VERIFICATION_STEP_INIT;
	verCtx.docAggrLevel = 0xff;
	res = KSI_VerificationRule_AggregationChainInputLevelVerification(&verCtx, &verRes);
	CuAssert(tc, "Input level is invalid.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_GEN_3);
	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	TEST_VERIFICATION_STEP_INIT;
	verCtx.docAggrLevel = ULLONG_MAX;
	res = KSI_VerificationRule_AggregationChainInputLevelVerification(&verCtx, &verRes);
	CuAssert(tc, "Input level is invalid.", res != KSI_OK && verRes.resultCode == KSI_VER_RES_NA && verRes.errorCode == KSI_VER_ERR_GEN_2);
	TEST_ASSERT_VERIFICATION_STEP_NA(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainInputLevelVerification_sigWithLevel(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2017-04-21.1-input-hash-level-5.ksig"
#define TEST_AGGR_LEVEL 5

	int res = KSI_OK;
	KSI_VerificationContext verCtx;
	KSI_RuleVerificationResult verRes;
	VerificationTempData tempData;
	KSI_Signature *signature = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_VerificationContext_init(&verCtx, ctx);
	CuAssert(tc, "Unable to create verification context.", res == KSI_OK);
	memset(&tempData, 0, sizeof(tempData));
	verCtx.tempData = &tempData;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &signature);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && signature != NULL);
	verCtx.signature = signature;

	TEST_VERIFICATION_STEP_INIT;
	verCtx.docAggrLevel = TEST_AGGR_LEVEL;
	res = KSI_VerificationRule_AggregationChainInputLevelVerification(&verCtx, &verRes);
	CuAssert(tc, "Input level is valid.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);
	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	TEST_VERIFICATION_STEP_INIT;
	verCtx.docAggrLevel = 0;
	res = KSI_VerificationRule_AggregationChainInputLevelVerification(&verCtx, &verRes);
	CuAssert(tc, "Input level is valid.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);
	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	TEST_VERIFICATION_STEP_INIT;
	verCtx.docAggrLevel = TEST_AGGR_LEVEL - 1;
	res = KSI_VerificationRule_AggregationChainInputLevelVerification(&verCtx, &verRes);
	CuAssert(tc, "Input level is valid.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_OK);
	TEST_ASSERT_VERIFICATION_STEP_SUCCEEDED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	TEST_VERIFICATION_STEP_INIT;
	verCtx.docAggrLevel = TEST_AGGR_LEVEL + 1;
	res = KSI_VerificationRule_AggregationChainInputLevelVerification(&verCtx, &verRes);
	CuAssert(tc, "Input level is invalid.", res == KSI_OK && verRes.resultCode == KSI_VER_RES_FAIL && verRes.errorCode == KSI_VER_ERR_GEN_3);
	TEST_ASSERT_VERIFICATION_STEP_FAILED(KSI_VERIFY_AGGRCHAIN_INTERNALLY);

	KSI_Signature_free(signature);

#undef TEST_SIGNATURE_FILE
#undef TEST_AGGR_LEVEL
}

CuSuite* KSITest_VerificationRules_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, testRule_AggregationChainInputHashVerification_validRfc3161);
	SUITE_ADD_TEST(suite, testRule_AggregationChainInputHashVerification_invalidRfc3161_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationChainInputHashVerification_missingRfc3161);
	SUITE_ADD_TEST(suite, testRule_AggregationChainMetaDataVerification_validMetaData);
	SUITE_ADD_TEST(suite, testRule_AggregationChainMetaDataVerification_validMetaDataNoPadding);
	SUITE_ADD_TEST(suite, testRule_AggregationChainMetaDataVerification_invalidMetaDataPaddingNotFirst);
	SUITE_ADD_TEST(suite, testRule_AggregationChainMetaDataVerification_invalidMetaDataPaddingNotTlv8);
	SUITE_ADD_TEST(suite, testRule_AggregationChainMetaDataVerification_invalidMetaDataPaddingFlagsNotSet);
	SUITE_ADD_TEST(suite, testRule_AggregationChainMetaDataVerification_invalidMetaDataPaddingValueNot01);
	SUITE_ADD_TEST(suite, testRule_AggregationChainMetaDataVerification_invalidMetaDataPaddingValueNot0101);
	SUITE_ADD_TEST(suite, testRule_AggregationChainMetaDataVerification_invalidMetaDataLengthNotEven);
	SUITE_ADD_TEST(suite, testRule_AggregationChainMetaDataVerification_invalidMetaDataNoPadding);
	SUITE_ADD_TEST(suite, testRule_AggregationChainMetaDataVerification_missingMetaData);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainConsistency);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainConsistency_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainTimeConsistency);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainTimeConsistency_validRfc3161);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainTimeConsistency_inconsistentAggrTime_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainTimeConsistency_rfc3161AggrTimeChanged_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainTimeConsistency_rfc3161ChainIndexAndAggrTimeChanged_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexConsistency);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexConsistency_validRfc3161);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexConsistency_prefixChanged_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexConsistency_prefixesChanged_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexConsistency_suffixChanged_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexContinuation);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexContinuation_validRfc3161);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexContinuation_rfc3161ChainIndexChanged_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexContinuation_rfc3161ChainIndexAndAggrTimeChanged_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexContinuation_doubleAggrChain_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexContinuation_sameChainIndex_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainIndexContinuation_wrongChainIndex_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainInputHashVerification_sigWithCalHashChain);
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainInputHashVerification_sigWithoutCalHashChain);
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainInputHashVerification_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainAggregationTime);
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainAggregationTime_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainRegistrationTime);
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainRegistrationTime_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordAggregationHash);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordAggregationHash_missingAutRec);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordAggregationHash_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordAggregationTime);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordAggregationTime_missingAutRec);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordAggregationTime_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_SignaturePublicationRecordPublicationHash);
	SUITE_ADD_TEST(suite, testRule_SignaturePublicationRecordPublicationHash_missingPubRec);
	SUITE_ADD_TEST(suite, testRule_SignaturePublicationRecordPublicationHash_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_SignaturePublicationRecordPublicationTime);
	SUITE_ADD_TEST(suite, testRule_SignaturePublicationRecordPublicationTime_missingPubRec);
	SUITE_ADD_TEST(suite, testRule_SignaturePublicationRecordPublicationTime_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_DocumentHashDoesNotExist);
	SUITE_ADD_TEST(suite, testRule_DocumentHashDoesNotExist_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_DocumentHashExistence);
	SUITE_ADD_TEST(suite, testRule_DocumentHashExistence_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_DocumentHashVerification);
	SUITE_ADD_TEST(suite, testRule_DocumentHashVerification_missingDocHash);
	SUITE_ADD_TEST(suite, testRule_DocumentHashVerification_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_DocumentHashVerification_rfc3161);
	SUITE_ADD_TEST(suite, testRule_DocumentHashVerification_rfc3161_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_SignatureDoesNotContainPublication);
	SUITE_ADD_TEST(suite, testRule_SignatureDoesNotContainPublication_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainRightLinksMatch);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainRightLinksMatchWithAdditionalLeftLinks);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainRightLinksMatch_linkCountMismatch_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainRightLinksMatch_rightLinksDiffer_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_SignaturePublicationRecordExistence);
	SUITE_ADD_TEST(suite, testRule_SignaturePublicationRecordExistence_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainRootHash);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainRootHash_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainDoesNotExist);
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainDoesNotExist_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainInputHash);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainInputHash_nokAggrOutHash_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainInputHash_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainAggregationTime);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainAggregationTime_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainExistence);
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainExistence_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordExistence);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordExistence_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordDoesNotExist);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordDoesNotExist_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CertificateExistence);
	SUITE_ADD_TEST(suite, testRule_CertificateExistence_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CertificateValidity);
	SUITE_ADD_TEST(suite, testRule_CertificateValidity_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordSignatureVerification);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordSignatureVerification_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsSignaturePublication);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsSignaturePublication_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsPublication);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsPublication_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_ExtendingPermittedVerification);
	SUITE_ADD_TEST(suite, testRule_ExtendingPermittedVerification_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationHashMatchesExtenderResponse_notExtended);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationHashMatchesExtenderResponse_extended);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationHashMatchesExtenderResponse_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationTimeMatchesExtenderResponse_notExtended);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationTimeMatchesExtenderResponse_extended);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationTimeMatchesExtenderResponse_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileExtendedSignatureInputHash_notExtended);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileExtendedSignatureInputHash_extended);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileExtendedSignatureInputHash_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExistence);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExistence_pubDataMissing_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExistence_pubHashMissing_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExistence_pubTimeMissing_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationTimeVerification);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationHashVerification);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationVerification_timeMismatch_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationVerification_hashMismatch_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationCreationTimeVerification);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationCreationTimeVerification_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationHashMatchesExtendedResponse);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationHashMatchesExtendedResponse_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationHashMatchesExtendedResponse_wrongCore_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationTimeMatchesExtendedResponse);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationTimeMatchesExtendedResponse_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExtendedSignatureInputHash);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExtendedSignatureInputHash_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationChainInputLevelVerification_sigWithRfc3161);
	SUITE_ADD_TEST(suite, testRule_AggregationChainInputLevelVerification_sigWithLevel);

	return suite;
}
