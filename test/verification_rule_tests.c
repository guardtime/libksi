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
#include "../src/ksi/internal.h"
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

static void preTest(void) {
	ctx->netProvider->requestCount = 0;
}

static void testRule_AggregationChainInputHashVerification_validRfc3161(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_AggregationChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain valid RFC3161 record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainInputHashVerification_invalidRfc3161_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-rfc3161-output-hash.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_AggregationChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == INT_1);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationChainInputHashVerification_missingRfc3161(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_AggregationChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain RFC3161 record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainConsistency(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_AggregationHashChainConsistency(&verCtx, &verRes);
	CuAssert(tc, "Signature aggregation hash chain inconsistent.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_DataHash_free(verCtx.tempData.aggregationOutputHash);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainConsistency_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/bad-aggregation-chain.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_AggregationHashChainConsistency(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == INT_1);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_DataHash_free(verCtx.tempData.aggregationOutputHash);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainTimeConsistency(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_AggregationHashChainTimeConsistency(&verCtx, &verRes);
	CuAssert(tc, "Signature aggregation hash chain time inconsistent.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_AggregationHashChainTimeConsistency_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-inconsistent-aggregation-chain-time.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_AggregationHashChainTimeConsistency(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == INT_2);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainInputHashVerification_sigWithCalHashChain(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarHashChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain correct calendar hash chain.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_DataHash_free(verCtx.tempData.aggregationOutputHash);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainInputHashVerification_sigWithoutCalHashChain(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	KSI_CalendarHashChain_free(verCtx.userData.sig->calendarChain);
	verCtx.userData.sig->calendarChain = NULL;

	res = KSI_VerificationRule_CalendarHashChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain calendar hash chain", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_DataHash_free(verCtx.tempData.aggregationOutputHash);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainInputHashVerification_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-hash-chain.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarHashChainInputHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == INT_3);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_DataHash_free(verCtx.tempData.aggregationOutputHash);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainAggregationTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarHashChainAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain correct calendar hash chain.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainAggregationTime_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-chain-aggregation-time.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarHashChainAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == INT_4);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainRegistrationTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarHashChainRegistrationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain correct calendar hash chain.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainRegistrationTime_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-chain-aggregation-time.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarHashChainRegistrationTime(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == INT_5);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain correct calendar authentication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationHash_missingAutRec(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-without-calendar-authentication-record.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain contain authentication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-calendar-authentication-record-hash.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == INT_8);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain correct calendar hash chain.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationTime_missingAutRec(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-without-calendar-authentication-record.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain contain authentication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordAggregationTime_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-authentication-record-publication-time.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == INT_6);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain publication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationHash_missingPubRec(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain publication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-publication-record-publication-data-hash.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == INT_9);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain publication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationTime_missingPubRec(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain publication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordPublicationTime_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-invalid-publication-record-publication-data-time.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_SignaturePublicationRecordPublicationTime(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == INT_7);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_DocumentHashVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.documentHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_getDocumentHash(verCtx.userData.sig, &verCtx.userData.documentHash);
	CuAssert(tc, "Unable to read signature document hash", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_DocumentHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature document hash and provided hash should be equal", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_DocumentHashVerification_missingDocHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.documentHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_DocumentHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Document hash should not be provided.", res == KSI_OK && verRes.resultCode == OK && verCtx.userData.documentHash == NULL);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_DocumentHashVerification_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_MOCK_IMPRINT   "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.documentHash = NULL;

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &verCtx.userData.documentHash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && verCtx.userData.documentHash != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_DocumentHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == GEN_1);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_DataHash_free(verCtx.userData.documentHash);

#undef TEST_SIGNATURE_FILE
#undef TEST_MOCK_IMPRINT
}

static void testRule_DocumentHashVerification_rfc3161(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.documentHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_RFC3161_getInputHash(verCtx.userData.sig->rfc3161, &verCtx.userData.documentHash);
	CuAssert(tc, "Unable to read signature RFC3161 input hash", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_DocumentHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Signature RFC3161 input hash should be ok.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_DocumentHashVerification_rfc3161_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-with-rfc3161-record-ok.ksig"
#define TEST_MOCK_IMPRINT   "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.documentHash = NULL;

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &verCtx.userData.documentHash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && verCtx.userData.documentHash != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_DocumentHashVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == GEN_1);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_DataHash_free(verCtx.userData.documentHash);

#undef TEST_SIGNATURE_FILE
#undef TEST_MOCK_IMPRINT
}

static void testRule_SignatureDoesNotContainPublication(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_SignatureDoesNotContainPublication(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain publication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignatureDoesNotContainPublication_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_SignatureDoesNotContainPublication(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureAggregationChainRightLinksMatches(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain publication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_ExtendedSignatureAggregationChainRightLinksMatches_linkCountMismatch_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &verCtx.tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.tempData.extendedSig != NULL);

	res = KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == CAL_4);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureAggregationChainRightLinksMatches_rightLinksDiffer_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/signature-invalid-calendar-right-link-sig-2014-04-30.1-extended.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &verCtx.tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.tempData.extendedSig != NULL);

	res = KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == CAL_4);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_SignaturePublicationRecordExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain publication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_SignaturePublicationRecordExistence_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_SignaturePublicationRecordExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureCalendarChainRootHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain calendar hash chain.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_ExtendedSignatureCalendarChainRootHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &verCtx.tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.tempData.extendedSig != NULL);

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == CAL_1);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_CalendarHashChainDoesNotExist(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	KSI_CalendarHashChain_free(verCtx.userData.sig->calendarChain);
	verCtx.userData.sig->calendarChain = NULL;

	res = KSI_VerificationRule_CalendarHashChainDoesNotExist(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain calendar hash chain.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainDoesNotExist_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarHashChainDoesNotExist(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureCalendarChainInputHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	int res;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.extendedSig = NULL;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain calendar hash chain.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);
	KSI_DataHash_free(verCtx.tempData.aggregationOutputHash);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_ExtendedSignatureCalendarChainInputHash_nokAggrOutHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	int res;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.extendedSig = NULL;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getDocumentHash(verCtx.userData.sig, &verCtx.tempData.aggregationOutputHash);
	CuAssert(tc, "Unable to read signature document hash", res == KSI_OK && verCtx.tempData.aggregationOutputHash != NULL);

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == CAL_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_ExtendedSignatureCalendarChainInputHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.extendedSig = NULL;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &verCtx.tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.tempData.extendedSig != NULL);

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == CAL_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);
	KSI_DataHash_free(verCtx.tempData.aggregationOutputHash);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureCalendarChainAggregationTime(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	int res;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain calendar hash chain.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_ExtendedSignatureCalendarChainAggregationTime_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &verCtx.tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.tempData.extendedSig != NULL);

	res = KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == CAL_3);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_CalendarHashChainExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarHashChainExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain calendar hash chain.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainExistence_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	KSI_CalendarHashChain_free(verCtx.userData.sig->calendarChain);
	verCtx.userData.sig->calendarChain = NULL;

	res = KSI_VerificationRule_CalendarHashChainExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.",  res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarAuthenticationRecordExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain calendar authentication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordExistence_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-calendar-authentication-record-missing.ksig"

	int res;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_CalendarAuthenticationRecordExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CertificateExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
#define TEST_CERT_FILE         "resource/tlv/mock.crt"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PKITruststore *pki = NULL;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.publicationsFile = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	/* Clear default publications file from CTX. */
	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

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

	res = KSI_VerificationRule_CertificateExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature autentication record certificate not found", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
#undef TEST_CERT_FILE
}

static void testRule_CertificateExistence_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications-one-cert-one-publication-record-with-wrong-hash.tlv"
#define TEST_CERT_FILE         "resource/tlv/mock.crt"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PKITruststore *pki = NULL;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.publicationsFile = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints for email", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, NULL);
	CuAssert(tc, "Unable to set clear PKI truststrore for KSI context.", res == KSI_OK);

	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CERT_FILE));
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new PKI truststrore for KSI context.", res == KSI_OK);

	res = KSI_VerificationRule_CertificateExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == KEY_1);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
#undef TEST_CERT_FILE
}

static void testRule_CalendarAuthenticationRecordSignatureVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-06-2.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
#define TEST_CERT_FILE         "resource/tlv/mock.crt"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PKITruststore *pki = NULL;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.publicationsFile = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

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

	res = KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify calendar authentication record signature", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
#undef TEST_CERT_FILE
}

static void testRule_CalendarAuthenticationRecordSignatureVerification_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/signature-cal-auth-wrong-signing-value.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
#define TEST_CERT_FILE         "resource/tlv/mock.crt"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PKITruststore *pki = NULL;
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.publicationsFile = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

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

	res = KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == KEY_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
#undef TEST_CERT_FILE
}

static void testRule_PublicationsFileContainsSignaturePublication(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.publicationsFile = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_VerificationRule_PublicationsFileContainsSignaturePublication(&verCtx, &verRes);
	CuAssert(tc, "Publications file should contain signature publication", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFileContainsSignaturePublication_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.publicationsFile = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_VerificationRule_PublicationsFileContainsSignaturePublication(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFileContainsPublication(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.publicationsFile = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_VerificationRule_PublicationsFileContainsPublication(&verCtx, &verRes);
	CuAssert(tc, "Publications file should contain signature publication", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFileContainsPublication_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.15042014.tlv"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.publicationsFile = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_VerificationRule_PublicationsFileContainsPublication(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_ExtendingPermittedVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.extendingAllowed = true;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_ExtendingPermittedVerification(&verCtx, &verRes);
	CuAssert(tc, "Extending should be permitted", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_ExtendingPermittedVerification_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.extendingAllowed = false;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_ExtendingPermittedVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_PublicationsFilePublicationHashMatchesExtenderResponse(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.extendedSig = NULL;
	verCtx.tempData.publicationsFile = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse(&verCtx, &verRes);
	CuAssert(tc, "Extender response hash should match publications file publication hash", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFilePublicationHashMatchesExtenderResponse_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_PUBLICATIONS_FILE  "resource/tlv/publications.tlv"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &verCtx.tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.tempData.extendedSig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == PUB_1);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFilePublicationTimeMatchesExtenderResponse(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.extendedSig = NULL;
	verCtx.tempData.publicationsFile = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_VerificationRule_PublicationsFilePublicationTimeMatchesExtenderResponse(&verCtx, &verRes);
	CuAssert(tc, "Extender response time should match publications file publication time", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFilePublicationTimeMatchesExtenderResponse_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_PUBLICATIONS_FILE  "resource/tlv/publications.tlv"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &verCtx.tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.tempData.extendedSig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_VerificationRule_PublicationsFilePublicationTimeMatchesExtenderResponse(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == PUB_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFileExtendedSignatureInputHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.extendedSig = NULL;
	verCtx.tempData.publicationsFile = NULL;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash(&verCtx, &verRes);
	CuAssert(tc, "Extender response time should match publications file publication time", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);
	KSI_DataHash_free(verCtx.tempData.aggregationOutputHash);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_PublicationsFileExtendedSignatureInputHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2-extended.ksig"
#define TEST_PUBLICATIONS_FILE  "resource/tlv/publications.tlv"

	int res = KSI_OK;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	const KSI_CertConstraint certCnst[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.extendedSig = NULL;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &verCtx.tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.tempData.extendedSig != NULL);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &verCtx.tempData.publicationsFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && verCtx.tempData.publicationsFile != NULL);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, certCnst);
	CuAssert(tc, "Unable to set cert constraints", res == KSI_OK);

	res = KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == PUB_3);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);
	KSI_DataHash_free(verCtx.tempData.aggregationOutputHash);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
#undef TEST_PUBLICATIONS_FILE
}

static void testRule_UserProvidedPublicationExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationRecord *tempRec = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record.", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data.", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_VerificationRule_UserProvidedPublicationExistence(&verCtx, &verRes);
	CuAssert(tc, "User publication data should be provided", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationExistence_pubDataMissing_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_VerificationRule_UserProvidedPublicationExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationExistence_pubHashMissing_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationRecord *tempRec = NULL;
	KSI_PublicationData *tempPubData = NULL;
	KSI_Integer *pubTime = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_PublicationData_new(ctx, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to create publication data.", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record.", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &tempPubData);
	CuAssert(tc, "Unable to read signature publication data.", res == KSI_OK && tempPubData != NULL);

	res = KSI_PublicationData_getTime(tempPubData, &pubTime);
	CuAssert(tc, "Unable to read signature publication time", res == KSI_OK && pubTime != NULL);

	/* Make a virtual copy of the time object. */
	KSI_Integer_ref(pubTime);

	res = KSI_PublicationData_setTime(verCtx.userData.userPublication, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSI_VerificationRule_UserProvidedPublicationExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationData_free(verCtx.userData.userPublication);

#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationExistence_pubTimeMissing_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationRecord *tempRec = NULL;
	KSI_PublicationData *tempPubData = NULL;
	KSI_DataHash *pubHash = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_PublicationData_new(ctx, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to create publication data.", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record.", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &tempPubData);
	CuAssert(tc, "Unable to read signature publication data.", res == KSI_OK && tempPubData != NULL);

	res = KSI_PublicationData_getImprint(tempPubData, &pubHash);
	CuAssert(tc, "Unable to read signature publication hash", res == KSI_OK && pubHash != NULL);

	/* Make a virtual copy of the hash object. */
	KSI_DataHash_ref(pubHash);

	res = KSI_PublicationData_setImprint(verCtx.userData.userPublication, pubHash);
	CuAssert(tc, "Unable to set publication hash.", res == KSI_OK);

	res = KSI_VerificationRule_UserProvidedPublicationExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationData_free(verCtx.userData.userPublication);

#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationRecord *tempRec = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_VerificationRule_UserProvidedPublicationVerification(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify signature publication data", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationVerification_timeMismatch_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_TIMESTAMP      1396608816

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *pubHash = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_PublicationData *tempPubData = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &tempPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && tempPubData != NULL);

	res = KSI_PublicationData_new(ctx, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_Integer_new(ctx, TEST_TIMESTAMP, &pubTime);
	CuAssert(tc, "Unable to create publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_setTime(verCtx.userData.userPublication, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSI_PublicationData_getImprint(tempPubData, &pubHash);
	CuAssert(tc, "Unable to read signature publication hash", res == KSI_OK && pubHash != NULL);

	/* Make a virtual copy of the hash object. */
	KSI_DataHash_ref(pubHash);

	res = KSI_PublicationData_setImprint(verCtx.userData.userPublication, pubHash);
	CuAssert(tc, "Unable to set publication hash.", res == KSI_OK);

	res = KSI_VerificationRule_UserProvidedPublicationVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationData_free(verCtx.userData.userPublication);

#undef TEST_SIGNATURE_FILE
#undef TEST_TIMESTAMP
}

static void testRule_UserProvidedPublicationVerification_hashMismatch_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_MOCK_IMPRINT   "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_Integer *pubTime = NULL;
	KSI_PublicationRecord *sigPubRec = NULL;
	KSI_PublicationData *sigPubData = NULL;
	KSI_DataHash *mockPubHash = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &sigPubRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && sigPubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(sigPubRec, &sigPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && sigPubData != NULL);

	res = KSI_PublicationData_new(ctx, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_PublicationData_getTime(sigPubData, &pubTime);
	CuAssert(tc, "Unable to read signature publication time", res == KSI_OK && pubTime != NULL);

	/* Make a virtual copy of the time object. */
	KSI_Integer_ref(pubTime);

	res = KSI_PublicationData_setTime(verCtx.userData.userPublication, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &mockPubHash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && mockPubHash != NULL);

	res = KSI_PublicationData_setImprint(verCtx.userData.userPublication, mockPubHash);
	CuAssert(tc, "Unable to set publication mock hash.", res == KSI_OK);

	res = KSI_VerificationRule_UserProvidedPublicationVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_CRYPTO_FAILURE && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationData_free(verCtx.userData.userPublication);

#undef TEST_SIGNATURE_FILE
#undef TEST_MOCK_IMPRINT
}

static void testRule_UserProvidedPublicationCreationTimeVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationRecord *tempRec = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify creation time", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationCreationTimeVerification_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_TIMESTAMP      1396608816

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_Integer *mockTime = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_PublicationData_new(ctx, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_Integer_new(ctx, TEST_TIMESTAMP, &mockTime);
	CuAssert(tc, "Unable to create publication time", res == KSI_OK && mockTime != NULL);

	res = KSI_PublicationData_setTime(verCtx.userData.userPublication, mockTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationData_free(verCtx.userData.userPublication);

#undef TEST_SIGNATURE_FILE
#undef TEST_TIMESTAMP
}

static void testRule_UserProvidedPublicationHashMatchesExtendedResponse(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationRecord *tempRec = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify extender response with user publication", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_UserProvidedPublicationHashMatchesExtendedResponse_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_MOCK_IMPRINT      "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *mockPubHash = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_PublicationData *tempPubData = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &tempPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && tempPubData != NULL);

	res = KSI_PublicationData_new(ctx, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_PublicationData_getTime(tempPubData, &pubTime);
	CuAssert(tc, "Unable to read signature publication time", res == KSI_OK && pubTime != NULL);

	/* Make a virtual copy of the time object. */
	KSI_Integer_ref(pubTime);

	res = KSI_PublicationData_setTime(verCtx.userData.userPublication, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &mockPubHash);
	CuAssert(tc, "Unable to create mock hash from string", res == KSI_OK && mockPubHash != NULL);

	res = KSI_PublicationData_setImprint(verCtx.userData.userPublication, mockPubHash);
	CuAssert(tc, "Unable to set publication mock hash.", res == KSI_OK);

	res = KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == PUB_1);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationData_free(verCtx.userData.userPublication);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_MOCK_IMPRINT
}

static void testRule_UserProvidedPublicationTimeMatchesExtendedResponse(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationRecord *tempRec = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify extender response with user publication", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_UserProvidedPublicationTimeMatchesExtendedResponse_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_TIMESTAMP          1396608816

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_Integer *mockPubTime = NULL;
	KSI_PublicationRecord *tempRec = NULL;
	KSI_PublicationData *tempPubData = NULL;
	KSI_DataHash *pubHash = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.tempData.extendedSig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.tempData.extendedSig != NULL);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &tempPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && tempPubData != NULL);

	res = KSI_PublicationData_new(ctx, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_Integer_new(ctx, TEST_TIMESTAMP, &mockPubTime);
	CuAssert(tc, "Unable to create mock time", res == KSI_OK && mockPubTime != NULL);

	res = KSI_PublicationData_setTime(verCtx.userData.userPublication, mockPubTime);
	CuAssert(tc, "Unable to set publication mock time.", res == KSI_OK);

	res = KSI_PublicationData_getImprint(tempPubData, &pubHash);
	CuAssert(tc, "Unable to read signature publication hash", res == KSI_OK && pubHash != NULL);

	/* Make a virtual copy of the hash object. */
	KSI_DataHash_ref(pubHash);

	res = KSI_PublicationData_setImprint(verCtx.userData.userPublication, pubHash);
	CuAssert(tc, "Unable to set publication hash.", res == KSI_OK);

	res = KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == PUB_2);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_PublicationData_free(verCtx.userData.userPublication);
	KSI_Signature_free(verCtx.tempData.extendedSig);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_TIMESTAMP
}

static void testRule_UserProvidedPublicationExtendedSignatureInputHash(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationRecord *tempRec = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;
	verCtx.tempData.extendedSig = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify extended signature input hash", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);
	KSI_DataHash_free(verCtx.tempData.aggregationOutputHash);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testRule_UserProvidedPublicationExtendedSignatureInputHash_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_MOCK_IMPRINT      "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationRecord *tempRec = NULL;

	KSI_ERR_clearErrors(ctx);

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;
	verCtx.userData.docAggrLevel = 0;
	verCtx.tempData.extendedSig = NULL;
	verCtx.tempData.aggregationOutputHash = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &tempRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && tempRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(tempRec, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &verCtx.tempData.aggregationOutputHash);
	CuAssert(tc, "Unable to create mock hash", res == KSI_OK && verCtx.tempData.aggregationOutputHash != NULL);

	res = KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == FAIL && verRes.errorCode == PUB_3);

	KSI_Signature_free(verCtx.userData.sig);
	KSI_Signature_free(verCtx.tempData.extendedSig);
	KSI_DataHash_free(verCtx.tempData.aggregationOutputHash);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_MOCK_IMPRINT
}

CuSuite* KSITest_VerificationRules_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, testRule_AggregationChainInputHashVerification_validRfc3161);
	SUITE_ADD_TEST(suite, testRule_AggregationChainInputHashVerification_invalidRfc3161_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationChainInputHashVerification_missingRfc3161);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainConsistency);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainConsistency_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainTimeConsistency);
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainTimeConsistency_verifyErrorResult);
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
	SUITE_ADD_TEST(suite, testRule_DocumentHashVerification);
	SUITE_ADD_TEST(suite, testRule_DocumentHashVerification_missingDocHash);
	SUITE_ADD_TEST(suite, testRule_DocumentHashVerification_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_DocumentHashVerification_rfc3161);
	SUITE_ADD_TEST(suite, testRule_DocumentHashVerification_rfc3161_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_SignatureDoesNotContainPublication);
	SUITE_ADD_TEST(suite, testRule_SignatureDoesNotContainPublication_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureAggregationChainRightLinksMatches);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureAggregationChainRightLinksMatches_linkCountMismatch_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureAggregationChainRightLinksMatches_rightLinksDiffer_verifyErrorResult);
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
	SUITE_ADD_TEST(suite, testRule_CertificateExistence);
	SUITE_ADD_TEST(suite, testRule_CertificateExistence_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordSignatureVerification);
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordSignatureVerification_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsSignaturePublication);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsSignaturePublication_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsPublication);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsPublication_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_ExtendingPermittedVerification);
	SUITE_ADD_TEST(suite, testRule_ExtendingPermittedVerification_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationHashMatchesExtenderResponse);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationHashMatchesExtenderResponse_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationTimeMatchesExtenderResponse);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationTimeMatchesExtenderResponse_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileExtendedSignatureInputHash);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileExtendedSignatureInputHash_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExistence);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExistence_pubDataMissing_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExistence_pubHashMissing_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExistence_pubTimeMissing_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationVerification);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationVerification_timeMismatch_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationVerification_hashMismatch_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationCreationTimeVerification);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationCreationTimeVerification_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationHashMatchesExtendedResponse);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationHashMatchesExtendedResponse_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationTimeMatchesExtendedResponse);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationTimeMatchesExtendedResponse_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExtendedSignatureInputHash);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExtendedSignatureInputHash_verifyErrorResult);

	return suite;
}
