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

static void testRule_AggregationChainInputHashVerification(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_AggregationHashChainConsistency(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_AggregationHashChainTimeConsistency(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CalendarHashChainInputHashVerification(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CalendarHashChainAggregationTime(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CalendarHashChainRegistrationTime(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CalendarAuthenticationRecordAggregationHash(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CalendarAuthenticationRecordAggregationTime(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_SignaturePublicationRecordPublicationHash(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_SignaturePublicationRecordPublicationTime(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_DocumentHashVerification(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_SignatureDoesNotContainPublication(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_ExtendedSignatureAggregationChainRightLinksMatches(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_SignaturePublicationRecordExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_OK;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;

	res = KSI_VerificationRule_SignaturePublicationRecordExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain publication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureCalendarChainRootHash(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CalendarHashChainDoesNotExist(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	KSI_CalendarHashChain_free(sig->calendarChain);
	sig->calendarChain = NULL;

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;

	res = KSI_VerificationRule_CalendarHashChainDoesNotExist(&verCtx, &verRes);
	CuAssert(tc, "Signature should not contain calendar hash chain.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainDoesNotExist_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_OK;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;

	res = KSI_VerificationRule_CalendarHashChainDoesNotExist(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_ExtendedSignatureCalendarChainInputHash(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_ExtendedSignatureCalendarChainAggregationTime(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CalendarHashChainExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;

	res = KSI_VerificationRule_CalendarHashChainExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain calendar hash chain.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarHashChainExistence_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	KSI_CalendarHashChain_free(sig->calendarChain);
	sig->calendarChain = NULL;

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;

	res = KSI_VerificationRule_CalendarHashChainExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned.",  res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-06-2.ksig"

	int res;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;

	res = KSI_VerificationRule_CalendarAuthenticationRecordExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature should contain calendar authentication record.", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CalendarAuthenticationRecordExistence_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/signature-calendar-authentication-record-missing.ksig"

	int res;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;

	res = KSI_VerificationRule_CalendarAuthenticationRecordExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_CertificateExistence(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
#if 0
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-06-2.ksig"
//#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"
#define TEST_CERT_FILE         "resource/tlv/mock.crt"

	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PKITruststore *pki = NULL;
	const KSI_CertConstraint arr[] = {
		{KSI_CERT_EMAIL, "publications@guardtime.com"},
		{NULL, NULL}
	};

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setPublicationUrl(ctx, getFullResourcePathUri(TEST_PUBLICATIONS_FILE));
	CuAssert(tc, "Unable to set pubfile URI.", res == KSI_OK);

	/* Clear default publications file from CTX. */
	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	CuAssert(tc, "Unable to clear default pubfile.", res == KSI_OK);

	/* Configure expected PKI cert and constraints for pub. file. */
	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new PKI truststrore for KSI context.", res == KSI_OK);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CERT_FILE));
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
	CuAssert(tc, "Unable to set OID for email", res == KSI_OK);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;
	verCtx.tempData.publicationsFile = NULL;
	res = KSI_VerificationRule_CertificateExistence(&verCtx, &verRes);
	CuAssert(tc, "Signature autentication record certificate not found", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(sig);
	KSI_PublicationsFile_free(verCtx.tempData.publicationsFile);

#undef TEST_CERT_FILE
#undef TEST_PUBLICATIONS_FILE
#undef TEST_SIGNATURE_FILE
#endif
}

static void testRule_CertificateExistence_verifyErrorResult(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CalendarAuthenticationRecordSignatureVerification(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_PublicationsFileContainsSignaturePublication(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_PublicationsFileContainsPublication(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_ExtendingPermittedVerification(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_PublicationsFilePublicationHashMatchesExtenderResponse(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_PublicationsFilePublicationTimeMatchesExtenderResponse(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_PublicationsFileExtendedSignatureInputHash(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_UserProvidedPublicationExistence(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationData *pubData = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_PublicationData_new(ctx, &pubData);
	CuAssert(tc, "Unable to create publication data.", res == KSI_OK && pubData != NULL);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;
	verCtx.userData.userPublication = pubData;

	KSI_VerificationRule_UserProvidedPublicationExistence(&verCtx, &verRes);
	CuAssert(tc, "User publication data should be provided", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(sig);
	KSI_PublicationData_free(pubData);

#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationExistence_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;
	verCtx.userData.userPublication = NULL;

	KSI_VerificationRule_UserProvidedPublicationExistence(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationData *pubData = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *pubHash = NULL;
	KSI_PublicationRecord *sigPubRec = NULL;
	KSI_PublicationData *sigPubData = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getPublicationRecord(sig, &sigPubRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && sigPubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(sigPubRec, &sigPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && sigPubData != NULL);

	res = KSI_PublicationData_getTime(sigPubData, &pubTime);
	CuAssert(tc, "Unable to read signature publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_getImprint(sigPubData, &pubHash);
	CuAssert(tc, "Unable to read signature publication hash", res == KSI_OK && pubHash != NULL);

	res = KSI_PublicationData_new(ctx, &pubData);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && pubData != NULL);

	res = KSI_PublicationData_setTime(pubData, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSI_PublicationData_setImprint(pubData, pubHash);
	CuAssert(tc, "Unable to set publication hash.", res == KSI_OK);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;
	verCtx.userData.userPublication = pubData;

	res = KSI_VerificationRule_UserProvidedPublicationVerification(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify signature publication data", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(sig);
	KSI_PublicationData_free(pubData);

#undef TEST_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationVerification_timeMismatch_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_TIMESTAMP      1396608816

	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationData *pubData = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *pubHash = NULL;
	KSI_PublicationRecord *sigPubRec = NULL;
	KSI_PublicationData *sigPubData = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getPublicationRecord(sig, &sigPubRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && sigPubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(sigPubRec, &sigPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && sigPubData != NULL);

	res = KSI_Integer_new(ctx, TEST_TIMESTAMP, &pubTime);
	CuAssert(tc, "Unable to create publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_getImprint(sigPubData, &pubHash);
	CuAssert(tc, "Unable to read signature publication hash", res == KSI_OK && pubHash != NULL);

	res = KSI_PublicationData_new(ctx, &pubData);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && pubData != NULL);

	res = KSI_PublicationData_setTime(pubData, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSI_PublicationData_setImprint(pubData, pubHash);
	CuAssert(tc, "Unable to set publication hash.", res == KSI_OK);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;
	verCtx.userData.userPublication = pubData;

	res = KSI_VerificationRule_UserProvidedPublicationVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(sig);
	KSI_Integer_free(pubTime);
	KSI_PublicationData_free(pubData);

#undef TEST_SIGNATURE_FILE
#undef TEST_TIMESTAMP
}

static void testRule_UserProvidedPublicationVerification_hashMismatch_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_DATA_HASH_NOK  "AAAAAA-CT5VGY-AAPUCF-L3EKCC-NRSX56-AXIDFL-VZJQK4-WDCPOE-3KIWGB-XGPPM3-O5BIMW-REOVR4"

	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationData *pubData = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_PublicationRecord *sigPubRec = NULL;
	KSI_PublicationData *sigPubData = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getPublicationRecord(sig, &sigPubRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && sigPubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(sigPubRec, &sigPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && sigPubData != NULL);

	res = KSI_PublicationData_getTime(sigPubData, &pubTime);
	CuAssert(tc, "Unable to read signature publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_fromBase32(ctx, TEST_DATA_HASH_NOK, &pubData);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && pubData != NULL);

	res = KSI_PublicationData_setTime(pubData, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;
	verCtx.userData.userPublication = pubData;

	res = KSI_VerificationRule_UserProvidedPublicationVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_CRYPTO_FAILURE && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(sig);
	KSI_PublicationData_free(pubData);

#undef TEST_SIGNATURE_FILE
#undef TEST_DATA_HASH_NOK
}

static void testRule_UserProvidedPublicationCreationTimeVerification(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_Signature *extSig = NULL;
	KSI_PublicationData *pubData = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_PublicationRecord *extSigPubRec = NULL;
	KSI_PublicationData *extSigPubData = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_EXT_SIGNATURE_FILE), &extSig);
	CuAssert(tc, "Unable to read extended signature from file.", res == KSI_OK && extSig != NULL);

	res = KSI_Signature_getPublicationRecord(extSig, &extSigPubRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && extSigPubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(extSigPubRec, &extSigPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && extSigPubData != NULL);

	res = KSI_PublicationData_getTime(extSigPubData, &pubTime);
	CuAssert(tc, "Unable to read signature publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_new(ctx, &pubData);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && pubData != NULL);

	res = KSI_PublicationData_setTime(pubData, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;
	verCtx.userData.userPublication = pubData;

	res = KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify signature publication data", res == KSI_OK && verRes.resultCode == OK);

	KSI_Signature_free(sig);
	KSI_Signature_free(extSig);
	KSI_PublicationData_free(pubData);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_SIGNATURE_FILE
}

static void testRule_UserProvidedPublicationCreationTimeVerification_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_TIMESTAMP      1396608816

	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *sig = NULL;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_PublicationData *pubData = NULL;
	KSI_Integer *pubTime = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Integer_new(ctx, 1396608816, &pubTime);
	CuAssert(tc, "Unable to create publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_new(ctx, &pubData);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && pubData != NULL);

	res = KSI_PublicationData_setTime(pubData, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	verCtx.ctx = ctx;
	verCtx.userData.sig = sig;
	verCtx.userData.userPublication = pubData;

	res = KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification(&verCtx, &verRes);
	CuAssert(tc, "Wrong error result returned", res == KSI_OK && verRes.resultCode == NA && verRes.errorCode == GEN_2);

	KSI_Signature_free(sig);
	KSI_PublicationData_free(pubData);

#undef TEST_SIGNATURE_FILE
#undef TEST_TIMESTAMP
}

static void testRule_UserProvidedPublicationHashMatchesExtendedResponse(CuTest *tc) {
#define TEST_SIGNATURE_FILE    "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"
#define TEST_EXT_RESPONSE_FILE "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_MOCK_IMPRINT      "01db27c0db0aebb8d3963c3a720985cedb600f91854cdb1e45ad631611c39284dd"

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *pubHash = NULL;
	KSI_DataHash *mockPubHash = NULL;
	KSI_PublicationRecord *sigPubRec = NULL;
	KSI_PublicationData *sigPubData = NULL;

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &sigPubRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && sigPubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(sigPubRec, &sigPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && sigPubData != NULL);

	res = KSI_PublicationData_getTime(sigPubData, &pubTime);
	CuAssert(tc, "Unable to read signature publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_getImprint(sigPubData, &pubHash);
	CuAssert(tc, "Unable to read signature publication hash", res == KSI_OK && pubHash != NULL);

	res = KSI_PublicationData_new(ctx, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_PublicationData_setTime(verCtx.userData.userPublication, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSI_PublicationData_setImprint(verCtx.userData.userPublication, pubHash);
	CuAssert(tc, "Unable to set publication hash.", res == KSI_OK);

	res = KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify extender response with user publication", res == KSI_OK && verRes.resultCode == OK);

	res = KSITest_DataHash_fromStr(ctx, TEST_MOCK_IMPRINT, &mockPubHash);
	CuAssert(tc, "Unable to create mock hash", res == KSI_OK && mockPubHash != NULL);

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
#define TEST_TIMESTAMP         1396608816

	int res = KSI_UNKNOWN_ERROR;
	VerificationContext verCtx;
	KSI_RuleVerificationResult verRes = {OK, GEN_1};
	KSI_Integer *pubTime = NULL;
	KSI_Integer *mockPubTime = NULL;
	KSI_DataHash *pubHash = NULL;
	KSI_PublicationRecord *sigPubRec = NULL;
	KSI_PublicationData *sigPubData = NULL;

	verCtx.ctx = ctx;
	verCtx.userData.sig = NULL;
	verCtx.userData.userPublication = NULL;
	verCtx.tempData.extendedSig = NULL;

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &verCtx.userData.sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && verCtx.userData.sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extender file URI.", res == KSI_OK);

	res = KSI_Signature_getPublicationRecord(verCtx.userData.sig, &sigPubRec);
	CuAssert(tc, "Unable to read signature publication record", res == KSI_OK && sigPubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(sigPubRec, &sigPubData);
	CuAssert(tc, "Unable to read signature publication data", res == KSI_OK && sigPubData != NULL);

	res = KSI_PublicationData_getTime(sigPubData, &pubTime);
	CuAssert(tc, "Unable to read signature publication time", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationData_getImprint(sigPubData, &pubHash);
	CuAssert(tc, "Unable to read signature publication hash", res == KSI_OK && pubHash != NULL);

	res = KSI_PublicationData_new(ctx, &verCtx.userData.userPublication);
	CuAssert(tc, "Unable to create publication data", res == KSI_OK && verCtx.userData.userPublication != NULL);

	res = KSI_PublicationData_setTime(verCtx.userData.userPublication, pubTime);
	CuAssert(tc, "Unable to set publication time.", res == KSI_OK);

	res = KSI_PublicationData_setImprint(verCtx.userData.userPublication, pubHash);
	CuAssert(tc, "Unable to set publication hash.", res == KSI_OK);

	res = KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse(&verCtx, &verRes);
	CuAssert(tc, "Failed to verify extender response with user publication", res == KSI_OK && verRes.resultCode == OK);

	res = KSI_Integer_new(ctx, TEST_TIMESTAMP, &mockPubTime);
	CuAssert(tc, "Unable to create mock time", res == KSI_OK && mockPubTime != NULL);

	res = KSI_PublicationData_setTime(verCtx.userData.userPublication, mockPubTime);
	CuAssert(tc, "Unable to set publication mock time.", res == KSI_OK);

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
	CuFail(tc, "Test not implemented!");
}

CuSuite* KSITest_VerificationRules_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, testRule_AggregationChainInputHashVerification                 );
	SUITE_ADD_TEST(suite, testRule_AggregationHashChainTimeConsistency                   );
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainInputHashVerification                );
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainAggregationTime                      );
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainRegistrationTime                     );
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordAggregationHash           );
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordAggregationTime           );
	SUITE_ADD_TEST(suite, testRule_SignaturePublicationRecordPublicationHash             );
	SUITE_ADD_TEST(suite, testRule_SignaturePublicationRecordPublicationTime             );
	SUITE_ADD_TEST(suite, testRule_DocumentHashVerification                              );
	SUITE_ADD_TEST(suite, testRule_SignatureDoesNotContainPublication                    );
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureAggregationChainRightLinksMatches    );
	SUITE_ADD_TEST(suite, testRule_SignaturePublicationRecordExistence                   );
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainRootHash                );
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainDoesNotExist                         );
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainDoesNotExist_verifyErrorResult       );
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainInputHash               );
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainAggregationTime         );
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainExistence                            );
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainExistence_verifyErrorResult          );
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordExistence                 );
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordExistence_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_CertificateExistence                                  );
	SUITE_ADD_TEST(suite, testRule_CertificateExistence_verifyErrorResult                );
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordSignatureVerification     );
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsSignaturePublication          );
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsPublication                   );
	SUITE_ADD_TEST(suite, testRule_ExtendingPermittedVerification                        );
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationHashMatchesExtenderResponse);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationTimeMatchesExtenderResponse);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileExtendedSignatureInputHash            );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExistence                      );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExistence_verifyErrorResult    );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationVerification                   );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationVerification_timeMismatch_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationVerification_hashMismatch_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationCreationTimeVerification       );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationCreationTimeVerification_verifyErrorResult);
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationHashMatchesExtendedResponse    );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationTimeMatchesExtendedResponse    );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExtendedSignatureInputHash     );

	return suite;
}
