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
#include "../src/ksi/signature.h"
#include "../src/ksi/ctx_impl.h"
#include "../src/ksi/net_impl.h"

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
	CuFail(tc, "Test not implemented!");
}

static void testRule_ExtendedSignatureCalendarChainRootHash(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CalendarHashChainDoesNotExist(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_ExtendedSignatureCalendarChainInputHash(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_ExtendedSignatureCalendarChainAggregationTime(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CalendarHashChainExistence(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CalendarAuthenticationRecordExistence(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_CertificateExistence(CuTest *tc) {
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
	CuFail(tc, "Test not implemented!");
}

static void testRule_UserProvidedPublicationVerification(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_UserProvidedPublicationCreationTimeVerification(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_UserProvidedPublicationHashMatchesExtendedResponse(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
}

static void testRule_UserProvidedPublicationTimeMatchesExtendedResponse(CuTest *tc) {
	CuFail(tc, "Test not implemented!");
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
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainInputHash               );
	SUITE_ADD_TEST(suite, testRule_ExtendedSignatureCalendarChainAggregationTime         );
	SUITE_ADD_TEST(suite, testRule_CalendarHashChainExistence                            );
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordExistence                 );
	SUITE_ADD_TEST(suite, testRule_CertificateExistence                                  );
	SUITE_ADD_TEST(suite, testRule_CalendarAuthenticationRecordSignatureVerification     );
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsSignaturePublication          );
	SUITE_ADD_TEST(suite, testRule_PublicationsFileContainsPublication                   );
	SUITE_ADD_TEST(suite, testRule_ExtendingPermittedVerification                        );
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationHashMatchesExtenderResponse);
	SUITE_ADD_TEST(suite, testRule_PublicationsFilePublicationTimeMatchesExtenderResponse);
	SUITE_ADD_TEST(suite, testRule_PublicationsFileExtendedSignatureInputHash            );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExistence                      );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationVerification                   );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationCreationTimeVerification       );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationHashMatchesExtendedResponse    );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationTimeMatchesExtendedResponse    );
	SUITE_ADD_TEST(suite, testRule_UserProvidedPublicationExtendedSignatureInputHash     );

	return suite;
}
