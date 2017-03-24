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
#include <stdlib.h>
#include <errno.h>

#include "cutest/CuTest.h"
#include "all_integration_tests.h"
#include "../src/ksi/signature_impl.h"

extern KSI_CTX *ctx;
extern KSITest_Conf conf;

#define TEST_USER "anon"
#define TEST_PASS "anon"

#define CSV_LINE_COMMENT '#'
#define CSV_FIELD_SEP ";"

enum CsvField_en {
	TEST_CF_SIGNATURE_URI,
	TEST_CF_VER_STATE,
	TEST_CF_ERROR_CODE,
	TEST_CF_ERROR_MESSAGE,
	TEST_CF_AGGR_INPUT_HASH,
	TEST_CF_CAL_INPUT_HASH,
	TEST_CF_CAL_OUTPUT_HASH,
	TEST_CF_REG_TIME,
	TEST_CF_AGGR_TIME,
	TEST_CF_PUB_TIME,
	TEST_CF_PUB_STRING,
	TEST_CF_EXTEND_PERM,
	TEST_CF_RESOURCE_FILE,
	TEST_CF_PUBS_FILE,

	TEST_NOF_CSV_FIELDS
};

enum VerificationState_en {
	TEST_VS_UNKNOWN,
	TEST_VS_PARSER_FAILURE,
	TEST_VS_NOT_IMPL_FAILURE,
	TEST_VS_POLICY,

	TEST_NOF_VER_STATES
};

static int csvString_toArray(char *line, const char *separator, const size_t nof_fields, char **array) {
	char *p = line;
	size_t spn = 0;
	size_t i;
	int valid = 0;

	if (line == NULL || strlen(line) == 0 || nof_fields == 0 || array == NULL) return -1;

	for (i = 0; i < nof_fields; i++) {
		spn = strcspn(p, separator);
		if (spn > 0) {
			array[i] = p;
			valid++;
		}
		p += spn;
		if (p == line + strlen(line)) break;
		*p = '\0';
		p++;
	}

	if (i != nof_fields) return -1;

	return valid;
}

static const KSI_Policy *getPolicy(const char *policyName) {
	if (policyName == NULL) return NULL;

	if (strcmp("calendar", policyName) == 0) return KSI_VERIFICATION_POLICY_CALENDAR_BASED;
	else if (strcmp("key", policyName) == 0) return KSI_VERIFICATION_POLICY_KEY_BASED;
	else if (strcmp("userPublication", policyName) == 0) return KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED;
	else if (strcmp("publicationsFile", policyName) == 0) return KSI_VERIFICATION_POLICY_PUBLICATIONS_FILE_BASED;
	else if (strcmp("internal", policyName) == 0) return KSI_VERIFICATION_POLICY_INTERNAL;
	else return NULL;
}

static int getTime(const char *ts, KSI_uint64_t *time) {
	long int tmp = 0;
	char *endp = NULL;

	if (ts == NULL || time == NULL) return -1;

	tmp = strtol(ts, &endp, 0);
	if (tmp < 0 || ts == endp || errno == ERANGE) return -1;

	*time = (KSI_uint64_t)tmp;

	return 1;
}

static void runTests(CuTest* tc, const char *testCsv, const char *root) {
	int res = KSI_UNKNOWN_ERROR;
	char path[1024];
	FILE *csvFile = NULL;
	unsigned int lineCount = 0;

	res = KSI_snprintf(path, sizeof(path), "%s/%s", root, testCsv);
	CuAssert(tc, "Unable to compose path.", res != 0);

	csvFile = fopen(path, "r");
	CuAssert(tc, "Unable to open CSV file.", csvFile != NULL);

	while (!feof(csvFile)) {
		char line[1024 * 2] = {0};
		char *csvData[TEST_NOF_CSV_FIELDS] = {NULL};
		KSI_Signature *sig = NULL;
		KSI_DataHash *documentHash = NULL;
		KSI_PublicationData *userPublication = NULL;
		KSI_VerificationContext context;
		const KSI_Policy *policy = NULL;
		unsigned char verState = TEST_VS_UNKNOWN;
		KSI_VerificationErrorCode errCode = KSI_VER_ERR_NONE;

		lineCount++;

		if (fgets(line, sizeof(line), csvFile) == NULL) break;
		/* Chech if the line is commented out. */
		if (line[0] == CSV_LINE_COMMENT) continue;

		KSI_LOG_debug(ctx, "Test CSV (%s::%u): %s", testCsv, lineCount, line);

		res = csvString_toArray(line, CSV_FIELD_SEP, TEST_NOF_CSV_FIELDS, csvData);
		CuAssert(tc, "Unable to parse CSV line.", res != -1);
		CuAssert(tc, "No data found on CSV line.", res > 0);

		CuAssert(tc, "Signature is not specified.", csvData[TEST_CF_SIGNATURE_URI] != NULL);


		res = KSI_VerificationContext_init(&context, ctx);
		CuAssert(tc, "Verification context creation failed.", res == KSI_OK);

		if (csvData[TEST_CF_AGGR_INPUT_HASH]) {
			res = KSITest_DataHash_fromStr(ctx, csvData[TEST_CF_AGGR_INPUT_HASH], &documentHash);
			CuAssert(tc, "Unable to create hash from string.", res == KSI_OK && documentHash != NULL);
			context.documentHash = documentHash;
		}

		if (csvData[TEST_CF_PUB_STRING]) {
			res = KSI_PublicationData_fromBase32(ctx, csvData[TEST_CF_PUB_STRING], &userPublication);
			CuAssert(tc, "Unable to decode publication string.",  res == KSI_OK && userPublication != NULL);
			context.userPublication = userPublication;
		}

		if (csvData[TEST_CF_VER_STATE]) {
			if (strcmp(csvData[TEST_CF_VER_STATE], "not-implemented") == 0) verState = TEST_VS_NOT_IMPL_FAILURE;
			else if (strcmp(csvData[TEST_CF_VER_STATE], "parsing") == 0) verState = TEST_VS_PARSER_FAILURE;
			else {
				verState = ((policy = getPolicy(csvData[TEST_CF_VER_STATE])) != NULL) ? TEST_VS_POLICY : TEST_VS_UNKNOWN;
			}
			CuAssert(tc, "Unknown verification state.", verState != TEST_VS_UNKNOWN);

			if (policy) {
				if (csvData[TEST_CF_ERROR_CODE]) {
					errCode = KSI_VerificationErrorCode_fromString(csvData[TEST_CF_ERROR_CODE]);
				}
			}
		}

#if POLICY_TESTS_SUPPORTED
		if (csvData[TEST_CF_EXTEND_PERM]) {
			context.extendingAllowed = (strcmp(csvData[TEST_CF_EXTEND_PERM], "true") == 0) ? 1 : 0;
		}

		if (csvData[TEST_CF_RESOURCE_FILE]) {
			res = KSI_snprintf(path, sizeof(path), "%s/%s", root, csvData[TEST_CF_RESOURCE_FILE]);
			CuAssert(tc, "Unable to compose path.", res != 0);

			res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(path), TEST_USER, TEST_PASS);
			CuAssert(tc, "Unable to set extend response from file.", res == KSI_OK);
		} else {
			res = KSI_CTX_setExtender(ctx, conf.extender_url, conf.extender_user, conf.extender_pass);
			CuAssert(tc, "Unable to set extender url.", res == KSI_OK);
		}

		if (csvData[TEST_CF_PUBS_FILE]) {
			res = KSI_snprintf(path, sizeof(path), "%s/%s", root, csvData[TEST_CF_PUBS_FILE]);
			CuAssert(tc, "Unable to compose path.", res != 0);

			res = KSI_CTX_setPublicationUrl(ctx, getFullResourcePathUri(path));
			CuAssert(tc, "Unable to set publications file url.", res == KSI_OK);
		} else {
			res = KSI_CTX_setPublicationUrl(ctx, conf.publications_file_url);
			CuAssert(tc, "Unable to set publications file url.", res == KSI_OK);
		}
#endif

		res = KSI_snprintf(path, sizeof(path), "%s/%s", root, csvData[TEST_CF_SIGNATURE_URI]);
		CuAssert(tc, "Unable to compose path.", res != 0);

		res = KSI_Signature_fromFileWithPolicy(ctx, path, (policy != NULL ? policy : KSI_VERIFICATION_POLICY_GENERAL), &context, &sig);
		if (res != KSI_OK) {
			if (verState == TEST_VS_POLICY) {
				/* Check if the failure is expected. */
				if (errCode != KSI_VER_ERR_NONE) {
					KSI_Signature *lastFailed = NULL;

					CuAssert(tc, "Signature failed not with policy verification failure.", policy != NULL && res == KSI_VERIFICATION_FAILURE);

					res = KSI_CTX_getLastFailedSignature(ctx, &lastFailed);
					CuAssert(tc, "Unable to get last failed signature.", res == KSI_OK && lastFailed != NULL);

					CuAssert(tc, "Verification error code mismatch.", errCode == lastFailed->policyVerificationResult->finalResult.errorCode);

					if (csvData[TEST_CF_ERROR_MESSAGE]) {
						CuAssert(tc, "Verification error message mismatch.",
								strcmp(KSI_Policy_getErrorString(errCode), csvData[TEST_CF_ERROR_MESSAGE]) == 0);
					}

					KSI_Signature_free(lastFailed);
					continue;
				} else {
					CuFail(tc, "Unexpected error during signature verification.");
				}
			} else if (verState == TEST_VS_NOT_IMPL_FAILURE || verState == TEST_VS_PARSER_FAILURE) {
				/* Signature is expected to fail. */
				continue;
			} else {
				CuFail(tc, "Failed because of an unexpected error.");
			}
		} else {
			/* Verify if the signature should have been failed during the verification state. */
			CuAssert(tc, "Signature should have failed verification.", !(verState == TEST_VS_NOT_IMPL_FAILURE || verState == TEST_VS_PARSER_FAILURE));
		}

		/* Verify expected results. */
		if (csvData[TEST_CF_CAL_INPUT_HASH]) {
			KSI_DataHash *calInHsh = NULL;
			KSI_DataHash *aggrRootHsh = NULL;

			res = KSI_AggregationHashChainList_aggregate(sig->aggregationChainList, ctx, 0, &aggrRootHsh);
			CuAssert(tc, "Unable to aggregate aggregation hash chain.", res == KSI_OK && aggrRootHsh != NULL);

			res = KSITest_DataHash_fromStr(ctx, csvData[TEST_CF_CAL_INPUT_HASH], &calInHsh);
			CuAssert(tc, "Unable to create hash from string", res == KSI_OK && calInHsh != NULL);

			CuAssert(tc, "Calendar input hash mismatch.", KSI_DataHash_equals(calInHsh, aggrRootHsh));

			KSI_DataHash_free(calInHsh);
			KSI_DataHash_free(aggrRootHsh);
		}

		if (csvData[TEST_CF_CAL_OUTPUT_HASH]) {
			KSI_DataHash *calOutHsh = NULL;
			KSI_DataHash *calRootHsh = NULL;

			res = KSITest_DataHash_fromStr(ctx, csvData[TEST_CF_CAL_OUTPUT_HASH], &calOutHsh);
			CuAssert(tc, "Unable to create hash from string", res == KSI_OK && calOutHsh != NULL);

			res = KSI_CalendarHashChain_aggregate(sig->calendarChain, &calRootHsh);
			CuAssert(tc, "Unable to aggregate calendar hash chain.", res == KSI_OK && calRootHsh != NULL);

			CuAssert(tc, "Calendar input hash mismatch.", KSI_DataHash_equals(calOutHsh, calRootHsh));

			KSI_DataHash_free(calOutHsh);
			KSI_DataHash_free(calRootHsh);
		}

		if (csvData[TEST_CF_REG_TIME]) {
			time_t calcTime = 0;
			KSI_uint64_t time = 0;

			CuAssert(tc, "Unable to parse registration time.", getTime(csvData[TEST_CF_REG_TIME], &time));
			time /= 1000;

			res = KSI_CalendarHashChain_calculateAggregationTime(sig->calendarChain, &calcTime);
			CuAssert(tc, "Unable to calculate signature aggregation time.", res == KSI_OK && calcTime != 0);

			CuAssert(tc, "Aggregation time mismatch.", calcTime == time);
		}

		if (csvData[TEST_CF_AGGR_TIME]) {
			KSI_Integer *sigAggrTime = NULL;
			KSI_uint64_t time = 0;

			CuAssert(tc, "Unable to parse aggregation time.", getTime(csvData[TEST_CF_AGGR_TIME], &time));
			time /= 1000;

			res = KSI_Signature_getSigningTime(sig, &sigAggrTime);
			CuAssert(tc, "Unable to get signature aggregation time.", res == KSI_OK && sigAggrTime != NULL);

			CuAssert(tc, "Aggregation time mismatch.", KSI_Integer_getUInt64(sigAggrTime) == time);
		}

		if (csvData[TEST_CF_PUB_TIME]) {
			KSI_Integer *sigPubTime = NULL;
			KSI_uint64_t time = 0;

			CuAssert(tc, "Unable to parse publication time.", getTime(csvData[TEST_CF_PUB_TIME], &time));
			time /= 1000;

			KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &sigPubTime);
			CuAssert(tc, "Unable to get signature publication time.", res == KSI_OK && sigPubTime != NULL);

			CuAssert(tc, "Publication time mismatch.", KSI_Integer_getUInt64(sigPubTime) == time);
		}

		KSI_VerificationContext_clean(&context);
		KSI_Signature_free(sig);
		KSI_DataHash_free(documentHash);
		KSI_PublicationData_free(userPublication);
	}

	if (csvFile) fclose(csvFile);
}


static void TestPack_ValidSignatures(CuTest* tc) {
	KSI_LOG_debug(ctx, "Test pack. Test valid signatures.");
	runTests(tc, "signature-results.csv",
			getFullResourcePath("resource/test_pack/valid-signatures"));
}

static void TestPack_InvalidSignatures(CuTest* tc) {
	KSI_LOG_debug(ctx, "Test pack. Test invalid signatures.");
	runTests(tc, "invalid-signature-results.csv",
			getFullResourcePath("resource/test_pack/invalid-signatures"));
}

static void TestPack_PolicyVerification(CuTest* tc) {
	KSI_LOG_debug(ctx, "Test pack. Test policy verification.");
	runTests(tc, "policy-verification-results.csv",
			getFullResourcePath("resource/test_pack/policy-verification-signatures"));
}

CuSuite* IntegrationTestPack_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestPack_ValidSignatures);
	SUITE_ADD_TEST(suite, TestPack_InvalidSignatures);
	SUITE_SKIP_TEST(suite, TestPack_PolicyVerification, "Max", "Not fully supported.");

	return suite;
}

