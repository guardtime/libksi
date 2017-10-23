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
#include <stdlib.h>
#include <errno.h>

#include "cutest/CuTest.h"
#include "all_integration_tests.h"

#include "../src/ksi/impl/ctx_impl.h"
#include "../src/ksi/impl/net_impl.h"
#include "../src/ksi/impl/policy_impl.h"
#include "../src/ksi/impl/signature_impl.h"


extern KSI_CTX *ctx;
extern KSITest_Conf conf;

#define TEST_USER "anon"
#define TEST_PASS "anon"

#define CSV_LINE_COMMENT '#'
#define CSV_FIELD_SEP ";"

enum CsvField_en {
	TEST_CF_SIGNATURE_URI,
	TEST_CF_VERIF_STATE,
	TEST_CF_ERROR_CODE,
	TEST_CF_ERROR_MESSAGE,
	TEST_CF_INPUT_HASH_LEVEL,
	TEST_CF_AGGR_INPUT_HASH,
	TEST_CF_CAL_INPUT_HASH,
	TEST_CF_CAL_OUTPUT_HASH,
	TEST_CF_AGGR_TIME,
	TEST_CF_PUB_TIME,
	TEST_CF_PUB_STRING,
	TEST_CF_EXTEND_PERM,
	TEST_CF_EXTEND_RESPONSE,
	TEST_CF_PUBS_FILE,

	TEST_NOF_CSV_FIELDS
};

enum VerificationState_en {
	TEST_VS_UNKNOWN,
	TEST_VS_PARSER_FAILURE,
	TEST_VS_NOT_IMPL,
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

static int getUint64(const char *s, KSI_uint64_t *time) {
	long int tmp = 0;
	char *endp = NULL;

	if (s == NULL || time == NULL) return -1;

	tmp = strtol(s, &endp, 0);
	if (tmp < 0 || s == endp || errno == ERANGE) return -1;

	*time = (KSI_uint64_t)tmp;

	return 1;
}

static const char *getPath(const char *root, const char* resource) {
	static char buf[2048];
	KSI_snprintf(buf, sizeof(buf), "%s/%s", root, resource);
	return buf;
}

static const char *getPathUri(const char *root, const char* resource) {
	static char uriBuffer[2048];
	KSI_snprintf(uriBuffer, sizeof(uriBuffer), "file://%s", getPath(root, resource));
	return uriBuffer;
}

static const char *failMsg(const char *testFile, size_t line, const char *errMsg, const char *extMsg) {
	static char buf[2048];
	KSI_snprintf(buf, sizeof(buf), "%s:%d: %s", testFile, line, errMsg);
	if (extMsg) KSI_snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), " (%s)", extMsg);
	return buf;
}

static void runTests(CuTest* tc, const char *testCsvFile, const char *rootPath) {
	int res = KSI_UNKNOWN_ERROR;
	FILE *csvFile = NULL;
	unsigned int lineCount = 0;

	csvFile = fopen(getPath(rootPath, testCsvFile), "r");
	CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to open CSV file.", NULL), csvFile != NULL);

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

		res = KSI_VerificationContext_init(&context, ctx);
		CuAssert(tc, failMsg(testCsvFile, lineCount, "Verification context initialization failed.", KSI_getErrorString(res)), res == KSI_OK);

		if (fgets(line, sizeof(line), csvFile) == NULL) break;
		/* Chech if the line is commented out. */
		if (line[0] == CSV_LINE_COMMENT) goto test_cleanup;

		KSI_LOG_debug(ctx, "Test CSV (%s:%u): %s", testCsvFile, lineCount, line);

		res = csvString_toArray(line, CSV_FIELD_SEP, TEST_NOF_CSV_FIELDS, csvData);
		CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to parse CSV line.", NULL), res != -1);
		CuAssert(tc, failMsg(testCsvFile, lineCount, "No data found on CSV line.", NULL), res > 0);

		CuAssert(tc, failMsg(testCsvFile, lineCount, "Signature is not specified.", NULL), csvData[TEST_CF_SIGNATURE_URI] != NULL);

		if (csvData[TEST_CF_VERIF_STATE]) {
			if (strcmp(csvData[TEST_CF_VERIF_STATE], "not-implemented") == 0) verState = TEST_VS_NOT_IMPL;
			else if (strcmp(csvData[TEST_CF_VERIF_STATE], "parsing") == 0) verState = TEST_VS_PARSER_FAILURE;
			else {
				verState = ((policy = getPolicy(csvData[TEST_CF_VERIF_STATE])) != NULL) ? TEST_VS_POLICY : TEST_VS_UNKNOWN;
			}
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unknown verification state.", NULL), verState != TEST_VS_UNKNOWN);

			if (policy) {
				if (csvData[TEST_CF_ERROR_CODE]) {
					errCode = KSI_VerificationErrorCode_fromString(csvData[TEST_CF_ERROR_CODE]);
					CuAssert(tc, failMsg(testCsvFile, lineCount, "Unknown error code.", NULL), errCode != KSI_VER_ERR_NONE);
				}
			}
		}
		/* Skip test if it is not supported. */
		if (verState == TEST_VS_NOT_IMPL) goto test_cleanup;

		if (csvData[TEST_CF_INPUT_HASH_LEVEL]) {
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to parse input level value.", NULL), getUint64(csvData[TEST_CF_INPUT_HASH_LEVEL], &context.docAggrLevel));
		}

		if (csvData[TEST_CF_AGGR_INPUT_HASH]) {
			res = KSITest_DataHash_fromStr(ctx, csvData[TEST_CF_AGGR_INPUT_HASH], &documentHash);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to create hash from string.", NULL), res == KSI_OK && documentHash != NULL);
			context.documentHash = documentHash;
		}

		if (csvData[TEST_CF_PUB_STRING]) {
			res = KSI_PublicationData_fromBase32(ctx, csvData[TEST_CF_PUB_STRING], &userPublication);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to decode publication string.", NULL),  res == KSI_OK && userPublication != NULL);
			context.userPublication = userPublication;
		}


		if (csvData[TEST_CF_EXTEND_PERM]) {
			context.extendingAllowed = (strcmp(csvData[TEST_CF_EXTEND_PERM], "true") == 0) ? 1 : 0;
		}

		if (csvData[TEST_CF_EXTEND_RESPONSE]) {
			/* Responses are in PDU v2. */
			res = KSI_CTX_setOption(ctx, KSI_OPT_EXT_PDU_VER, (void*)KSI_PDU_VERSION_2);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to set PDU version.", KSI_getErrorString(res)), res == KSI_OK);

			/* Restart request counter. */
			ctx->netProvider->requestCount = 0;

			res = KSI_CTX_setExtender(ctx, getPathUri(rootPath, csvData[TEST_CF_EXTEND_RESPONSE]), TEST_USER, TEST_PASS);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to set extend response from file.", KSI_getErrorString(res)), res == KSI_OK);
		} else {
			/* Restore default PDU version. */
			res = KSI_CTX_setOption(ctx, KSI_OPT_EXT_PDU_VER, (void*)KSI_EXTENDING_PDU_VERSION);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to set PDU version.", KSI_getErrorString(res)), res == KSI_OK);

			res = KSI_CTX_setExtender(ctx, KSITest_composeUri("ksi+http", &conf.extender), conf.extender.user, conf.extender.pass);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to set extender url.", KSI_getErrorString(res)), res == KSI_OK);
		}

		if (csvData[TEST_CF_PUBS_FILE]) {
			res = KSI_CTX_setPublicationUrl(ctx, getPathUri(rootPath, csvData[TEST_CF_PUBS_FILE]));
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to set publications file url.", KSI_getErrorString(res)), res == KSI_OK);
		} else {
			res = KSI_CTX_setPublicationUrl(ctx, conf.pubfile.url);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to set publications file url.", KSI_getErrorString(res)), res == KSI_OK);
		}

		res = KSI_Signature_fromFileWithPolicy(ctx, getPath(rootPath, csvData[TEST_CF_SIGNATURE_URI]),
				(policy != NULL ? policy : KSI_VERIFICATION_POLICY_GENERAL), &context, &sig);
		if (res != KSI_OK) {
			if (verState == TEST_VS_POLICY) {
				/* Check if the failure is expected. */
				if (errCode != KSI_VER_ERR_NONE) {
					KSI_Signature *lastFailed = NULL;

					CuAssert(tc, failMsg(testCsvFile, lineCount, "Signature did not fail with policy based verification.", KSI_getErrorString(res)),
							policy != NULL && res == KSI_VERIFICATION_FAILURE);

					res = KSI_CTX_getLastFailedSignature(ctx, &lastFailed);
					CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to get last failed signature.", NULL), res == KSI_OK && lastFailed != NULL);

					if (errCode != lastFailed->policyVerificationResult->finalResult.errorCode) {
						KSI_LOG_debug(ctx, "Verification error code mismatch: ");
						KSI_LOG_debug(ctx, "...extpected: %s", KSI_VerificationErrorCode_toString(errCode));
						KSI_LOG_debug(ctx, "...result   : %s", KSI_VerificationErrorCode_toString(lastFailed->policyVerificationResult->finalResult.errorCode));

						CuFail(tc, failMsg(testCsvFile, lineCount, "Verification error code mismatch.", NULL));
					}

					if (csvData[TEST_CF_ERROR_MESSAGE]) {
						if (strcmp(KSI_Policy_getErrorString(errCode), csvData[TEST_CF_ERROR_MESSAGE]) != 0) {
							KSI_LOG_debug(ctx, "Verification error message mismatch: ");
							KSI_LOG_debug(ctx, "...extpected: %s", csvData[TEST_CF_ERROR_MESSAGE]);
							KSI_LOG_debug(ctx, "...result   : %s", KSI_Policy_getErrorString(errCode));

							CuFail(tc, failMsg(testCsvFile, lineCount, "Verification error message mismatch.", NULL));
						}
					}

					KSI_Signature_free(lastFailed);
					goto test_cleanup;
				} else {
					CuFail(tc, failMsg(testCsvFile, lineCount, "Unexpected error during signature verification.", NULL));
				}
			} else if (verState == TEST_VS_PARSER_FAILURE) {
				/* Signature is expected to fail. */
				goto test_cleanup;
			} else {
				CuFail(tc, failMsg(testCsvFile, lineCount, "Failed because of an unexpected error.", NULL));
			}
		} else {
			/* Verify if the signature should have been failed during the verification state. */
			if (verState == TEST_VS_POLICY) {
				CuAssert(tc, failMsg(testCsvFile, lineCount, "Signature should have failed during policy verification state.", NULL),  errCode == KSI_VER_ERR_NONE);
			} else if (verState == TEST_VS_PARSER_FAILURE) {
				CuFail(tc, failMsg(testCsvFile, lineCount, "Signature should have failed during parsing state.", NULL));
			}
		}

		/* Verify expected results. */
		if (csvData[TEST_CF_CAL_INPUT_HASH]) {
			KSI_DataHash *calInHsh = NULL;
			KSI_DataHash *aggrRootHsh = NULL;

			res = KSI_AggregationHashChainList_aggregate(sig->aggregationChainList, ctx, 0, &aggrRootHsh);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to aggregate aggregation hash chain.", KSI_getErrorString(res)), res == KSI_OK && aggrRootHsh != NULL);

			res = KSITest_DataHash_fromStr(ctx, csvData[TEST_CF_CAL_INPUT_HASH], &calInHsh);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to create hash from string", KSI_getErrorString(res)), res == KSI_OK && calInHsh != NULL);

			CuAssert(tc, failMsg(testCsvFile, lineCount, "Calendar input hash mismatch.", NULL), KSI_DataHash_equals(calInHsh, aggrRootHsh));

			KSI_DataHash_free(calInHsh);
			KSI_DataHash_free(aggrRootHsh);
		}

		if (csvData[TEST_CF_CAL_OUTPUT_HASH]) {
			KSI_DataHash *calOutHsh = NULL;
			KSI_DataHash *calRootHsh = NULL;

			res = KSITest_DataHash_fromStr(ctx, csvData[TEST_CF_CAL_OUTPUT_HASH], &calOutHsh);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to create hash from string", KSI_getErrorString(res)), res == KSI_OK && calOutHsh != NULL);

			res = KSI_CalendarHashChain_aggregate(sig->calendarChain, &calRootHsh);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to aggregate calendar hash chain.", KSI_getErrorString(res)), res == KSI_OK && calRootHsh != NULL);

			CuAssert(tc, failMsg(testCsvFile, lineCount, "Calendar input hash mismatch.", NULL), KSI_DataHash_equals(calOutHsh, calRootHsh));

			KSI_DataHash_free(calOutHsh);
			KSI_DataHash_free(calRootHsh);
		}

		if (csvData[TEST_CF_AGGR_TIME]) {
			KSI_Integer *sigAggrTime = NULL;
			KSI_uint64_t time = 0;

			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to parse aggregation time.", NULL), getUint64(csvData[TEST_CF_AGGR_TIME], &time));

			res = KSI_Signature_getSigningTime(sig, &sigAggrTime);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to get signature aggregation time.", KSI_getErrorString(res)), res == KSI_OK && sigAggrTime != NULL);

			CuAssert(tc, failMsg(testCsvFile, lineCount, "Aggregation time mismatch.", NULL), KSI_Integer_getUInt64(sigAggrTime) == time);
		}

		if (csvData[TEST_CF_PUB_TIME]) {
			KSI_Integer *sigPubTime = NULL;
			KSI_uint64_t time = 0;

			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to parse publication time.", NULL), getUint64(csvData[TEST_CF_PUB_TIME], &time));

			KSI_CalendarHashChain_getPublicationTime(sig->calendarChain, &sigPubTime);
			CuAssert(tc, failMsg(testCsvFile, lineCount, "Unable to get signature publication time.", KSI_getErrorString(res)), res == KSI_OK && sigPubTime != NULL);

			CuAssert(tc, failMsg(testCsvFile, lineCount, "Publication time mismatch.", NULL), KSI_Integer_getUInt64(sigPubTime) == time);
		}

test_cleanup:
		KSI_VerificationContext_clean(&context);
		KSI_Signature_free(sig);
		KSI_DataHash_free(documentHash);
		KSI_PublicationData_free(userPublication);
	}

	if (csvFile) fclose(csvFile);
}


static void TestPack_ValidSignatures(CuTest* tc) {
	KSI_LOG_debug(ctx, "Test pack. Test valid signatures.");
	runTests(tc, "signature-results.csv", getFullResourcePath("resource/test_pack/valid-signatures"));
}

static void TestPack_InvalidSignatures(CuTest* tc) {
	KSI_LOG_debug(ctx, "Test pack. Test invalid signatures.");
	runTests(tc, "invalid-signature-results.csv", getFullResourcePath("resource/test_pack/invalid-signatures"));
}

static void TestPack_PolicyVerification(CuTest* tc) {
	KSI_LOG_debug(ctx, "Test pack. Test policy verification.");
	runTests(tc, "policy-verification-results.csv", getFullResourcePath("resource/test_pack/policy-verification-signatures"));
}

static void TestPack_InternalPolicySignatures(CuTest* tc) {
	KSI_LOG_debug(ctx, "Test pack. Test invalid signatures.");
	runTests(tc, "internal-policy-results.csv", getFullResourcePath("resource/test_pack/internal-policy-signatures"));
}

static void postTest(void) {
	/* Restore default PDU version. */
	KSI_CTX_setOption(ctx, KSI_OPT_AGGR_PDU_VER, (void*)KSI_AGGREGATION_PDU_VERSION);
	KSI_CTX_setOption(ctx, KSI_OPT_EXT_PDU_VER, (void*)KSI_EXTENDING_PDU_VERSION);

	/* Set default publications file. */
	KSI_CTX_setPublicationUrl(ctx, conf.pubfile.url);
}

CuSuite* IntegrationTestPack_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->postTest = postTest;

	SUITE_ADD_TEST(suite, TestPack_ValidSignatures);
	SUITE_ADD_TEST(suite, TestPack_InvalidSignatures);
	SUITE_ADD_TEST(suite, TestPack_PolicyVerification);
	SUITE_ADD_TEST(suite, TestPack_InternalPolicySignatures);

	return suite;
}
