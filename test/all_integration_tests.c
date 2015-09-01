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

#include<stdio.h>
#include<string.h>
#include<ctype.h>
#include<stdlib.h>

#include "cutest/CuTest.h"
#include "all_integration_tests.h"
#include "support_tests.h"

#ifndef UNIT_TEST_OUTPUT_XML
#  define UNIT_TEST_OUTPUT_XML "_testsuite.xml"
#endif

KSI_CTX *ctx = NULL;


static CuSuite* initSuite(void) {
	CuSuite *suite = CuSuiteNew();

	addSuite(suite, AggreIntegrationTests_getSuite);
	addSuite(suite, ExtIntegrationTests_getSuite);

	return suite;
}

static int RunAllTests() {
	int failCount;
	int res;
	CuSuite* suite = initSuite();
	FILE *logFile = NULL;

	/* Create the context. */
	res = KSI_CTX_new(&ctx);
	if (ctx == NULL || res != KSI_OK){
		fprintf(stderr, "Error: Unable to init KSI context (%s)!\n", KSI_getErrorString(res));
		exit(EXIT_FAILURE);
	}

	logFile = fopen("integration_test.log", "w");
	if (logFile == NULL) {
		fprintf(stderr, "Unable to open log file.\n");
		exit(EXIT_FAILURE);
	}

	KSI_CTX_setLoggerCallback(ctx, KSI_LOG_StreamLogger, logFile);
	KSI_CTX_setLogLevel(ctx, KSI_LOG_DEBUG);

	KSI_CTX_setAggregator(ctx, aggreURL, aggreUser, aggrePass);
	KSI_CTX_setExtender(ctx, extURL, extUser, extPass);

	CuSuiteRun(suite);

	printStats(suite, "==== INTEGRATION TEST RESULTS ====");

	writeXmlReport(suite, UNIT_TEST_OUTPUT_XML);

	failCount = suite->failCount;

	CuSuiteDelete(suite);

	if (logFile != NULL) {
		fclose(logFile);
	}

	KSI_CTX_free(ctx);

	return failCount;
}

const char *aggreURL = NULL;
const char *aggreUser = NULL;
const char *aggrePass = NULL;
const char *extURL = NULL;
const char *extUser = NULL;
const char *extPass = NULL;


int main(int argc, char** argv) {
	if (argc != 8) {
		printf("Usage:\n %s <path to test root> <aggr url> <aggr user> <aggr pass> <ext url> <ext user> <ext pass>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	initFullResourcePath(argv[1]);

	aggreURL = argv[2];
	aggreUser = argv[3];
	aggrePass = argv[4];
	extURL = argv[5];
	extUser = argv[6];
	extPass = argv[7];

	return RunAllTests();
}
