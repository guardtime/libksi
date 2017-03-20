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

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "cutest/CuTest.h"
#include "all_integration_tests.h"
#include "support_tests.h"
#include "ksi/compatibility.h"

#ifndef UNIT_TEST_OUTPUT_XML
#  define UNIT_TEST_OUTPUT_XML "_testsuite.xml"
#endif

KSI_CTX *ctx = NULL;

/**
 * Configuration object for integration tests.
 */
KSITest_Conf conf;

static CuSuite* initSuite(void) {
	CuSuite *suite = CuSuiteNew();

	addSuite(suite, AggreIntegrationTests_getSuite);
	addSuite(suite, ExtIntegrationTests_getSuite);
	addSuite(suite, PubIntegrationTests_getSuite);

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

	res = KSI_CTX_setPublicationUrl(ctx, conf.publications_file_url);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file URL.\n");
		exit(EXIT_FAILURE);
	}

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, conf.testPubFileCertConstraints);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file verification constraints.\n");
		exit(EXIT_FAILURE);
	}

	logFile = fopen("integration_test.log", "w");
	if (logFile == NULL) {
		fprintf(stderr, "Unable to open log file.\n");
		exit(EXIT_FAILURE);
	}

	KSI_CTX_setLoggerCallback(ctx, KSI_LOG_StreamLogger, logFile);
	KSI_CTX_setLogLevel(ctx, KSI_LOG_DEBUG);

	KSI_CTX_setAggregator(ctx, conf.aggregator_url, conf.aggregator_user, conf.aggregator_pass);
	KSI_CTX_setExtender(ctx, conf.extender_url, conf.extender_user, conf.extender_pass);
	KSI_CTX_setConnectionTimeoutSeconds(ctx, 30);
	KSI_CTX_setTransferTimeoutSeconds(ctx, 30);

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

int main(int argc, char** argv) {
	if (argc != 2) {
		printf("Usage:\n %s <path to test root>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	initFullResourcePath(argv[1]);

	if (KSITest_Conf_load(getFullResourcePath("integrationtest.conf"), &conf)) {
		exit(EXIT_FAILURE);
	}


	return RunAllTests();
}
