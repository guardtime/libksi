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


#include "support_tests.h"
#include "all_integration_tests.h"
#include "ksi/ksi.h"
#include "ksi/net_uri.h"
#include "../src/ksi/ctx_impl.h"



#define DIR_SEP '/'

int ctx_get_base_external_error(KSI_CTX *ctx) {
	char buf[1024];
	int ext_error = 0;

	if (ctx == NULL) return -1;

	if (KSI_ERR_getBaseErrorMessage(ctx, buf, sizeof(buf), NULL, &ext_error) != KSI_OK) {
		return -1;
	}

	return ext_error;
}

void addSuite(CuSuite *suite, CuSuite* (*fn)(void)) {
	int i;
	CuSuite *tmp = fn();

	for (i = 0 ; i < tmp->count ; ++i) {
		CuTest* testCase = tmp->list[i];
		CuSuiteAdd(suite, testCase);
		tmp->list[i] = NULL;
	}

	CuSuiteDelete(tmp);
}

void printStats(CuSuite *suite, const char *heding) {
	CuString *output = CuStringNew();
	CuSuiteDetails(suite, output);

	printf("\n\n%s\n\n", heding);
	printf("%s\n", output->buffer);

	CuStringDelete(output);
}



static const char *projectRoot = NULL;

const char *getFullResourcePath(const char* resource) {
	static char buf[2048];
	KSI_snprintf(buf, sizeof(buf), "%s%c%s", projectRoot, DIR_SEP, resource);
	return buf;
}

const char *getFullResourcePathUri(const char* resource) {
	static char uriBuffer[2048];
	KSI_snprintf(uriBuffer, sizeof(uriBuffer), "file://%s", getFullResourcePath(resource));
	return uriBuffer;
}

void initFullResourcePath(const char* rootDir) {
	projectRoot = rootDir;
}

static void escapeStr(const char *str, CuString *escaped) {
	long long int p;
	static const char *replIndex = "<>&\"'";
	static const char *repl[] = { "lt", "gt", "amp", "quot", "#39"};
	while (*str) {
		/* Find the index of current char. */
		p = (long long int)(strchr(replIndex, *str) - replIndex);
		/* If the character is found, use the replacement */
		if (p >= 0) {
			CuStringAppendFormat(escaped, "&%s", repl[p]);
		} else {
			CuStringAppendChar(escaped, *str);
		}
		str++;
	}
}

static void createSuiteXMLSummary(CuSuite* testSuite, CuString* summary) {
	int i;
	CuString *tmpCuStr = NULL;

	CuStringAppendFormat(summary, "<testsuite tests=\"%d\">\n", testSuite->count);

	for (i = 0 ; i < testSuite->count ; ++i) {
		CuTest* testCase = testSuite->list[i];

		/* Escape the test case name. */
		CuStringDelete(tmpCuStr);
		tmpCuStr = CuStringNew();
		escapeStr(testCase->name, tmpCuStr);

		CuStringAppendFormat(summary, "\t<testcase classname=\"CuTest\" name=\"%s\"", tmpCuStr->buffer);
		if (testCase->failed) {
			/* Escape the fault message. */
			CuStringDelete(tmpCuStr);
			tmpCuStr = CuStringNew();
			escapeStr(testCase->message, tmpCuStr);

			CuStringAppend(summary, ">\n");
			CuStringAppendFormat(summary, "\t\t<failure type=\"AssertionFailure\">%s</failure>\n", tmpCuStr->buffer);
			CuStringAppend(summary, "\t</testcase>\n");
		} else if(testCase->skip){
			CuStringDelete(tmpCuStr);
			tmpCuStr = CuStringNew();
			escapeStr(testCase->skipMessage, tmpCuStr);
			CuStringAppendFormat(tmpCuStr, " Skipped by %s.", testCase->skippedBy);

			CuStringAppend(summary, ">\n");
			CuStringAppendFormat(summary, "\t\t<skipped>%s</skipped>\n", tmpCuStr->buffer);
			CuStringAppend(summary, "\t</testcase>\n");

		}else {
			CuStringAppend(summary, " />\n");
		}
	}
	CuStringAppend(summary, "</testsuite>\n");

	/* Cleanup */
	CuStringDelete(tmpCuStr);
}

void writeXmlReport(CuSuite *suite, const char *fname) {
	CuString *xmlOutput = CuStringNew();
	FILE *f = NULL;

	createSuiteXMLSummary(suite, xmlOutput);

	f = fopen(fname, "w");
	if (f == NULL) {
		fprintf(stderr, "Unable to open '%s' for writing results.", fname);
	} else {
		fprintf(f, "%s\n", xmlOutput->buffer);
	}

	/* Cleanup. */
	if (f) fclose(f);

	CuStringDelete(xmlOutput);
}
