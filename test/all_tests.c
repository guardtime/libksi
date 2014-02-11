#include<stdio.h>
#include<string.h>

#include "../src/config.h"
#include "cutest/CuTest.h"

#include "all_tests.h"

#ifndef HAVE_CONFIG_H
#  define UNIT_TEST_OUTPUT_XML "_testsuite.xml"
#endif

static void escapeStr(const char *str, CuString *escaped) {
	int p;
	static const char *replIndex = "<>&\"'";
	static const char *repl[] = { "lt", "gt", "amp", "quot", "#39"};
	while (*str) {
		/* Find the index of current char. */
		p = strchr(replIndex, *str) - replIndex;
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

	for (i = 0 ; i < testSuite->count ; ++i)
	{
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
			CuStringAppendFormat(summary, "\t\t<failure type=\"AssertionFailure\">%s</failure>", tmpCuStr->buffer);
			CuStringAppend(summary, "\t</testcase>\n");
		} else {
			CuStringAppend(summary, " />\n");
		}
	}
	CuStringAppend(summary, "</testsuite>\n");

	/* Cleanup */
	CuStringDelete(tmpCuStr);

}

static void addSuite(CuSuite *suite, CuSuite* (*fn)(void)) {
	int i;
	CuSuite *tmp = fn();

	for (i = 0 ; i < tmp->count ; ++i)
	{
		CuTest* testCase = tmp->list[i];
		CuSuiteAdd(suite, testCase);
		tmp->list[i] = NULL;
	}

	CuSuiteDelete(tmp);
}


static int RunAllTests() {
	int failCount;
	FILE *f = NULL;

	CuString *output = CuStringNew();
	CuString *xmlOutput = CuStringNew();

	CuSuite* suite = CuSuiteNew();

	addSuite(suite, KSI_CTX_GetSuite);
	addSuite(suite, KSI_LOG_GetSuite);
	addSuite(suite, KSI_RDR_GetSuite);

	CuSuiteRun(suite);

	CuSuiteSummary(suite, output);
	CuSuiteDetails(suite, output);

	/* Output humanreadable test result. */
	printf("%s\n", output->buffer);

	createSuiteXMLSummary(suite, xmlOutput);

	f = fopen(UNIT_TEST_OUTPUT_XML, "w");
	if (f == NULL) {
		fprintf(stderr, "Unable to open '%s' for writing results.", UNIT_TEST_OUTPUT_XML);
	} else {
		fprintf(f, "%s\n", xmlOutput->buffer);
	}

	failCount = suite->failCount;

	/* Cleanup. */
	if (f) fclose(f);

	CuStringDelete(xmlOutput);
	CuStringDelete(output);
	CuSuiteDelete(suite);

	return failCount;
}

int main(void) {
	return RunAllTests();
}
