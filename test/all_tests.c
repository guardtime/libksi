#include<stdio.h>
#include<string.h>

#include "../src/config.h"
#include "cutest/CuTest.h"

#include "all_tests.h"

#ifndef UNIT_TEST_OUTPUT_XML
#  define UNIT_TEST_OUTPUT_XML "_testsuite.xml"
#endif

KSI_CTX *ctx;

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

static CuSuite* initSuite(void) {
	CuSuite *suite = CuSuiteNew();

	addSuite(suite, KSI_CTX_GetSuite);
	addSuite(suite, KSI_LOG_GetSuite);
	addSuite(suite, KSI_RDR_GetSuite);
	addSuite(suite, KSI_TLV_GetSuite);
	addSuite(suite, KSI_TLV_Sample_GetSuite);
	addSuite(suite, KSI_Hash_GetSuite);

	return suite;
}

static void printStats(CuSuite *suite) {
	CuString *output = CuStringNew();
	CuSuiteDetails(suite, output);

	printf("\n\n==== TEST RESULTS ====\n\n");
	printf("%s\n", output->buffer);

	CuStringDelete(output);
}

static void writeXmlReport(CuSuite *suite) {
	CuString *xmlOutput = CuStringNew();
	FILE *f = NULL;

	createSuiteXMLSummary(suite, xmlOutput);

	f = fopen(UNIT_TEST_OUTPUT_XML, "w");
	if (f == NULL) {
		fprintf(stderr, "Unable to open '%s' for writing results.", UNIT_TEST_OUTPUT_XML);
	} else {
		fprintf(f, "%s\n", xmlOutput->buffer);
	}

	/* Cleanup. */
	if (f) fclose(f);

	CuStringDelete(xmlOutput);
}

static int RunAllTests() {
	int failCount;

	KSI_CTX_new(&ctx);

	CuSuite* suite = initSuite();
	CuSuiteRun(suite);

	printStats(suite);

	writeXmlReport(suite);

	failCount = suite->failCount;

	CuSuiteDelete(suite);

	KSI_CTX_free(ctx);

	return failCount;
}

int debug_memcmp(void *ptr1, void *ptr2, size_t len) {
	int res;
	int i;
	res = memcmp(ptr1, ptr2, len);
	if (res) {
		printf("> ");
		for (i = 0; i < len; i++)
			printf("%02x ", *((unsigned char *)ptr1 + i));
		printf("\n< ");
		for (i = 0; i < len; i++)
			printf("%02x ", *((unsigned char *)ptr2 + i));
		printf("\n");
	}
	return res;
}


int main(void) {
	return RunAllTests();
}
