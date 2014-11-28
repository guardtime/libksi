#include<stdio.h>
#include<string.h>
#include<ctype.h>

#include "cutest/CuTest.h"
#include "all_tests.h"

#include "libgen.h"

#ifndef _WIN32
#  ifdef HAVE_CONFIG_H
#    include "../src/ksi/config.h"
#  endif
#endif

#ifdef _WIN32
#  define DIR_SEP '\\'
#else
#  define DIR_SEP '/'
#endif

#ifndef UNIT_TEST_OUTPUT_XML
#  define UNIT_TEST_OUTPUT_XML "_testsuite.xml"
#endif

KSI_CTX *ctx = NULL;

extern unsigned char *KSI_NET_MOCK_response;
extern unsigned KSI_NET_MOCK_response_len;


void KSITest_setFileMockResponse(CuTest *tc, const char *fileName) {
	FILE *f = NULL;

	/* Read response from file. */
	f = fopen(fileName, "rb");
	CuAssert(tc, "Unable to open sample response file", f != NULL);

	KSI_NET_MOCK_response_len = (unsigned)fread(KSI_NET_MOCK_response, 1, MOCK_BUFFER_SIZE, f);
	fclose(f);
}

static void escapeStr(const char *str, CuString *escaped) {
	int p;
	static const char *replIndex = "<>&\"'";
	static const char *repl[] = { "lt", "gt", "amp", "quot", "#39"};
	while (*str) {
		/* Find the index of current char. */
		p = (int)(strchr(replIndex, *str) - replIndex);
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

	for (i = 0 ; i < tmp->count ; ++i) {
		CuTest* testCase = tmp->list[i];
		CuSuiteAdd(suite, testCase);
		tmp->list[i] = NULL;
	}

	CuSuiteDelete(tmp);
}

static CuSuite* initSuite(void) {
	CuSuite *suite = CuSuiteNew();

	addSuite(suite, KSITest_CTX_getSuite);
	addSuite(suite, KSITest_RDR_getSuite);
	addSuite(suite, KSITest_TLV_getSuite);
	addSuite(suite, KSITest_TLV_Sample_getSuite);
	addSuite(suite, KSITest_Hash_getSuite);
	addSuite(suite, KSITest_HMAC_getSuite);
	addSuite(suite, KSITest_NET_getSuite);
	addSuite(suite, KSITest_HashChain_getSuite);
	addSuite(suite, KSITest_Signature_getSuite);
	addSuite(suite, KSITest_Publicationsfile_getSuite);
	addSuite(suite, KSITest_Truststore_getSuite);
	
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
	int res;
	CuSuite* suite = initSuite();
	FILE *logFile = NULL;

	res = KSI_CTX_new(&ctx);
	if(ctx == NULL || res != KSI_OK){
		fprintf(stderr, "Error: Unable to init KSI context (%s)!\n", KSI_getErrorString(res));
		exit(EXIT_FAILURE);
	}

	logFile = fopen("test.log", "w");
	if (logFile == NULL) {
		fprintf(stderr, "Unable to open log file.\n");
		exit(EXIT_FAILURE);
	}

	KSI_CTX_setLoggerCallback(ctx, KSI_LOG_StreamLogger, logFile);
	KSI_CTX_setLogLevel(ctx, KSI_LOG_DEBUG);
	CuSuiteRun(suite);

	printStats(suite);

	writeXmlReport(suite);

	failCount = suite->failCount;

	CuSuiteDelete(suite);

	if (logFile != NULL) {
		fclose(logFile);
	}

	KSI_CTX_free(ctx);

	return failCount;
}

int KSITest_memcmp(void *ptr1, void *ptr2, size_t len) {
	int res;
	size_t i;
	res = memcmp(ptr1, ptr2, len);
	if (res) {
		printf("> ");
		for (i = 0; i < len; i++)
			printf("%02x", *((unsigned char *)ptr1 + i));
		printf("\n< ");
		for (i = 0; i < len; i++)
			printf("%02x", *((unsigned char *)ptr2 + i));
		printf("\n");
	}
	return res;
}

int KSITest_DataHash_fromStr(KSI_CTX *ctx, const char *hexstr, KSI_DataHash **hsh) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *tmp = NULL;
	unsigned char raw[0xff];
	unsigned len = 0;

	res = KSITest_decodeHexStr(hexstr, raw, sizeof(raw), &len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHash_fromImprint(ctx, raw, len, &tmp);
	if (res != KSI_OK) goto cleanup;

	*hsh = tmp;
	tmp = NULL;

cleanup:

	KSI_DataHash_free(tmp);

	return res;
}

int KSITest_decodeHexStr(const char *hexstr, unsigned char *buf, unsigned buf_size, unsigned *buf_length) {
	int res = KSI_UNKNOWN_ERROR;
	int i = 0;
	unsigned len = 0;
	int count = 0;

	if (hexstr != NULL) {
		while (hexstr[i]) {
			char chr = hexstr[i++];
			if (isspace(chr)) continue;

			if (len >= buf_size) {
				res = KSI_BUFFER_OVERFLOW;
				goto cleanup;
			}

			if (count == 0) {
				buf[len] = 0;
			}

			chr = (char)tolower(chr);
			if (isdigit(chr)) {
				buf[len] = (unsigned char)(buf[len] << 4) | (unsigned char)(chr - '0');
			} else if (chr >= 'a' && chr <= 'f') {
				buf[len] = (unsigned char)(buf[len] << 4) | (unsigned char)(chr - 'a' + 10);
			} else {
				res = KSI_INVALID_FORMAT;
				goto cleanup;
			}

			if (++count > 1) {
				count = 0;
				len++;
			}
		}
	}
	if (count != 0) {
		/* Single char hex value. */
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	*buf_length = len;

	res = KSI_OK;

cleanup:

	return res;
}

static const char *projectRoot = NULL;
static char pathBuffer[2048];

const char *getFullResourcePath(const char* resource){
	snprintf(pathBuffer, sizeof(pathBuffer), "%s%c%s", projectRoot, DIR_SEP, resource);
	return pathBuffer;
}

int main(int argc, char** argv) {
	if (argc != 2) {
		printf("Usage:\n %s <path to test root>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	projectRoot = argv[1];
	return RunAllTests();
}
