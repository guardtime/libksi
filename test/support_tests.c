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

#include "support_tests.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include <ksi/ksi.h>
#include <ksi/net_uri.h>
#include <ksi/compatibility.h>

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

int KSITest_decodeHexStr(const char *hexstr, unsigned char *buf, size_t buf_size, size_t *buf_length) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i = 0;
	size_t len = 0;
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

int KSITest_DataHash_fromStr(KSI_CTX *ctx, const char *hexstr, KSI_DataHash **hsh) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *tmp = NULL;
	unsigned char raw[0xff];
	size_t len = 0;

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

const char *KSITest_composeUri(const char *scheme, const KSITest_ServiceConf *service) {
	static char buf[2048] = {0};

	size_t len = 0;
	size_t c = 0;

	/* Set scheme. */
	c = KSI_snprintf(buf, sizeof(buf), "%s://", scheme);
	if (c == 0) return NULL; else len += c;
	/* Set credentials. */
	if (service->user != NULL && service->pass != NULL) {
		c = KSI_snprintf(buf + len, sizeof(buf) - len, "%s:%s@", service->user, service->pass);
		if (c == 0) return NULL; else len += c;
	}
	/* Set host. */
	c = KSI_snprintf(buf + len, sizeof(buf) - len, "%s", service->host);
	if (c == 0) return NULL; else len += c;
	/* Set port. */
	c = KSI_snprintf(buf + len, sizeof(buf) - len, ":%u", service->port);
	if (c == 0) return NULL; else len += c;

	return buf;
}
