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
#include "all_tests.h"
#include "../src/ksi/pkitruststore.h"
#include "../src/ksi/ksi.h"


#ifndef _WIN32
#  ifdef HAVE_CONFIG_H
#    include "../src/ksi/config.h"
#  endif
#endif

#ifndef UNIT_TEST_OUTPUT_XML
#  define UNIT_TEST_OUTPUT_XML "_testsuite.xml"
#endif

KSI_CTX *ctx = NULL;

#define TEST_DEFAULT_PUB_FILE "resource/tlv/publications.tlv"

const KSI_CertConstraint testPubFileCertConstraints[] = {
		{ KSI_CERT_EMAIL, "publications@guardtime.com"},
		{ NULL, NULL }
};


int KSITest_setDefaultPubfileAndVerInfo(KSI_CTX *ctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PKITruststore *pki = NULL;

	if (ctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_setPublicationsFile(ctx, NULL);
	if (res != KSI_OK) goto cleanup;

	res = KSI_CTX_setPublicationUrl(ctx, getFullResourcePathUri(TEST_DEFAULT_PUB_FILE));
	if (res != KSI_OK) goto cleanup;

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, testPubFileCertConstraints);
	if (res != KSI_OK) goto cleanup;

	res = KSI_CTX_setPKITruststore(ctx, NULL);
	if (res != KSI_OK) goto cleanup;

	res = KSI_PKITruststore_new(ctx, 0, &pki);
	if (res != KSI_OK) goto cleanup;

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath("resource/tlv/mock.crt"));
	if (res != KSI_OK) goto cleanup;

	res = KSI_CTX_setPKITruststore(ctx, pki);
	if (res != KSI_OK) goto cleanup;

	pki = NULL;
	res = KSI_OK;

cleanup:

	KSI_PKITruststore_free(pki);

return res;
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
	addSuite(suite, KSITest_compatibility_getSuite);
	addSuite(suite, KSITest_uriClient_getSuite);
	addSuite(suite, KSITest_multiSignature_getSuite);
	addSuite(suite, KSITest_VerificationRules_getSuite);
	addSuite(suite, KSITest_Policy_getSuite);

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

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, testPubFileCertConstraints);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file verification constraints.\n");
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

	printStats(suite, "==== TEST RESULTS ====");

	writeXmlReport(suite, UNIT_TEST_OUTPUT_XML);

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

int main(int argc, char** argv) {
	if (argc != 2) {
		printf("Usage:\n %s <path to test root>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	initFullResourcePath(argv[1]);

	return RunAllTests();
}
