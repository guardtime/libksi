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
#include <ksi/pkitruststore.h>
#include <ksi/ksi.h>
#include <ksi/tlv.h>

#include "../src/ksi/ctx_impl.h"

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

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath("resource/crt/mock.crt"));
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
	addSuite(suite, KSITest_NetCommon_getSuite);
	addSuite(suite, KSITest_NetPduV1_getSuite);
	addSuite(suite, KSITest_NetPduV2_getSuite);
	addSuite(suite, KSITest_HashChain_getSuite);
	addSuite(suite, KSITest_Signature_getSuite);
	addSuite(suite, KSITest_Publicationsfile_getSuite);
	addSuite(suite, KSITest_Truststore_getSuite);
	addSuite(suite, KSITest_compatibility_getSuite);
	addSuite(suite, KSITest_uriClient_getSuite);
	addSuite(suite, KSITest_TreeBuilder_getSuite);
	addSuite(suite, KSITest_VerificationRules_getSuite);
	addSuite(suite, KSITest_Policy_getSuite);
	addSuite(suite, KSITest_versionNumber_getSuite);
	addSuite(suite, KSITest_Blocksigner_getSuite);
	addSuite(suite, KSITest_Flags_getSuite);
	addSuite(suite, KSITest_SignatureBuilder_getSuite);
	addSuite(suite, KSITest_List_getSuite);

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

	res = KSI_CTX_setAggregatorHmacAlgorithm(ctx, TEST_DEFAULT_AGGR_HMAC_ALGORITHM);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set aggregator HMAC algorithm.\n");
		exit(EXIT_FAILURE);
	}

	res = KSI_CTX_setExtenderHmacAlgorithm(ctx, TEST_DEFAULT_EXT_HMAC_ALGORITHM);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set extender HMAC algorithm.\n");
		exit(EXIT_FAILURE);
	}

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, testPubFileCertConstraints);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file verification constraints.\n");
		exit(EXIT_FAILURE);
	}

	res = KSITest_setDefaultPubfileAndVerInfo(ctx);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set default publications file.");
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

int KSITest_tlvFromFile(const char *fileName, KSI_TLV **tlv) {
	int res;
	FILE *f = NULL;
	unsigned char buf[0xffff + 4];
	size_t len;
	KSI_FTLV ftlv;

	KSI_LOG_debug(ctx, "Open TLV file: '%s'", fileName);

	f = fopen(fileName, "rb");
	if (f == NULL) {
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	res = KSI_FTLV_fileRead(f, buf, sizeof(buf), &len, &ftlv);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TLV_parseBlob(ctx, buf, len, tlv);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	if (f != NULL) fclose(f);

	return res;
}

int KSITest_CTX_clone(KSI_CTX **out) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *tmp = NULL;

	if (out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_CTX_new(&tmp);
	if (res != KSI_OK) goto cleanup;

	tmp->logLevel = ctx->logLevel;
	tmp->loggerCB = ctx->loggerCB;
	tmp->loggerCtx = ctx->loggerCtx;

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_CTX_free(tmp);

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
