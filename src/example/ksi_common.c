/*
 * Copyright 2013-2016 Guardtime, Inc.
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
#include <ksi/ksi.h>
#include <ksi/policy.h>

int OpenLogging(KSI_CTX *ksi, char *fileName, FILE **logFile) {
	int res = KSI_UNKNOWN_ERROR;
	FILE *tmp = NULL;

	if (ksi == NULL || fileName == NULL || logFile == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = fopen(fileName, "w");
	if (tmp == NULL) {
		fprintf(stderr, "Unable to open log file.\n");
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	res = KSI_CTX_setLoggerCallback(ksi, KSI_LOG_StreamLogger, tmp);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set logger callback.\n");
		goto cleanup;
	}

	res = KSI_CTX_setLogLevel(ksi, KSI_LOG_DEBUG);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set log level.\n");
		goto cleanup;
	}

	*logFile = tmp;

cleanup:

	return res;
}

int GetDocumentHash(char *fileName, KSI_Signature *sig, KSI_DataHash **hsh) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *tmp = NULL;
	KSI_DataHasher *hsr = NULL;
	FILE *in = NULL;
	unsigned char buf[1024];
	size_t buf_len;

	if (fileName == NULL || sig == NULL || hsh == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Create hasher. */
	res = KSI_Signature_createDataHasher(sig, &hsr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create data hasher.\n");
		goto cleanup;
	}

	/* Open the document for reading. */
	in = fopen(fileName, "rb");
	if (in == NULL) {
		fprintf(stderr, "Unable to open data file '%s'.\n", fileName);
		goto cleanup;
	}

	/* Calculate the hash of the document. */
	while (!feof(in)) {
		buf_len = fread(buf, 1, sizeof(buf), in);
		res = KSI_DataHasher_add(hsr, buf, buf_len);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable hash the document.\n");
			goto cleanup;
		}
	}

	/* Finalize the hash computation. */
	res = KSI_DataHasher_close(hsr, &tmp);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to close the hashing process.\n");
		goto cleanup;
	}

	*hsh = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(tmp);
	if (in != NULL) fclose(in);

	return res;
}

int PrintVerificationInfo(KSI_PolicyVerificationResult *result) {
	int res;
	size_t i;
	size_t prefix;
	char *resultName[] = {"OK", "NA", "FAIL"};

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	printf("Verification info:\n");
	for (i = 0; i < KSI_RuleVerificationResultList_length(result->ruleResults); i++) {
		KSI_RuleVerificationResult *tmp = NULL;

		res = KSI_RuleVerificationResultList_elementAt(result->ruleResults, i, &tmp);
		if (res != KSI_OK) goto cleanup;
		/* Print the rule name without the prefix. */
		if (!memcmp(tmp->ruleName, "KSI_VerificationRule_", strlen("KSI_VerificationRule_"))) {
			prefix = strlen("KSI_VerificationRule_");
		} else {
			prefix = 0;
		}
		printf("%4s in rule %s\n", resultName[tmp->resultCode], tmp->ruleName + prefix);
	}
	printf("Final result:\n");
	if (!memcmp(result->finalResult.ruleName, "KSI_VerificationRule_", strlen("KSI_VerificationRule_"))) {
		prefix = strlen("KSI_VerificationRule_");
	} else {
		prefix = 0;
	}
	printf("%4s in rule %s\n", resultName[result->finalResult.resultCode], result->finalResult.ruleName + prefix);
	res = KSI_OK;

cleanup:

	return res;
}
