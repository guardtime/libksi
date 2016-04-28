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
#include "ksi_common.h"

int main(int argc, char **argv) {
	int res = KSI_UNKNOWN_ERROR;
	static KSI_CTX *ksi = NULL;
	KSI_Signature *sig = NULL;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_PublicationData *pubData = NULL;
	FILE *logFile = NULL;

	const KSI_CertConstraint pubFileCertConstr[] = {
			{ KSI_CERT_EMAIL, "publications@guardtime.com"},
			{ NULL, NULL }
	};

	/* Init context. */
	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to init KSI context.\n");
		goto cleanup;
	}

	/* Configure the logger. */
	res = OpenLogging(ksi, "ksi_verify_pub.log", &logFile);
	if (res != KSI_OK) goto cleanup;

	KSI_LOG_info(ksi, "Using KSI version: '%s'", KSI_getVersion());

	/* Check parameters. */
	if (argc != 6) {
		fprintf(stderr, "Usage\n"
				"  %s <data file | -> <signature> <publication-str> <extender url> <pub-file url>\n", argv[0]);
		goto cleanup;
	}

	/* Configure extender. */
	res = KSI_CTX_setExtender(ksi, argv[4], "anon", "anon");
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set extender parameters.\n");
		goto cleanup;
	}

	/* Set the publications file url. */
	res = KSI_CTX_setPublicationUrl(ksi, argv[5]);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file url.\n");
		goto cleanup;
	}

	/* Set default certificate constraints for verifying the publications file. */
	res = KSI_CTX_setDefaultPubFileCertConstraints(ksi, pubFileCertConstr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to configure publications file cert constraints.\n");
		goto cleanup;
	}

	/* Get policy for verification. */
	res = KSI_Policy_getUserProvidedPublicationBased(ksi, &policy);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to get policy.\n");
		goto cleanup;
	}

	/* Create context for verification. */
	res = KSI_VerificationContext_create(ksi, &context);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to create verification context.\n");
		goto cleanup;
	}

	printf("Reading signature... ");
	/* Read the signature. */
	res = KSI_Signature_fromFile(ksi, argv[2], &sig);
	if (res != KSI_OK) {
		printf("failed (%s)\n", KSI_getErrorString(res));
		goto cleanup;
	}
	printf("ok\n");

	/* Set signature in verification context. */
	res = KSI_VerificationContext_setSignature(context, sig);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to set signature in verification context.\n");
		goto cleanup;
	}

	/* Allow extending in verification context. */
	res = KSI_VerificationContext_setExtendingAllowed(context, 1);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to allow extending in verification context.\n");
		goto cleanup;
	}

	/* Parse the publications string. */
	res = KSI_PublicationData_fromBase32(ksi, argv[3], &pubData);
	if (res != KSI_OK) {
		fprintf(stderr, "Invalid publication: '%s'\n", argv[3]);
		goto cleanup;
	}

	/* Set user publication in verification context. */
	res = KSI_VerificationContext_setUserPublication(context, pubData);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to set user publication in verification context.\n");
		goto cleanup;
	}

	if (strcmp(argv[1], "-")) {
		/* Calculate document hash. */
		res = GetDocumentHash(argv[1], sig, &hsh);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to get document hash.\n");
			goto cleanup;
		}

		/* Set document hash in verification context. */
		res = KSI_VerificationContext_setDocumentHash(context, hsh);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed to set document hash in verification context.\n");
			goto cleanup;
		}
	}

	printf("Verifying signature...");
	res = KSI_SignatureVerifier_verify(policy, context, &result);
	if (res != KSI_OK) {
		printf("Failed to complete verification due to error 0x%x (%s)\n", res, KSI_getErrorString(res));
		goto cleanup;
	}
	else {
		switch (result->finalResult.resultCode) {
			case KSI_VER_RES_OK:
				printf("Verification successful.\n");
				break;
			case KSI_VER_RES_NA:
				printf("Verification inconclusive with code %d.\n", result->finalResult.errorCode);
				break;
			case KSI_VER_RES_FAIL:
				printf("Verification failed with code %d.\n", result->finalResult.errorCode);
				break;
			default:
				printf("Unexpected verification result.\n");
				goto cleanup;
				break;
		}
	}

	/* Print individual steps of verification. */
	res = PrintVerificationInfo(result);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to print verification info.\n");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	if (logFile != NULL) fclose(logFile);
	if (res != KSI_OK && ksi != NULL) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	/* Free resources. */
	KSI_VerificationContext_free(context);
	KSI_PolicyVerificationResult_free(result);
	KSI_DataHash_free(hsh);
	KSI_CTX_free(ksi);

	return res;
}
