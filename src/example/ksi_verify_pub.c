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
#include <ksi/ksi.h>

/** 
 * Global KSI context for this sigle threaded program.
 * */
static KSI_CTX *ksi = NULL;

/**
 * This function extends the signature to the given publication.
 * \param[in]	sig			Initial signature.
 * \param[in]	pubStr		Null-terminated c string of the publication.
 * \param[out]	ext			Pointer to the receiving pointer to the extended signature.
 * \return Returns KSI_OK if successful.
 */
static int extendToPublication(KSI_Signature *sig, const char *pubStr, KSI_Signature **ext) {
	int res = KSI_UNKNOWN_ERROR;

	/* Only the published data. */
	KSI_PublicationData *pubData = NULL;
	/* Published data and the references to the actual publications. */
	KSI_PublicationRecord *pubRec = NULL;

	/* Publication time. */
	KSI_Integer *pubTime = NULL;
	/* Signature signing time. */
	KSI_Integer *signTime = NULL;
	/* Parse the publications string. */
	res = KSI_PublicationData_fromBase32(ksi, pubStr, &pubData);
	if (res != KSI_OK) {
		fprintf(stderr, "Invalid publication: '%s'\n", pubStr);
		goto cleanup;
	}

	/* Verify the publication is newer than the signature. */
    res = KSI_Signature_getSigningTime(sig, &signTime);
	if (res != KSI_OK) goto cleanup;

	res = KSI_PublicationData_getTime(pubData, &pubTime);
	if (res != KSI_OK) goto cleanup;

	if (KSI_Integer_compare(signTime, pubTime) > 0) {
		fprintf(stderr, "Signature created after publication.\n");
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Create a publication record. */
	res = KSI_PublicationRecord_new(ksi, &pubRec);
	if (res != KSI_OK) goto cleanup;

	/* Set the published data value. */
	res = KSI_PublicationRecord_setPublishedData(pubRec, pubData);
	if (res != KSI_OK) goto cleanup;

	/* The pointer will be free by KSI_PublicatioinRecord_free. */
	pubData = NULL;

	/* NB! If the user wants to store the extended signature, some publication references should
 	 * be added to the publication reference. As we are going to discard the signature after
 	 * verification, the references are not important. */

	/* Extend the signature to the publication. */
	res = KSI_Signature_extend(sig, ksi, pubRec, ext);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to to extend the signature to the given publication: '%s'\n", pubStr);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	/* We can cleanup the values. */
	KSI_PublicationData_free(pubData);
	KSI_PublicationRecord_free(pubRec);

	return res;
}


int main(int argc, char **argv) {
	int res = KSI_UNKNOWN_ERROR;
	/* Signature read from the file. */
	KSI_Signature *sig = NULL;
	
	/* Signature extended to the publication. */
	KSI_Signature *ext = NULL;

	/* Hash of the data file. */
	KSI_DataHash *hsh = NULL;

	/* Hash value extracted from the signature. */
	KSI_DataHash *signHsh = NULL;

	/* Data file hasher. */
	KSI_DataHasher *hsr = NULL;

	/* Input file descriptor. */
	FILE *in = NULL;

	/* Buffer for reading the input. */
	unsigned char buf[1024];

	/* Length of the buffer content. */
	size_t buf_len;

	/* Verification info object. */
	const KSI_VerificationResult *info = NULL;

	/* File descriptor for logging. */
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

	logFile = fopen("ksi_verify.log", "w");
	if (logFile == NULL) {
		fprintf(stderr, "Unable to open log file.\n");
	}

	res = KSI_CTX_setDefaultPubFileCertConstraints(ksi, pubFileCertConstr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to configure publications file cert constraints.\n");
		goto cleanup;
	}

	/* Configure the logger. */
	KSI_CTX_setLoggerCallback(ksi, KSI_LOG_StreamLogger, logFile);
	KSI_CTX_setLogLevel(ksi, KSI_LOG_DEBUG);

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
	res = KSI_CTX_setPublicationUrl(ksi, argv[4]);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file url.\n");
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

	printf("Verifying the signature with the publication... ");
	res = extendToPublication(sig, argv[3], &ext);
	switch (res) {
		case KSI_OK:
			printf("ok\n");
			break;
		case KSI_VERIFICATION_FAILURE:
			printf("failed\n");
			break;
		default:
			printf("failed (%s)\n", KSI_getErrorString(res));
			goto cleanup;
	}

	/* Create hasher. */
	res = KSI_Signature_createDataHasher(ext, &hsr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create data hasher.\n");
		goto cleanup;
	}

	if (strcmp(argv[1], "-")) {
		in = fopen(argv[1], "rb");
		if (in == NULL) {
			fprintf(stderr, "Unable to open data file '%s'.\n", argv[1]);
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
		res = KSI_DataHasher_close(hsr, &hsh);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed to close the hashing process.\n");
			goto cleanup;
		}

		res = KSI_Signature_getDocumentHash(sig, &signHsh);
		if (res != KSI_OK) goto cleanup;

		printf("Verifying document hash... ");
		if (!KSI_DataHash_equals(hsh, signHsh)) {
			printf("Wrong document!\n");
			goto cleanup;
		}
		printf("ok\n");
	} 

	res = KSI_Signature_getVerificationResult(ext, &info);
	if (res != KSI_OK) goto cleanup;

	if (info != NULL) {
		size_t i;
		printf("Verification info:\n");
		for (i = 0; i < KSI_VerificationResult_getStepResultCount(info); i++) {
			const KSI_VerificationStepResult *result = NULL;
			const char *desc = NULL;
			res = KSI_VerificationResult_getStepResult(info, i, &result);
			if (res != KSI_OK) goto cleanup;
			printf("\t0x%02x:\t%s", KSI_VerificationStepResult_getStep(result), KSI_VerificationStepResult_isSuccess(result) ? "OK" : "FAIL");
			desc = KSI_VerificationStepResult_getDescription(result);
			if (desc && *desc) {
				printf(" (%s)", desc);
			}
			printf("\n");
		}
	}

	res = KSI_OK;

cleanup:

	if (logFile != NULL) fclose(logFile);
	if (res != KSI_OK && ksi != NULL) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	if (in != NULL) fclose(in);

	KSI_Signature_free(sig);
	KSI_Signature_free(ext);
	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
	KSI_CTX_free(ksi);

	return res;
}
