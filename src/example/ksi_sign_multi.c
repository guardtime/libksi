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
#include <ksi/net_uri.h>
#include <ksi/multi_signature.h>
#include "ksi_common.h"

static void printHelp(char *exec) {
	fprintf(stderr, "Usage:\n"
			"  %s <in-data-file> [<in-data-file> ...] <out-sign-file> <aggregator-uri> <user> <pass> <pub-file url> \n", exec);
}

static int initKsiCtx(char **data, KSI_CTX **ksi) {
	int res = KSI_UNKNOWN_ERROR;

	const KSI_CertConstraint pubFileCertConstr[] = {
			{ KSI_CERT_EMAIL, "publications@guardtime.com"},
			{ NULL, NULL }
	};

	/* Create new KSI context for this thread. */
	res = KSI_CTX_new(ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create context.\n");
		goto cleanup;
	}

	/* Set publications file certificate contsraints. */
	res = KSI_CTX_setDefaultPubFileCertConstraints(*ksi, pubFileCertConstr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to configure publications file cert constraints.\n");
		goto cleanup;
	}

	/* Set signing service. */
	res = KSI_CTX_setAggregator(*ksi, data[0], data[1], data[2]);
	if (res != KSI_OK) goto cleanup;

	/* Check publications file url. */
	res = KSI_CTX_setPublicationUrl(*ksi, data[3]);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file url.\n");
		goto cleanup;
	}

	printf("  KSI context initialization completed.\n");

cleanup:
	return res;
}

static int signFile(KSI_CTX *ksi, char *inFile, KSI_Signature **sign) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_Signature *tmp = NULL;
	char *signerIdentity = NULL;
	unsigned char buf[1024];
	size_t buf_len;
	FILE *in = NULL;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;

	in = fopen(inFile, "rb");
	if (in == NULL) {
		fprintf(stderr, "Unable to open input file '%s'\n", inFile);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	printf("  Signing file: %s\n", inFile);

	/* Create a data hasher using default algorithm. */
	res = KSI_DataHasher_open(ksi, KSI_getHashAlgorithmByName("default"), &hsr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create hasher.\n");
		goto cleanup;
	}

	/* Read the input file and calculate the hash of its contents. */
	while (!feof(in)) {
		buf_len = fread(buf, 1, sizeof(buf), in);

		/* Add  next block to the calculation. */
		res = KSI_DataHasher_add(hsr, buf, buf_len);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to add data to hasher.\n");
			goto cleanup;
		}
	}

	/* Close the data hasher and retreive the data hash. */
	res = KSI_DataHasher_close(hsr, &hsh);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create hash.\n");
		goto cleanup;
	}

	/* Sign the data hash. */
	res = KSI_createSignature(ksi, hsh, &tmp);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to sign %d.\n", res);
		goto cleanup;
	}

	res = KSI_verifySignature(ksi, tmp);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to verify signature.\n");
		goto cleanup;
	}

	/* Output the signer id */
	res = KSI_Signature_getSignerIdentity(tmp, &signerIdentity);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to extract signer identity.\n");
	}
	if (signerIdentity != NULL) {
		printf("  Signer id: %s\n", signerIdentity);
	}

	*sign = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:
	if (in != NULL) fclose(in);

	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);

	KSI_free(signerIdentity);

	return res;
}

static int loadMultiSignature(KSI_CTX *ksi, char **inFiles, int nofInFiles, KSI_MultiSignature **ms) {
	int res = KSI_UNKNOWN_ERROR;

	int i;
	KSI_Signature *sign = NULL;

	res = KSI_MultiSignature_new(ksi, ms);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create an empty multi-signature container.\n");
		goto cleanup;
	}

	for (i = 0; i < nofInFiles; i++) {
		/* Sign the input file. */
		res = signFile(ksi, inFiles[i], &sign);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to create signature from %s.\n", inFiles[i]);
			goto cleanup;
		}

		/* Add the uni-signature to the multi signature container.  */
		res = KSI_MultiSignature_add(*ms, sign);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to add signature to multi-signature container.\n");
			goto cleanup;
		}

		printf("  Signature added to multi-signature container.\n");

		KSI_Signature_free(sign);
		sign = NULL;
	}

cleanup:

	KSI_Signature_free(sign);

	return res;
}

static int saveMultiSignature(KSI_MultiSignature *ms, char *outFile) {
	int res = KSI_UNKNOWN_ERROR;

	FILE *out = NULL;

	unsigned char *raw = NULL;
	size_t raw_len;

	/* Output file. */
	out = fopen(outFile, "wb");
	if (out == NULL) {
		fprintf(stderr, "Unable to open output file '%s'\n", outFile);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	/* Serialize the multi-signature container. */
	res = KSI_MultiSignature_serialize(ms, &raw, &raw_len);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to serialize multi-signature.");
		goto cleanup;
	}

	/* Write the multi-signature file. */
	if (!fwrite(raw, 1, raw_len, out)) {
		fprintf(stderr, "Unable to write output file.\n");
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	printf("  Multi-signature saved to %s.\n", outFile);

cleanup:

	KSI_free(raw);

	return res;
}

int main(int argc, char **argv) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *ksi = NULL;
	int nofInFiles = 0;
	KSI_MultiSignature *msign = NULL;
	FILE *logFile = NULL;

	/* Handle command line parameters */
	if (argc < 7) {
		printHelp(argv[0]);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	nofInFiles = argc - 6;

	/* Initialiaze KSI context. */
	res = initKsiCtx(&(argv[nofInFiles + 2]), &ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to initialize KSI context.\n");
		goto cleanup;
	}

	/* Configure the logger. */
	res = OpenLogging(ksi, "ksi_sign_multi.log", &logFile);
	if (res != KSI_OK) goto cleanup;

	KSI_LOG_info(ksi, "Using KSI version: '%s'", KSI_getVersion());

	/* Sign the files and create multi-signature container. */
	res = loadMultiSignature(ksi, &argv[1], nofInFiles, &msign);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to initialize multi-signature.\n");
		goto cleanup;
	}

	/* Write the multi-signature to file. */
	res = saveMultiSignature(msign, argv[nofInFiles + 1]);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to save multi-signature to file.\n");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	if (logFile != NULL) fclose(logFile);

	if (res != KSI_OK && ksi != NULL) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	KSI_MultiSignature_free(msign);

	KSI_CTX_free(ksi);

	return res;

}
