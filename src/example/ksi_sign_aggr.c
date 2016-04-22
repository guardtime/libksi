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
#include <ksi/net_uri.h>

int main(int argc, char **argv) {
	KSI_CTX *ksi = NULL;
	int res = KSI_UNKNOWN_ERROR;

	FILE *in = NULL;
	FILE *out = NULL;

	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sign = NULL;

	unsigned char *raw = NULL;
	size_t raw_len;

	unsigned char buf[1024];
	size_t buf_len;

	char *signerIdentity = NULL;

	FILE *logFile = NULL;

	const KSI_CertConstraint pubFileCertConstr[] = {
			{ KSI_CERT_EMAIL, "publications@guardtime.com"},
			{ NULL, NULL }
	};

	/* Handle command line parameters */
	if (argc != 7) {
		fprintf(stderr, "Usage:\n"
				"  %s <in-data-file> <out-sign-file> <aggregator-uri> <user> <pass> <pub-file url> \n", argv[0]);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Input file */
	in = fopen(argv[1], "rb");
	if (in == NULL) {
		fprintf(stderr, "Unable to open input file '%s'\n", argv[1]);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	/* Create new KSI context for this thread. */
	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create context.\n");
		goto cleanup;
	}

	logFile = fopen("ksi_sign_aggr.log", "w");
	if (logFile == NULL) {
		fprintf(stderr, "Unable to open log file.\n");
	}

	res = KSI_CTX_setDefaultPubFileCertConstraints(ksi, pubFileCertConstr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to configure publications file cert constraints.\n");
		goto cleanup;
	}

	KSI_CTX_setLoggerCallback(ksi, KSI_LOG_StreamLogger, logFile);
	KSI_CTX_setLogLevel(ksi, KSI_LOG_DEBUG);

	KSI_LOG_info(ksi, "Using KSI version: '%s'", KSI_getVersion());

	res = KSI_CTX_setAggregator(ksi, argv[3], argv[4], argv[5]);
	if (res != KSI_OK) goto cleanup;

	/* Check publications file url. */
	res = KSI_CTX_setPublicationUrl(ksi, argv[6]);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file url.\n");
		goto cleanup;
	}

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
	res = KSI_Signature_signAggregated(ksi, hsh, 4, &sign);
//	res = KSI_createSignature(ksi, hsh, &sign);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to sign %d.\n", res);
		goto cleanup;
	}

	res = KSI_Signature_verifyAggregated(sign, ksi, 4);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to verify signature.\n");
		goto cleanup;
	}

	/* Output the signer id */
	res = KSI_Signature_getSignerIdentity(sign, &signerIdentity);
	if (res == KSI_OK) {
		printf("Signer id: %s\n", signerIdentity);
	} else {
		fprintf(stderr, "Unable to extract signer identity.\n");
	}
    
	/* Serialize the signature. */
	res = KSI_Signature_serialize(sign, &raw, &raw_len);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to serialize signature.");
		goto cleanup;
	}

	/* Output file */
	out = fopen(argv[2], "wb");
	if (out == NULL) {
		fprintf(stderr, "Unable to open input file '%s'\n", argv[2]);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	/* Write the signature file. */
	if (!fwrite(raw, 1, raw_len, out)) {
		fprintf(stderr, "Unable to write output file.\n");
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	/* Only print message when signature output is not stdout. */
	if (out != NULL) {
		printf("Signature saved.\n");
	}

	res = KSI_OK;

cleanup:

	if (logFile != NULL) fclose(logFile);

	if (res != KSI_OK && ksi != NULL) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	if (in != NULL) fclose(in);
	if (out != NULL) fclose(out);

	KSI_free(signerIdentity);

	KSI_Signature_free(sign);
	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);

	KSI_free(raw);

	KSI_CTX_free(ksi);

	return res;

}
