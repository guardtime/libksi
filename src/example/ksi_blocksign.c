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
#include <ksi/blocksigner.h>
#include <ksi/compatibility.h>
#include "ksi_common.h"

typedef char* Name;

static KSI_CTX *ksi = NULL;

static int initKsiCtx(const char *aggr, const char *publFile) {
	int res = KSI_UNKNOWN_ERROR;

	const KSI_CertConstraint pubFileCertConstr[] = {
			{ KSI_CERT_EMAIL, "publications@guardtime.com"},
			{ NULL, NULL }
	};

	/* Create new KSI context for this thread. */
	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create context.\n");
		goto cleanup;
	}

	/* Set publications file certificate contsraints. */
	res = KSI_CTX_setDefaultPubFileCertConstraints(ksi, pubFileCertConstr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to configure publications file cert constraints.\n");
		goto cleanup;
	}

	/* Set signing service. */
	res = KSI_CTX_setAggregator(ksi, aggr, NULL, NULL);
	if (res != KSI_OK) goto cleanup;

	/* Check publications file url. */
	res = KSI_CTX_setPublicationUrl(ksi, publFile);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file url.\n");
		goto cleanup;
	}

	printf("  KSI context initialization completed.\n");

cleanup:
	return res;
}

static int getHash(char *inFile, KSI_DataHash **hsh) {
	int res = KSI_UNKNOWN_ERROR;

	unsigned char buf[1024];
	size_t buf_len;
	FILE *in = NULL;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *tmp = NULL;

	in = fopen(inFile, "rb");
	if (in == NULL) {
		fprintf(stderr, "%s: Unable to open file.\n", inFile);
		res = KSI_IO_ERROR;
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
	res = KSI_DataHasher_close(hsr, &tmp);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create hash.\n");
		goto cleanup;
	}
	*hsh = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:
	if (in != NULL) fclose(in);

	KSI_DataHash_free(tmp);
	KSI_DataHasher_free(hsr);

	return res;
}

static int writeToFile(char *name, KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;

	FILE *out = NULL;
	unsigned char *raw = NULL;
	size_t raw_len;

	/* Output file. */
	out = fopen(name, "wb");
	if (out == NULL) {
		fprintf(stderr, "%s: Unable to open output file.\n", name);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	/* Serialize the signature. */
	res = KSI_Signature_serialize(sig, &raw, &raw_len);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to serialize signature.");
		goto cleanup;
	}

	/* Write the signature to file. */
	if (!fwrite(raw, 1, raw_len, out)) {
		fprintf(stderr, "Unable to write output file.\n");
		res = KSI_IO_ERROR;
		goto cleanup;
	}

cleanup:
	if (out != NULL) fclose(out);

	KSI_free(raw);

	return res;
}

static void printHelp(char *exec) {
	fprintf(stderr, "Usage:\n"
			"  %s <ksi+http://<user>:<pass>@<aggregator-uri>> <pub-file url> <in-data-file> [<in-data-file> ...] \n", exec);
}

int main(int argc, char **argv) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_BlockSigner *bs = NULL;
	KSI_LIST(KSI_BlockSignerHandle) *handleList = NULL;
	FILE *logFile = NULL;
	size_t i;
	KSI_DataHash *hsh = NULL;
	KSI_BlockSignerHandle *hndl = NULL;
	KSI_Signature *sig = NULL;

	/* Handle command line parameters */
	if (argc < 4) {
		printHelp(argv[0]);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Initialiaze KSI context. */
	res = initKsiCtx(argv[1], argv[2]);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to initialize KSI context.\n");
		goto cleanup;
	}

	/* Configure the logger. */
	res = OpenLogging(ksi, "ksi_blocksign.log", &logFile);
	if (res != KSI_OK) goto cleanup;

	KSI_LOG_info(ksi, "Using KSI version: '%s'.", KSI_getVersion());

	/* Create new block-signer instance. */
	res = KSI_BlockSigner_new(ksi, KSI_getHashAlgorithmByName("default"), NULL, NULL, &bs);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to create new block-signer instance.\n");
		goto cleanup;
	}

	/* Initialize a list for keeping hash-handle pairs. */
	res = KSI_BlockSignerHandleList_new(&handleList);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to create new block-signer handle map list.\n");
		goto cleanup;
	}

	/* Loop over the input files. */
	for (i = 3; i < argc; i++) {
		/* Get the hash value of the input file. */
		res = getHash(argv[i], &hsh);
		if (res != KSI_OK) {
			fprintf(stderr, "%s: Failed to calculate the hash.\n", argv[i]);
			goto cleanup;
		}

		/* Add the hash value to the block signer. */
		res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, &hndl);
		if (res != KSI_OK) {
			fprintf(stderr, "%s: Unable to add data hash to the block signer.\n", argv[i]);
			goto cleanup;
		}

		res = KSI_BlockSignerHandleList_append(handleList, hndl);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to append handle to the list.\n");
			goto cleanup;
		}

		/* Free the resources. */
		KSI_DataHash_free(hsh);
		hndl = NULL;
		hsh = NULL;
	}

	/* Close the block signer and sign the root value. */
	res = KSI_BlockSigner_close(bs, NULL);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to close and sign the block signer.\n");
		goto cleanup;
	}

	/* Loop over the input files again, and save the signatures. */
	for (i = 3; i < argc; i++) {
		char buf[0xffff];
		KSI_BlockSignerHandle *pHandle = NULL;

		/* Create a filename for the input signature. */
		KSI_snprintf(buf, sizeof(buf), "%s.ksig", argv[i]);

		/* Get the handle from the list. */
		res = KSI_BlockSignerHandleList_elementAt(handleList, i - 3, &pHandle);
		if (res != KSI_OK) {
			fprintf(stderr, "%s: Unable to extract the leaf handle from the list.\n", argv[i]);
			goto cleanup;
		}

		/* Extract the signature. */
		res = KSI_BlockSignerHandle_getSignature(pHandle, &sig);
		if (res != KSI_OK) {
			fprintf(stderr, "%s: Unable to extract the signature.\n", argv[i]);
			goto cleanup;
		}

		/* Save the signature to a file. */
		res = writeToFile(buf, sig);
		if (res != KSI_OK) {
			fprintf(stderr, "%s: Unable to save the signature.\n", buf);
			goto cleanup;
		}

		/* Free the resources. */
		KSI_Signature_free(sig);
		sig = NULL;
	}

	res = KSI_OK;

cleanup:

	if (logFile != NULL) fclose(logFile);

	if (res != KSI_OK && ksi != NULL) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	KSI_Signature_free(sig);
	KSI_DataHash_free(hsh);
	KSI_BlockSignerHandleList_free(handleList);
	KSI_BlockSigner_free(bs);
	KSI_CTX_free(ksi);

	return res;

}
