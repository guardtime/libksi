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
#include "ksi_common.h"

typedef char* Name;

KSI_DEFINE_LIST(Name)
KSI_IMPLEMENT_LIST(Name, NULL)

typedef struct {
	KSI_DataHash *hsh;

	KSI_BlockSignerHandle *bsHandle;
	NameList *names;
} BlockSignerHandlePair;

static void BlockSignerHandlePair_free(BlockSignerHandlePair *p) {
	if (p != NULL) {
		KSI_DataHash_free(p->hsh);
		KSI_BlockSignerHandle_free(p->bsHandle);
		NameList_free(p->names);
		KSI_free(p);
	}
}

static int BlockSignerHandlePair_new(KSI_DataHash *hsh, BlockSignerHandlePair **p) {
	int res = KSI_UNKNOWN_ERROR;
	BlockSignerHandlePair *tmp = NULL;

	tmp = KSI_malloc(sizeof(BlockSignerHandlePair));
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->hsh = hsh;
	tmp->bsHandle = NULL;
	res = NameList_new(&tmp->names);
	if (res != KSI_OK) goto cleanup;

	*p = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	BlockSignerHandlePair_free(tmp);

	return res;
}

KSI_DEFINE_LIST(BlockSignerHandlePair)
KSI_IMPLEMENT_LIST(BlockSignerHandlePair, BlockSignerHandlePair_free)

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

static int getHash(KSI_CTX *ksi, char *inFile, KSI_DataHash **hsh) {
	int res = KSI_UNKNOWN_ERROR;

	unsigned char buf[1024];
	size_t buf_len;
	FILE *in = NULL;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *tmp = NULL;

	in = fopen(inFile, "rb");
	if (in == NULL) {
		fprintf(stderr, "Unable to open input file '%s'\n", inFile);
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

static int checkHashExist(KSI_DataHash *hsh, BlockSignerHandlePairList *handleMap, BlockSignerHandlePair **pair) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	for (i = 0; i < BlockSignerHandlePairList_length(handleMap); i++) {
		BlockSignerHandlePair *tmp = NULL;

		res = BlockSignerHandlePairList_elementAt(handleMap, i, &tmp);
		if (res != KSI_OK) goto cleanup;

		if (tmp != NULL && KSI_DataHash_equals(tmp->hsh, hsh)) {
			*pair = tmp;
			break;
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int isNameInList(NameList *names, char *name) {
	size_t i;
	for (i = 0; i < NameList_length(names); i++) {
		Name *tmp = NULL;

		if (NameList_elementAt(names, i, &tmp) != KSI_OK) {
			fprintf(stderr, "Unable to extract name from list.\n");
			return 1;
		}

		if (strlen(name) == strlen((char*)(*tmp)) && !strcmp(name, (char*)(*tmp))) {
			return 1;
		}
	}
	return 0;
}

static int initMetaData(KSI_CTX *ksi, char *signer, KSI_MetaData **md) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MetaData *tmp = NULL;
	KSI_Utf8String *cId = NULL;

	res = KSI_MetaData_new(ksi, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Utf8String_new(ksi, signer, strlen(signer) + 1, &cId);
	if (res != KSI_OK) goto cleanup;

	res = KSI_MetaData_setClientId(tmp, cId);
	if (res != KSI_OK) goto cleanup;

	*md = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_MetaData_free(tmp);
	KSI_Utf8String_free(cId);

	return res;
}

static int signFiles(KSI_CTX *ksi, char *signerId, char **inFiles, int nofInFiles, KSI_BlockSigner *bs, BlockSignerHandlePairList *handleMap) {
	int res = KSI_UNKNOWN_ERROR;
	BlockSignerHandlePair *tmp = NULL;
	size_t i;
	KSI_MetaData *md = NULL;
	KSI_DataHash *hsh;

	res = initMetaData(ksi, signerId, &md);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to initialize meta data with signer id: %s.\n", signerId);
		goto cleanup;
	}

	for (i = 0; i < nofInFiles; i++) {
		BlockSignerHandlePair *pair = NULL;

		printf("  Processing file: %s.\n", inFiles[i]);

		/* Calculate hash value for the given file. */
		res = getHash(ksi, inFiles[i], &hsh);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to get hash for file: %s.\n", inFiles[i]);
			goto cleanup;
		}

		/* Check whether the hash value is already added to the blocksigner. */
		res = checkHashExist(hsh, handleMap, &pair);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to check hash for existance.\n");
			goto cleanup;
		}

		if (pair == NULL) {
			/* The hash value has not been added yet to the blocksigner */
			res = BlockSignerHandlePair_new(hsh, &tmp);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to create to handle pair.\n");
				goto cleanup;
			}
			hsh = NULL;

			res = KSI_BlockSigner_addLeaf(bs, tmp->hsh, 0, md, &tmp->bsHandle);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to add leaf to the block signer.\n");
				goto cleanup;
			}

			printf("  ... File hash added to blocksigner.\n");

			/* Keep the name for further signature storage. */
			res = NameList_append(tmp->names, (Name*)&inFiles[i]);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to add file name.\n");
				goto cleanup;
			}

			res = BlockSignerHandlePairList_append(handleMap, tmp);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to append hash-handle pair to list.\n");
				goto cleanup;
			}
			tmp = NULL;
		} else {

			/* The hash value of the file is allready present in the blocksigner.
			 * Check whether the file name is also present.
			 */
			if (!isNameInList(pair->names, inFiles[i])) {
				res = NameList_append(pair->names, (Name*)&inFiles[i]);
				if (res != KSI_OK) {
					fprintf(stderr, "Unable to add file name.\n");
					goto cleanup;
				}
				printf("  ... File with same hash but different name added to list.\n");
			} else {
				printf("  ... File with same hash and name allready present... dropped!\n");
			}
		}

		KSI_DataHash_free(hsh);
	}

	/* After all files have been processed finalize the signing procedure. */
	res = KSI_BlockSigner_close(bs, NULL);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to close the blocksigner.\n");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:
	KSI_DataHash_free(hsh);
	KSI_MetaData_free(md);

	BlockSignerHandlePair_free(tmp);

	return res;
}

static int writeToFile(char *name, KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;

	FILE *out = NULL;
	unsigned char *raw = NULL;
	size_t raw_len;
	char *sigName = KSI_malloc(sizeof(char) * (strlen(name) + 5 + 1));

	/* Compose signature file name: orig_name.ksig*/
	sprintf(sigName, "%s.ksig", name);

	/* Output file. */
	out = fopen(sigName, "wb");
	if (out == NULL) {
		fprintf(stderr, "Unable to open output file '%s'\n", sigName);
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

	printf("  ... Signature saved to %s.\n", sigName);

cleanup:
	if (out != NULL) fclose(out);

	KSI_free(sigName);
	KSI_free(raw);

	return res;
}

static int saveSignatures(KSI_CTX *ksi, BlockSignerHandlePairList *handleMap) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	KSI_Signature *sig = NULL;
	char *id = NULL;

	printf("\n  Saving locally aggregated signatures...\n");

	for (i = 0; i < BlockSignerHandlePairList_length(handleMap); i++) {
		BlockSignerHandlePair *p = NULL;
		size_t k;

		res = BlockSignerHandlePairList_elementAt(handleMap, i, &p);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to extract handle pair from list.\n");
			goto cleanup;
		}

		/* Extract the signature. */
		res = KSI_BlockSignerHandle_getSignature(p->bsHandle, &sig);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to extract signature.\n");
			goto cleanup;
		}

		/* Verify the signature. */
		res = KSI_verifySignature(ksi, sig);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to verify the extracted signature.\n");
			goto cleanup;
		}

		/* Extract the id attribution. */
		res = KSI_Signature_getSignerIdentity(sig, &id);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to extract the signer identity.\n");
			goto cleanup;
		}
		printf("  Signer id: %s\n", id);
		KSI_free(id);
		id = NULL;

		/* Save signature for every unique name. */
		for (k = 0; k < NameList_length(p->names); k++) {
			Name *name = NULL;

			res = NameList_elementAt(p->names, k, &name);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to extract name from list.\n");
				goto cleanup;
			}

			res = writeToFile((char*)(*name), sig);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to write signature to file.\n");
				goto cleanup;
			}
		}

		/* Cleanup. */
		KSI_Signature_free(sig);
		sig = NULL;
	}

	res = KSI_OK;
cleanup:
	if (id != NULL) KSI_free(id);

	KSI_Signature_free(sig);

	return res;
}

static void printHelp(char *exec) {
	fprintf(stderr, "Usage:\n"
			"  %s <signer-id> <in-data-file> [<in-data-file> ...] <aggregator-uri> <user> <pass> <pub-file url> \n", exec);
}

int main(int argc, char **argv) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *ksi = NULL;
	int nofInFiles = 0;
	KSI_BlockSigner *bs = NULL;
	KSI_LIST(BlockSignerHandlePair) *handleMap = NULL;
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
	res = OpenLogging(ksi, "ksi_blocksign.log", &logFile);
	if (res != KSI_OK) goto cleanup;

	KSI_LOG_info(ksi, "Using KSI version: '%s'", KSI_getVersion());

	/* Create new block-signer instance. */
	res = KSI_BlockSigner_new(ksi, KSI_getHashAlgorithmByName("default"), NULL, NULL, &bs);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to create new block-signer instance.\n");
		goto cleanup;
	}

	/* Initialize a list for keeping hash-handle pairs. */
	res = BlockSignerHandlePairList_new(&handleMap);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to create new block-signer handle map list.\n");
		goto cleanup;
	}

	res = signFiles(ksi, argv[1], &argv[2], nofInFiles, bs, handleMap);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to sign files.\n");
		goto cleanup;
	}

	res = saveSignatures(ksi, handleMap);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to save signatures.\n");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	if (logFile != NULL) fclose(logFile);

	if (res != KSI_OK && ksi != NULL) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	BlockSignerHandlePairList_free(handleMap);
	KSI_BlockSigner_free(bs);
	KSI_CTX_free(ksi);

	return res;

}
