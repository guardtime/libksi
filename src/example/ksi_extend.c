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
#include <ksi/net_http.h>
#include "ksi_common.h"

int main(int argc, char **argv) {
	KSI_CTX *ksi = NULL;
	int res;
	FILE *out = NULL;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	unsigned char *raw = NULL;
	size_t raw_len;
	unsigned count;
	FILE *logFile = NULL;

	const KSI_CertConstraint pubFileCertConstr[] = {
			{ KSI_CERT_EMAIL, "publications@guardtime.com"},
			{ NULL, NULL }
	};

	if (argc != 5) {
		printf("Usage:\n"
				"  %s <signature> <extended> <extender uri> <pub-file url>\n", argv[0]);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Init KSI context. */
	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to init KSI context.\n");
		goto cleanup;
	}

	/* Configure the logger. */
	res = OpenLogging(ksi, "ksi_extend.log", &logFile);
	if (res != KSI_OK) goto cleanup;


	res = KSI_CTX_setDefaultPubFileCertConstraints(ksi, pubFileCertConstr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to configure publications file cert constraints.\n");
		goto cleanup;
	}

	KSI_LOG_info(ksi, "Using KSI version: '%s'", KSI_getVersion());

	res = KSI_CTX_setExtender(ksi, argv[3], "anon", "anon");
	if (res != KSI_OK) goto cleanup;

	res = KSI_CTX_setPublicationUrl(ksi, argv[4]);
	if (res != KSI_OK) goto cleanup;

	/* Read the signature. */
	res = KSI_Signature_fromFile(ksi, argv[1], &sig);
	if (res != KSI_OK) {
		KSI_ERR_statusDump(ksi, stdout);
		fprintf(stderr, "Unable to read signature from '%s'.\n", argv[1]);
		goto cleanup;
	}

	/* Make sure the signature is ok. */
	res = KSI_verifySignature(ksi, sig);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to verify signature.\n");
		KSI_ERR_statusDump(ksi, stderr);
		goto cleanup;
	}

	/* Extend the signature. */
	res = KSI_extendSignature(ksi, sig, &ext);
	if (res != KSI_OK) {
		if (res == KSI_EXTEND_NO_SUITABLE_PUBLICATION) {
			printf("No suitable publication to extend to.\n");
			goto cleanup;
		}
		fprintf(stderr, "Unable to extend signature.\n");
		KSI_ERR_statusDump(ksi, stderr);
		goto cleanup;
	}

	/* To be extra sure, lets verify the extended signature. */
	res = KSI_verifySignature(ksi, ext);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to verify the extended signature.\n");
		KSI_ERR_statusDump(ksi, stderr);
		goto cleanup;
	}

	/* Serialize the extended signature. */
	res = KSI_Signature_serialize(ext, &raw, &raw_len);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to serialize extended signature.\n");
		goto cleanup;
	}

	/* Open output file. */
	out = fopen(argv[2], "wb");
	if (out == NULL) {
		fprintf(stderr, "Unable to open output file '%s'.\n", argv[2]);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	count = (unsigned) fwrite(raw, 1, raw_len, out);
	if (count != raw_len) {
		fprintf(stderr, "Failed to write output file.\n");
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	printf("Signature extended.");

cleanup:

	if (logFile != NULL) fclose(logFile);
	if (out != NULL) fclose(out);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);
	KSI_free(raw);
	KSI_CTX_free(ksi);

	return res;
}
