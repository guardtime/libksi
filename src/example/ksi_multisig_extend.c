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
#include <ksi/ksi.h>
#include <ksi/multi_signature.h>

KSI_CTX *ksi = NULL;

int main (int argc, char **argv) {
	int res;
	KSI_MultiSignature *ms = NULL;

	char *infn = NULL;
	char *outfn = NULL;
	char *uri = NULL;
	char *user = NULL;
	char *key = NULL;
	char *pub = NULL;
	unsigned char *buf = NULL;
	size_t buf_len;
	FILE *fd = NULL;
	size_t written;

	const KSI_CertConstraint pubFileCertConstr[] = {
			{ KSI_CERT_EMAIL, "publications@guardtime.com"},
			{ NULL, NULL }
	};

	if (argc != 7) {
		fprintf(stdout, "Usage:\n"
				"  %s <in> <out> <extender url> <user> <key> <pub file>\n", argv[0]);
		res = KSI_OK;
		goto cleanup;
	}

	infn = argv[1];
	outfn = argv[2];
	uri = argv[3];
	user = argv[4];
	key = argv[5];
	pub = argv[6];

	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) goto cleanup;

	res = KSI_CTX_setExtender(ksi, uri, user, key);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set extender.\n");
		goto cleanup;
	}

	res = KSI_CTX_setDefaultPubFileCertConstraints(ksi, pubFileCertConstr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to configure publications file cert constraints.\n");
		goto cleanup;
	}

	res = KSI_CTX_setPublicationUrl(ksi, pub);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set publications file url.\n");
		goto cleanup;
	}

	res = KSI_MultiSignature_fromFile(ksi, infn, &ms);
	if (res != KSI_OK) {
		fprintf(stderr, "%s: Unable to read multi signature container: %s\n", infn, KSI_getErrorString(res));
		goto cleanup;
	}

	res = KSI_MultiSignature_extend(ms);
	if (res != KSI_OK) {
		fprintf(stderr, "%s: Unable to extend multi signature container: %s.\n", infn, KSI_getErrorString(res));
		goto cleanup;
	}

	res = KSI_MultiSignature_serialize(ms, &buf, &buf_len);
	if (res != KSI_OK) {
		fprintf(stderr, "%s: Unable to serialize multi signature container: %s\n", infn, KSI_getErrorString(res));
		goto cleanup;
	}

	fd = fopen(outfn, "wb");
	if (fd == NULL) {
		fprintf(stderr, "%s: unable to open file for writing.\n", outfn);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	written = fwrite(buf, 1, buf_len, fd);
	if (written != buf_len) {
		fprintf(stderr, "%s: Error writing to file.\n", outfn);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	if (res != KSI_OK) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	if (fd != NULL) fclose(fd);
	KSI_free(buf);
	KSI_CTX_free(ksi);

	return res;
}
