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
#include <ksi/multi_signature.h>

static KSI_CTX *ksi = NULL;

static int loadMultiSignature(const char *file, KSI_MultiSignature **ms) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MultiSignature *tmp = NULL;
	FILE *f = NULL;
	unsigned char *buf = NULL;
	size_t buf_size = 0;
	size_t buf_len = 0;

	f = fopen(file, "rb");
	if (f != NULL) {
		while (!feof(f)) {
			buf_size += 0xffff;
			if (buf == NULL) {
				buf = KSI_malloc(buf_size);
				if (buf == NULL) {
					res = KSI_OUT_OF_MEMORY;
					goto cleanup;
				}
			} else {
				unsigned char *tmp_buf = NULL;
				tmp_buf = KSI_malloc(buf_size);
				if (tmp_buf == NULL) {
					res = KSI_OUT_OF_MEMORY;
					goto cleanup;
				}

				memcpy(tmp_buf, buf, buf_len);
				KSI_free(buf);
				buf = tmp_buf;
			}

			buf_len = fread(buf + buf_len, 1, buf_size - buf_len, f);
		}

		res = KSI_MultiSignature_parse(ksi, buf, buf_len, &tmp);
		if (res != KSI_OK) goto cleanup;

	} else {
		/* Create a new container. */
		res = KSI_MultiSignature_new(ksi, &tmp);
		if (res != KSI_OK) goto cleanup;
	}


	*ms = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	if (f != NULL) fclose(f);
	KSI_free(buf);

	return res;
}


static int saveMultiSignature(const char *mf, KSI_MultiSignature *ms) {
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *buf = NULL;
	FILE *f = NULL;
	size_t buf_len;
	size_t written;

	res = KSI_MultiSignature_writeBytes(ms, NULL, 0, &buf_len, 0);
	if (res != KSI_OK) {
		fprintf(stderr, "%s: Unable to serialize multi signature container: %s\n", mf, KSI_getErrorString(res));
		goto cleanup;
	}

	buf = KSI_malloc(buf_len);
	if (buf == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = KSI_MultiSignature_writeBytes(ms, buf, buf_len, &buf_len, 0);
	if (res != KSI_OK) {
		fprintf(stderr, "%s: Unable to actually serialize the multi signature container (should never hapen): %s\n", mf, KSI_getErrorString(res));
		goto cleanup;
	}

	f = fopen(mf, "wb");
	if (f == NULL) {
		fprintf(stderr, "%s: Unable to open file for writing.\n", mf);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	written = fwrite(buf, buf_len, 1, f);
	if (written != 1) {
		fprintf(stderr, "%s: Unable to write multi signature.\n", mf);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_free(buf);
	return res;
}

int main(int argc, char **argv) {
	int res;
	KSI_MultiSignature *ms = NULL;
	KSI_Signature *sig = NULL;
	const char *mf = argv[1];
	size_t i;

	if (argc < 3) {
		fprintf(stdout, "Usage:\n"
				"  %s <multi sig> <uni sig> [<uni sig> ...]\n\n", argv[0]);
		return 1;
	}

	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to init KSI context.\n");
		goto cleanup;
	}

	res = loadMultiSignature(mf, &ms);
	if (res != KSI_OK) {
		fprintf(stderr, "%s: Unable to load/create multi signature container: %s\n", mf, KSI_getErrorString(res));
		goto cleanup;
	}

	for (i = 2; i < argc; i++) {
		const char *uf = argv[i];

		res = KSI_Signature_fromFile(ksi, uf, &sig);
		if (res != KSI_OK) {
			fprintf(stderr, "%s: Unable to read signature file: %s\n", uf, KSI_getErrorString(res));
			goto cleanup;
		}

		res = KSI_MultiSignature_add(ms, sig);
		if (res != KSI_OK) {
			fprintf(stderr, "%s: Unable to add signature to multi signature container: %s\n", uf, KSI_getErrorString(res));
			goto cleanup;
		}

		KSI_Signature_free(sig);
		sig = NULL;
	}

	res = saveMultiSignature(mf, ms);
	if (res != KSI_OK) {
		fprintf(stderr, "%s: Unable to save multi signature container: %s.\n", mf, KSI_getErrorString(res));
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	if (res != KSI_OK) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	KSI_MultiSignature_free(ms);
	KSI_CTX_free(ksi);

	return res;
}
