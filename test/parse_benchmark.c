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

static size_t parseCount = 1000000;

int main() {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ksi = NULL;
	unsigned char raw[0xffff];
	unsigned len;
	FILE *f = NULL;
	time_t start;
	time_t end;
	size_t count = 0;
	KSI_Signature *sig = NULL;

	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create KSI context.\n");
		goto cleanup;
	}

	f = fopen("test/resource/tlv/ok-sig-2014-04-30.1.ksig", "rb");
	if (f == NULL) {
		fprintf(stderr, "Unable to open input.\n");
		goto cleanup;
	}

	len = fread(raw, 1, sizeof(raw), f);

	printf("Len = %d\n", len);

	time(&start);

	for (count = 0; count < parseCount; count++) {
		res = KSI_Signature_parse(ksi, raw, len, &sig);
		if (res != KSI_OK) {
			KSI_ERR_statusDump(ksi, stderr);
			fprintf(stderr, "Failed to parse signature.\n");
			goto cleanup;
		}

		KSI_Signature_free(sig);
		sig = NULL;

	}

	time(&end);

	printf("Parsed %llu signatures in %lld seconds. (one in %0.2f ms)\n", (unsigned long long)parseCount, (unsigned long long)end - start, (double)(end - start) * 1000 / parseCount);

	res = KSI_OK;

cleanup:

	KSI_Signature_free(sig);
	KSI_CTX_free(ksi);
	if (f != NULL) fclose(f);

	return res;

}
