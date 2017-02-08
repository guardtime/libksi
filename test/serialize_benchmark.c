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

#if KSI_AGGREGATION_PDU_VERSION == 2
#	define	TEST_RESOURCE_AGGR_VER "v2"
#else
#	define	TEST_RESOURCE_AGGR_VER "v1"
#endif

static size_t parseCount = 1000000;

int main() {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ksi = NULL;
	unsigned char raw[0xffff];
	size_t len;
	FILE *f = NULL;
	time_t start;
	time_t end;
	size_t count = 0;
	KSI_AggregationPdu *pdu = NULL;
	unsigned char *serialized = NULL;
	size_t serialized_len;

	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create KSI context.\n");
		goto cleanup;
	}

	f = fopen("test/resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response.tlv", "rb");
	if (f == NULL) {
		fprintf(stderr, "Unable to open input.\n");
		goto cleanup;
	}

	len = fread(raw, 1, sizeof(raw), f);

	printf("Len = %llu\n", (unsigned long long) len);

	res = KSI_AggregationPdu_parse(ksi, raw, len, &pdu);
	if (res != KSI_OK) {
		KSI_ERR_statusDump(ksi, stderr);
		fprintf(stderr, "Failed to parse PDU.\n");
		goto cleanup;
	}

	time(&start);

	for (count = 0; count < parseCount; count++) {
		res = KSI_AggregationPdu_serialize(pdu, &serialized, &serialized_len);
		if (res != KSI_OK) {
			KSI_ERR_statusDump(ksi, stderr);
			fprintf(stderr, "Failed to serialize PDU.\n");
			goto cleanup;
		}

		KSI_free(serialized);
		serialized = NULL;

	}

	time(&end);

	printf("Serialized %llu PDUs in %lld seconds. (one in %0.2f ms)\n", (unsigned long long)parseCount, (unsigned long long)end - start, (double)(end - start) * 1000 / parseCount);

	res = KSI_OK;

cleanup:

	KSI_free(serialized);
	KSI_AggregationPdu_free(pdu);
	KSI_CTX_free(ksi);
	if (f != NULL) fclose(f);

	return res;

}
