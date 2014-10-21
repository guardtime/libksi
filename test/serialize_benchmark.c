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
	KSI_AggregationPdu *pdu = NULL;
	unsigned char *serialized = NULL;
	unsigned serialized_len;

	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create KSI context.\n");
		goto cleanup;
	}

	f = fopen("test/resource/tlv/ok-sig-2014-07-01.1-aggr_response.tlv", "rb");
	if (f == NULL) {
		fprintf(stderr, "Unable to open input.\n");
		goto cleanup;
	}

	len = fread(raw, 1, sizeof(raw), f);

	printf("Len = %d\n", len);

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
