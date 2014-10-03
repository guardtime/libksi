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

	printf("Parsed %llu signatures in %lld seconds. (one in %0.2f ms)\n", parseCount, end - start, (double)(end - start) * 1000 / parseCount);

	res = KSI_OK;

cleanup:

	KSI_Signature_free(sig);
	KSI_CTX_free(ksi);
	if (f != NULL) fclose(f);

	return res;

}
