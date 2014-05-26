#include "../src/ksi_internal.h"

int main(void) {
	KSI_CTX *ctx;
	int res;

	FILE *f = NULL;

	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sign = NULL;

	unsigned char *raw;
	int raw_len;

	res = KSI_global_init();
	if (res != KSI_OK) goto cleanup;

	res = KSI_CTX_new(&ctx);
	if (res != KSI_OK) {
		printf("Unable to create context.\n");
		goto cleanup;
	}

	res = KSI_DataHasher_open(ctx, KSI_HASHALG_SHA2_256, &hsr);
	if (res != KSI_OK) {
		printf("Unable to create hasher.\n");
		goto cleanup;
	}

	res = KSI_DataHasher_add(hsr, "LAPTOP", 6);
	if (res != KSI_OK) {
		printf("Unable to add data to hasher.\n");
		goto cleanup;
	}

	res = KSI_DataHasher_close(hsr, &hsh);
	if (res != KSI_OK) {
		printf("Unable to create hash.\n");
		goto cleanup;
	}

	res = KSI_Signature_sign(ctx, hsh, &sign);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to sign %d.\n", res);
		KSI_ERR_statusDump(ctx, stderr);
		goto cleanup;
	}

	/* Save the signature */
	f = fopen("sign_test.gtsig", "wb");
	if (f == NULL) {
		fprintf(stderr, "Unable to open outputfile.\n");
		goto cleanup;
	}

	res = KSI_Signature_serialize(sign, &raw, &raw_len);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to serialize signature.");
	}

	if (!fwrite(raw, 1, raw_len, f)) {
		fprintf(stderr, "Unable to write file.\n");
		goto cleanup;
	}

	printf("File saved.\n");

cleanup:

	if (f != NULL) fclose(f);

	KSI_Signature_free(sign);
	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);

	KSI_CTX_free(ctx);

	KSI_global_cleanup();

	return 0;

}
