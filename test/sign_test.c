#include "../src/ksi_internal.h"

int main(void) {
	KSI_CTX *ctx;
	int res;

	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sign = NULL;

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

	res = KSI_sign(hsh, &sign);
	if (res != KSI_OK) {
		printf("Unable to sign %d.\n", res);
		KSI_ERR_statusDump(ctx, stderr);
		goto cleanup;
	}


cleanup:

	KSI_Signature_free(sign);
	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);

	KSI_CTX_free(ctx);

	KSI_global_cleanup();

	return 0;

}
