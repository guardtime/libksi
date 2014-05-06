#include "../src/ksi_internal.h"

int main(int argc, char **argv) {
	KSI_CTX *ctx;
	int res;

	FILE *f = NULL;

	KSI_Signature *sign = NULL;
	KSI_Signature *ext = NULL;
	const char *fileName = NULL;
	unsigned char *serialized = NULL;
	int serialized_len = 0;

	if (argc != 2) {
		printf("Usage\n  %s <signature file>\n\n", *argv);
		goto cleanup;
	}

	fileName = argv[1];

	res = KSI_global_init();
	if (res != KSI_OK) goto cleanup;

	res = KSI_CTX_new(&ctx);
	if (res != KSI_OK) {
		printf("Unable to create context.\n");
		goto cleanup;
	}

	res = KSI_Signature_fromFile(ctx, fileName, &sign);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to open signature file %s\n", fileName);
		goto cleanup;
	}

	res = KSI_Signature_extend(sign, NULL, &ext);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to extend %d.\n", res);
		KSI_ERR_statusDump(ctx, stderr);
		goto cleanup;
	}

	res = KSI_Signature_serialize(ext, &serialized, &serialized_len);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to serialize extended signature.");
		goto cleanup;
	}

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Serialized", serialized, serialized_len);

cleanup:

	if (f != NULL) fclose(f);

	KSI_free(serialized);
	KSI_Signature_free(sign);
	KSI_Signature_free(ext);

	KSI_CTX_free(ctx);

	KSI_global_cleanup();

	return 0;

}
