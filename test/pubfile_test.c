#include "../src/ksi_internal.h"

int main(int argc, char **argv) {
	KSI_CTX *ctx;
	int res;
	KSI_KSITrustProvider *ksiTrustProvider = NULL;
	KSI_LIST(KSI_PublicationRecord) *publications = NULL;
	int i;

	const char *fileName = NULL;

	if (argc != 2) {
		printf("Usage:\n  %s <publications file>\n\n", *argv);
		goto cleanup;
	}

	fileName = argv[1];

	res = KSI_global_init();
	if (res != KSI_OK) {
		printf("KSI global init failed.");
		goto cleanup;
	}

	res = KSI_CTX_new(&ctx);
	if (res != KSI_OK) {
		printf("Unable to create context.\n");
		goto cleanup;
	}

	res = KSI_KSITrustProvider_fromFile(ctx, fileName, &ksiTrustProvider);
	if (res != KSI_OK) {
		KSI_ERR_statusDump(ctx, stdout);
		fprintf(stderr, "Unable to read publications file.\n");
		goto cleanup;
	}

	res = KSI_KSITrustProvider_getPublications(ksiTrustProvider, &publications);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to get publications from store.\n");
		goto cleanup;
	}

	for (i = 0; i < KSI_PublicationRecordList_length(publications); i++) {
		KSI_PublicationRecord *rec = NULL;
		KSI_LIST(KSI_Utf8String) *refs = NULL;
		int j;

		printf("Publication:\n");

		res = KSI_PublicationRecordList_elementAt(publications, i, &rec);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed while iterating publications list.\n");
			goto cleanup;
		}

		res = KSI_PublicationRecord_getPublicationRef(rec, &refs);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed to get publications ref list from publication record.\n");
			goto cleanup;
		}

		printf("refs@0x%x\n", refs);

		for (j = 0; j < KSI_Utf8StringList_length(refs); j++) {
			KSI_Utf8String *ref = NULL;
			res =  KSI_Utf8StringList_elementAt(refs, j, &ref);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to get publication ref.\n");
				goto cleanup;
			}

			printf("    %s\n", (char *)ref);
		}

	}

cleanup:

	KSI_KSITrustProvider_free(ksiTrustProvider);
	KSI_CTX_free(ctx);

	KSI_global_cleanup();

	return 0;

}
