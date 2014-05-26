#include <time.h>

#include "../src/ksi_internal.h"



static int printCerts(KSI_PublicationsFile *pubFile) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(KSI_CertificateRecord) *certRecList = NULL;
	int i;
	unsigned char *raw = NULL;
	int len = 0;

	printf("[certificates]\n");

	res = KSI_PublicationsFile_getCertificates(pubFile, &certRecList);
	if (res != KSI_OK) goto cleanup;

	for (i = 0; i < KSI_CertificateRecordList_length(certRecList); i++) {
		KSI_CertificateRecord *certRec = NULL;
		KSI_PKICertificate *cert = NULL;
		int j;

		printf("cert-dummy-%d=file%d.der\n", i, i);

		res = KSI_CertificateRecordList_elementAt(certRecList, i, &certRec);
		if (res != KSI_OK) goto cleanup;

		res = KSI_CertificateRecord_getCert(certRec, &cert);
		if (res != KSI_OK) goto cleanup;

		res = KSI_PKICertificate_serialize(cert, &raw, &len);
		if (res != KSI_OK) goto cleanup;

/*		for (j = 0; j < len; j++) {
			printf("%02x", raw[j]);
			if (j + 1 < len && (j + 1) % 60 == 0) printf("\n");
		}

		printf("\n\n");
*/
		KSI_free(raw);
		raw = NULL;
	}

	res = KSI_OK;

cleanup:

	KSI_free(raw);
	return res;
}

int main(int argc, char **argv) {
	KSI_CTX *ctx;
	int res;
	KSI_PublicationsFile *publicationsFile = NULL;
	KSI_LIST(KSI_PublicationRecord) *publications = NULL;
	int i;

	const char *fileName = NULL;

	if (argc != 1 && argc != 2) {
		printf("Usage:\n  %s <publications file>\n\n", *argv);
		goto cleanup;
	}


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

	res = KSI_PKITruststore_addLookupFile(ctx->pkiTruststore, "test/resource/tlv/server-3.crt");
	if (res != KSI_OK) {
		KSI_ERR_statusDump(ctx, stdout);
		fprintf(stderr, "Unable to read cert.\n");
		goto cleanup;
	}

	if (argc == 2) {
		fileName = argv[1];
		res = KSI_PublicationsFile_fromFile(ctx, fileName, &publicationsFile);
		if (res != KSI_OK) {
			KSI_ERR_statusDump(ctx, stdout);
			fprintf(stderr, "Unable to read publications file.\n");
			goto cleanup;
		}
	} else {
		res = KSI_receivePublicationsFile(ctx, &publicationsFile);
		if (res != KSI_OK) {
			KSI_ERR_statusDump(ctx, stdout);
			fprintf(stderr, "Unable to read publications file.\n");
			goto cleanup;
		}
	}
	res = KSI_PublicationsFile_getPublications(publicationsFile, &publications);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to get publications from store.\n");
		goto cleanup;
	}

	printf("[publications]\n");
	for (i = 0; i < KSI_PublicationRecordList_length(publications); i++) {
		KSI_PublicationRecord *rec = NULL;
		KSI_PublicationData *pubDat = NULL;
		char *pubStr = NULL;
		KSI_LIST(KSI_Utf8String) *refs = NULL;
		int j;
		struct tm *tm_pubTime;
		time_t pubTime;
		KSI_Integer *pubTimeO = NULL;

		res = KSI_PublicationRecordList_elementAt(publications, i, &rec);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed while iterating publications list.\n");
			goto cleanup;
		}

		res = KSI_PublicationRecord_getPublishedData(rec, &pubDat);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed to extract published data\n");
			goto cleanup;
		}

		res = KSI_publishedDataToBase32(pubDat, &pubStr);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed to create publication string from published data.\n");
			goto cleanup;
		}

		res = KSI_PublicationRecord_getPublicationRef(rec, &refs);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed to get publications ref list from publication record.\n");
			goto cleanup;
		}


		res = KSI_PublicationData_getTime(pubDat, &pubTimeO);
		if (res != KSI_OK || pubTimeO == NULL) {
			fprintf(stderr, "Failed to get publication time\n");
			goto cleanup;
		}

		pubTime =  KSI_Integer_getUInt64(pubTimeO);
		tm_pubTime = gmtime(&pubTime);
		if (tm_pubTime == NULL) {
			fprintf(stderr, "Unable to parse publication time.\n");
			goto cleanup;
		}

		printf("[pub-%d-%d-%d]\n", 1900 + tm_pubTime->tm_year, tm_pubTime->tm_mon, tm_pubTime->tm_mday);
		printf("pub=%s\n", pubStr);

		for (j = 0; j < KSI_Utf8StringList_length(refs); j++) {
			KSI_Utf8String *ref = NULL;
			res =  KSI_Utf8StringList_elementAt(refs, j, &ref);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to get publication ref.\n");
				goto cleanup;
			}

			printf("ref%d=%s\n", j, KSI_Utf8String_cstr(ref));
		}

		printf("\n");

		KSI_free(pubStr);
	}

	res = printCerts(publicationsFile);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to print certificates");
		goto cleanup;
	}

cleanup:

	KSI_CTX_free(ctx);

	KSI_global_cleanup();

	return 0;

}
