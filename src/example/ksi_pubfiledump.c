#include <time.h>
#include <string.h>

#include <ksi/ksi.h>

#include <ksi/compatibility.h>

int toHex(KSI_OctetString *certId, char **hex) {
	int res = KSI_UNKNOWN_ERROR;
	unsigned len;
	const unsigned char *raw = NULL;
	unsigned int raw_len = 0;
	char *tmp = NULL;
	unsigned int i;

	res = KSI_OctetString_extract(certId, &raw, &raw_len);
	if (res != KSI_OK) goto cleanup;

	len = 2*raw_len + 1;

	tmp = KSI_calloc(len, 1);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	for (i = 0; i < raw_len; i++) {
		KSI_snprintf(tmp + (i * 2), len - i * 2, "%02x", raw[i]);
	}

	*hex = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);

	return res;
}


static int printCerts(KSI_PublicationsFile *pubFile) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(KSI_CertificateRecord) *certRecList = NULL;
	size_t i;
	char *hex = NULL;
	unsigned char *raw = NULL;
	unsigned len = 0;
	FILE *f = NULL;

	printf("[certificates]\n");

	res = KSI_PublicationsFile_getCertificates(pubFile, &certRecList);
	if (res != KSI_OK) goto cleanup;

	for (i = 0; i < KSI_CertificateRecordList_length(certRecList); i++) {
		char fileName[0xff];
		KSI_CertificateRecord *certRec = NULL;
		KSI_PKICertificate *cert = NULL;
		KSI_OctetString *certId = NULL;

		/* Get the next certificate record from the list. */
		res = KSI_CertificateRecordList_elementAt(certRecList, i, &certRec);
		if (res != KSI_OK) goto cleanup;

		/* Extract the certId. */
		res = KSI_CertificateRecord_getCertId(certRec, &certId);
		if (res != KSI_OK) goto cleanup;

		/* Encode the certId as base32. */
		res = toHex(certId, &hex);
		if (res != KSI_OK) goto cleanup;

		/* Create the file name. */
		KSI_snprintf(fileName, sizeof(fileName), "%s.der", hex);
		printf("cert%llu=%s\n", (long long unsigned)i, fileName);

		KSI_free(hex);
		hex = NULL;

		res = KSI_CertificateRecord_getCert(certRec, &cert);
		if (res != KSI_OK) goto cleanup;

		res = KSI_PKICertificate_serialize(cert, &raw, &len);
		if (res != KSI_OK) goto cleanup;

		f = fopen(fileName, "w");
		if (f == NULL) {
			fprintf(stderr, "Unable to write file '%s'\n", fileName);
			goto cleanup;
		}

		/* TODO! Check for write errors */
		fwrite(raw, 1, len, f);

		fclose(f);
		f = NULL;

		KSI_free(raw);
		raw = NULL;
	}

	res = KSI_OK;

cleanup:

	if (f != NULL) fclose(f);
	KSI_free(raw);
	return res;
}

int main(int argc, char **argv) {
	KSI_CTX *ctx = NULL;
	int res;
	KSI_PublicationsFile *publicationsFile = NULL;
	KSI_LIST(KSI_PublicationRecord) *publications = NULL;
	size_t i;

	const char *fileName = NULL;

	if (argc != 2) {
		printf("Usage:\n  %s <publications file>\n\n", *argv);
		goto cleanup;
	}

	res = KSI_CTX_new(&ctx);
	if (res != KSI_OK) {
		printf("Unable to create context.\n");
		goto cleanup;
	}

	if (argc == 2 && strncmp(argv[1], "-", 1)) {
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

	res = KSI_verifyPublicationsFile(ctx, publicationsFile);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to verify publications file");
		KSI_ERR_statusDump(ctx, stderr);
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
		size_t j;
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

		res = KSI_PublicationData_toBase32(pubDat, &pubStr);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed to create publication string from published data.\n");
			goto cleanup;
		}

		res = KSI_PublicationRecord_getPublicationRefList(rec, &refs);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed to get publications ref list from publication record.\n");
			goto cleanup;
		}


		res = KSI_PublicationData_getTime(pubDat, &pubTimeO);
		if (res != KSI_OK || pubTimeO == NULL) {
			fprintf(stderr, "Failed to get publication time\n");
			goto cleanup;
		}

		pubTime =  (time_t)KSI_Integer_getUInt64(pubTimeO);
		tm_pubTime = gmtime(&pubTime);
		if (tm_pubTime == NULL) {
			fprintf(stderr, "Unable to parse publication time.\n");
			goto cleanup;
		}

		printf("[pub-%d-%d-%d]\n", 1900 + tm_pubTime->tm_year, tm_pubTime->tm_mon + 1, tm_pubTime->tm_mday);
		printf("pub=%s\n", pubStr);

		for (j = 0; j < KSI_Utf8StringList_length(refs); j++) {
			KSI_Utf8String *ref = NULL;
			res =  KSI_Utf8StringList_elementAt(refs, j, &ref);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to get publication ref.\n");
				goto cleanup;
			}

			printf("ref%llu=%s\n", (long long unsigned)j, KSI_Utf8String_cstr(ref));
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

	return 0;

}
