#include <stdio.h>
#include <string.h>
#include <ksi/ksi.h>
#include <ksi/net_http.h>

int main(int argc, char **argv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ksi = NULL;
	KSI_Signature *sig = NULL;
	KSI_NetworkClient *net = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_DataHasher *hsr = NULL;
	FILE *in = NULL;
	unsigned char buf[1024];
	unsigned buf_len;
	const KSI_VerificationResult *info = NULL;

	/* Init context. */
	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to init KSI context.\n");
		goto cleanup;
	}

	/* Check parameters. */
	if (argc != 5) {
		fprintf(stderr, "Usage\n"
				"  %s <data file> <signature> <extender url | - > <pub-file url | ->\n", argv[0]);
		goto cleanup;
	}

	if (strncmp("-",argv[3], 1) || strncmp("-", argv[4], 1)) {
		res = KSI_HttpClient_new(ksi, &net);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to create new network provider.\n");
			goto cleanup;
		}

		if (strncmp("-", argv[3], 1)) {
			/* Set extender uri. */
			res = KSI_HttpClient_setExtenderUrl(net, argv[3]);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to set extender url.\n");
				goto cleanup;
			}
		}

		if (strncmp("-", argv[4], 1)) {
			/* Set the publications file url. */
			res = KSI_HttpClient_setPublicationUrl(net, argv[4]);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to set publications file url.\n");
				goto cleanup;
			}
		}

		res = KSI_setNetworkProvider(ksi, net);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to set new network provider.\n");
			goto cleanup;
		}
		net = NULL;
	}

	printf("Reading signature... ");
	/* Read the signature. */
	res = KSI_Signature_fromFile(ksi, argv[2], &sig);
	if (res != KSI_OK) {
		printf("failed (%s)\n", KSI_getErrorString(res));
		goto cleanup;
	}
	printf("ok\n");

	/* Create hasher. */
	res = KSI_Signature_createDataHasher(sig, &hsr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create data hasher.\n");
		goto cleanup;
	}

	in = fopen(argv[1], "rb");
	if (in == NULL) {
		fprintf(stderr, "Unable to open data file '%s'.\n", argv[1]);
		goto cleanup;
	}

	/* Calculate the hash of the document. */
	while (!feof(in)) {
		buf_len = (unsigned)fread(buf, 1, sizeof(buf), in);
		res = KSI_DataHasher_add(hsr, buf, buf_len);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable hash the document.\n");
			goto cleanup;
		}
	}

	/* Finalize the hash computation. */
	res = KSI_DataHasher_close(hsr, &hsh);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to close the hashing process.\n");
		goto cleanup;
	}

	printf("Verifying document hash... ");
	res = KSI_Signature_verifyDataHash(sig, ksi, hsh);
	switch (res) {
		case KSI_OK:
			printf("ok\n");
			break;
		case KSI_VERIFICATION_FAILURE:
			printf("failed\n");
			break;
		default:
			printf("failed (%s)\n", KSI_getErrorString(res));
			goto cleanup;
	}
	res = KSI_Signature_getVerificationResult(sig, &info);
	if (res != KSI_OK) goto cleanup;

	if (info != NULL) {
		size_t i;
		printf("Verification info:\n");
		for (i = 0; i < KSI_VerificationResult_getStepResultCount(info); i++) {
			const KSI_VerificationStepResult *result = NULL;
			const char *desc = NULL;
			res = KSI_VerificationResult_getStepResult(info, i, &result);
			if (res != KSI_OK) goto cleanup;
			printf("\t0x%02x:\t%s", KSI_VerificationStepResult_getStep(result), KSI_VerificationStepResult_isSuccess(result) ? "OK" : "FAIL");
			desc = KSI_VerificationStepResult_getDescription(result);
			if (desc && *desc) {
				printf(" (%s)", desc);
			}
			printf("\n");
		}
	}

	res = KSI_OK;

cleanup:

	if (res != KSI_OK && ksi != NULL) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	if (in != NULL) fclose(in);

	KSI_NetworkClient_free(net);
	KSI_Signature_free(sig);
	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);
	KSI_CTX_free(ksi);

	return res;
}
