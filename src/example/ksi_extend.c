#include <stdio.h>
#include <string.h>

#include <ksi/ksi.h>
#include <ksi/net_http.h>


int main(int argc, char **argv) {
	KSI_CTX *ksi = NULL;
	int res;
	FILE *out = NULL;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	KSI_NetworkClient *net = NULL;
	unsigned char *raw = NULL;
	unsigned raw_len;
	unsigned count;

	res = KSI_global_init();
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to init global KSI.\n");
		goto cleanup;
	}

	if (argc != 5) {
		printf("Usage:\n"
				"  %s <signature> <extended> <extender uri | -> <pub-file uri | ->\n", argv[0]);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Init KSI context */
	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to init KSI context.\n");
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
	}

	/* Clear the errors. */
	KSI_ERR_clearErrors(ksi);
	/* Read the signature. */
	res = KSI_Signature_fromFile(ksi, argv[1], &sig);
	if (res != KSI_OK) {
		KSI_ERR_statusDump(ksi, stdout);
		fprintf(stderr, "Unable to read signature from '%s'\n", argv[1]);
		goto cleanup;
	}

	/* Make sure the signature is ok. */
	res = KSI_verifySignature(ksi, sig);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to verify signature.\n");
		KSI_ERR_statusDump(ksi, stderr);
		goto cleanup;
	}

	/* Extend the signature. */
	res = KSI_extendSignature(ksi, sig, &ext);
	if (res != KSI_OK) {
		if (res == KSI_EXTEND_NO_SUITABLE_PUBLICATION) {
			printf("No suitable publication to extend to.\n");
			goto cleanup;
		}
		fprintf(stderr, "Unable to extend signature.\n");
		KSI_ERR_statusDump(ksi, stderr);
		goto cleanup;
	}

	/* To be extra sure, lets verify the extended signature. */
	res = KSI_verifySignature(ksi, ext);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to verify the extended signature.\n");
		KSI_ERR_statusDump(ksi, stderr);
		goto cleanup;
	}

	/* Serialize the extended signature. */
	res = KSI_Signature_serialize(ext, &raw, &raw_len);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to serialize extended signature.\n");
		goto cleanup;
	}

	/* Open output file. */
	out = fopen(argv[2], "wb");
	if (out == NULL) {
		fprintf(stderr, "Unable to open output file '%s'\n", argv[2]);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	count = (unsigned)fwrite(raw, 1, raw_len, out);
	if (count != raw_len) {
		fprintf(stderr, "Failed to write output file.\n");
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	printf("Signature extended.");

cleanup:

	if (out != NULL) fclose(out);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);
	KSI_free(raw);
	KSI_CTX_free(ksi);
	KSI_global_cleanup();

	return res;
}
