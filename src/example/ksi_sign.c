#include <stdio.h>
#include <string.h>

#include <ksi/ksi.h>
#include <ksi/net_http.h>

int main(int argc, char **argv) {
	KSI_CTX *ksi = NULL;
	int res = KSI_UNKNOWN_ERROR;

	FILE *in = NULL;
	FILE *out = NULL;

	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sign = NULL;

	unsigned char *raw = NULL;
	unsigned raw_len;

	unsigned char buf[1024];
	unsigned buf_len;

	/** Global init of KSI */
	res = KSI_global_init();
	if (res != KSI_OK) goto cleanup;

	/* Handle command line parameters */
	if (argc != 5) {
		fprintf(stderr, "Usage:\n"
				"  %s <in-file> <out-file> <aggregator url |-> <pub-file url | -> \n", argv[0]);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Input file */
	in = fopen(argv[1], "rb");
	if (in == NULL) {
		fprintf(stderr, "Unable to open input file '%s'\n", argv[1]);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	/* Create new KSI context for this thread. */
	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create context.\n");
		goto cleanup;
	}

	KSI_CTX_setLogLevel(ksi, KSI_LOG_DEBUG);

	/* Check if uri's are specified. */
	if (strncmp("-", argv[3], 1) || strncmp("-", argv[4], 1)) {
		KSI_NetworkClient *net = NULL;
		res = KSI_HttpClient_new(ksi, &net);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to create new network provider.\n");
			goto cleanup;
		}

		/* Check aggregator url */
		if (strncmp("-", argv[3], 1)) {
			res = KSI_HttpClient_setSignerUrl(net, argv[3]);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to set aggregator url.\n");
				goto cleanup;
			}
		}

		/* Check publications file url. */
		if (strncmp("-", argv[4], 1)) {
			res = KSI_HttpClient_setPublicationUrl(net, argv[4]);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to set publications file url.\n");
				goto cleanup;
			}
		}

		/* Set the new network provider. */
		res = KSI_setNetworkProvider(ksi, net);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to set network provider.\n");
			res = KSI_UNKNOWN_ERROR;

			goto cleanup;
		}
	}

	/* Create a data hasher using default algorithm. */
	res = KSI_DataHasher_open(ksi, KSI_getHashAlgorithmByName("default"), &hsr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create hasher.\n");
		goto cleanup;
	}

	/* Read the input file and calculate the hash of its contents. */
	while (!feof(in)) {
		buf_len = (unsigned)fread(buf, 1, sizeof(buf), in);

		/* Add  next block to the calculation. */
		res = KSI_DataHasher_add(hsr, buf, buf_len);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to add data to hasher.\n");
			goto cleanup;
		}
	}

	/* Close the data hasher and retreive the data hash. */
	res = KSI_DataHasher_close(hsr, &hsh);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create hash.\n");
		goto cleanup;
	}

	/* Sign the data hash. */
	res = KSI_createSignature(ksi, hsh, &sign);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to sign %d.\n", res);
		KSI_ERR_statusDump(ksi, stderr);
		goto cleanup;
	}

	/* Serialize the signature. */
	res = KSI_Signature_serialize(sign, &raw, &raw_len);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to serialize signature.");
		goto cleanup;
	}

	/* Output file */
	out = fopen(argv[2], "wb");
	if (out == NULL) {
		fprintf(stderr, "Unable to open input file '%s'\n", argv[2]);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	/* Write the signature file. */
	if (!fwrite(raw, 1, raw_len, out)) {
		fprintf(stderr, "Unable to write output file.\n");
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	/* Only print message when signature output is not stdout. */
	if (out != NULL) {
		printf("Signature saved.\n");
	}

	res = KSI_OK;

cleanup:

	if (in != NULL) fclose(in);
	if (out != NULL) fclose(out);

	KSI_Signature_free(sign);
	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);

	KSI_free(raw);

	KSI_CTX_free(ksi);

	/* Global cleanup */
	KSI_global_cleanup();

	return res;

}
