/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ksi/ksi.h>
#include <ksi/net_http.h>
#include <ksi/net_tcp.h>

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

	char *signerIdentity = NULL;
	KSI_TcpClient *net = NULL;

	FILE *logFile = NULL;

	/* Handle command line parameters */
	if (argc != 8) {
		fprintf(stderr, "Usage:\n"
				"  %s <in-file> <out-file> <aggregator> <port> <user> <pass> <pub-file url | -> \n", argv[0]);
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

	logFile = fopen("ksi_aggr.log", "w");
	if (logFile == NULL) {
		fprintf(stderr, "Unable to open log file.\n");
	}

	KSI_CTX_setLoggerCallback(ksi, KSI_LOG_StreamLogger, logFile);

	KSI_CTX_setLogLevel(ksi, KSI_LOG_DEBUG);

	/* Check if uri's are specified. */
	res = KSI_TcpClient_new(ksi, &net);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create new network provider.\n");
		goto cleanup;
	}

	res = KSI_TcpClient_setAggregator(net, argv[3], atoi(argv[4]), argv[5], argv[6]);
	if (res != KSI_OK) goto cleanup;

	/* Check publications file url. */
	if (strncmp("-", argv[7], 1)) {
		res = KSI_TcpClient_setPublicationUrl(net, argv[7]);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to set publications file url.\n");
			goto cleanup;
		}
	}

	/* Set the new network provider. */
	res = KSI_CTX_setNetworkProvider(ksi, (KSI_NetworkClient*)net);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set network provider.\n");
		res = KSI_UNKNOWN_ERROR;

		goto cleanup;
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
		goto cleanup;
	}

	res = KSI_verifySignature(ksi, sign);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to verify signature.");
		goto cleanup;
	}

	/* Output the signer id */
	res = KSI_Signature_getSignerIdentity(sign, &signerIdentity);
	if (res == KSI_OK) {
		printf("Signer id: %s\n", signerIdentity);
	} else {
		fprintf(stderr, "Unable to extract signer identity.\n");
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

	if (logFile != NULL) fclose(logFile);

	if (res != KSI_OK && ksi != NULL) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	if (in != NULL) fclose(in);
	if (out != NULL) fclose(out);

	KSI_free(signerIdentity);

	KSI_Signature_free(sign);
	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);

	KSI_free(raw);

	KSI_CTX_free(ksi);

	return res;

}
