/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef _WIN32
#  include <windows.h>
#  define sleep_ms(x) Sleep((x))
#else
#  include <unistd.h>
#  define sleep_ms(x) usleep((x)*1000)
#endif

#include <ksi/ksi.h>
#include <ksi/net.h>
#include <ksi/net_async.h>
#include <ksi/net_uri.h>
#include <ksi/signature_builder.h>
#include <ksi/compatibility.h>

#include "ksi_common.h"

enum {
	ARGV_COMMAND = 0,
	ARGV_AGGR_URI,
	ARGV_USER,
	ARGV_PASS,
	ARGV_DELIM,
	NOF_STATIC_ARGS,

	ARGV_IN_DATA_FILE_START = NOF_STATIC_ARGS,
};

static int getHash(KSI_CTX *ksi, char *inFile, KSI_DataHash **hsh) {
	int res = KSI_UNKNOWN_ERROR;

	unsigned char buf[1024];
	size_t buf_len;
	FILE *in = NULL;

	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *tmp = NULL;

	in = fopen(inFile, "rb");
	if (in == NULL) {
		fprintf(stderr, "Unable to open file: %s.\n", inFile);
		res = KSI_IO_ERROR;
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
		buf_len = fread(buf, 1, sizeof(buf), in);

		/* Add  next block to the calculation. */
		res = KSI_DataHasher_add(hsr, buf, buf_len);
		if (res != KSI_OK) {
			fprintf(stderr, "Unable to add data to hasher.\n");
			goto cleanup;
		}
	}

	/* Close the data hasher and retreive the data hash. */
	res = KSI_DataHasher_close(hsr, &tmp);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create hash.\n");
		goto cleanup;
	}
	*hsh = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:
	if (in != NULL) fclose(in);

	KSI_DataHash_free(tmp);
	KSI_DataHasher_free(hsr);

	return res;
}

static int saveSignature(const char *fileName, const KSI_AggregationResp *resp) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_SignatureBuilder *builder = NULL;
	KSI_Signature *sig = NULL;

	FILE *out = NULL;
	unsigned char *raw = NULL;
	size_t raw_len;

	char sigFileName[0xff];

	/* Generate KSI signature from aggregation response. */
	res = KSI_SignatureBuilder_openFromAggregationResp(resp, &builder);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create signature builder from aggregation response.\n");
		goto cleanup;
	}

	res = KSI_SignatureBuilder_close(builder, 0, &sig);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to close signature builder.\n");
		goto cleanup;
	}

	/* Create a filename for the signature. */
	KSI_snprintf(sigFileName, sizeof(sigFileName), "%s.ksig", fileName);

	/* Open output file. */
	out = fopen(sigFileName, "wb");
	if (out == NULL) {
		fprintf(stderr, "%s: Unable to open output file.\n", sigFileName);
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	/* Serialize the signature. */
	res = KSI_Signature_serialize(sig, &raw, &raw_len);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to serialize signature.");
		goto cleanup;
	}

	/* Write serialized data to file. */
	if (!fwrite(raw, 1, raw_len, out)) {
		fprintf(stderr, "Unable to write output file.\n");
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	printf("Signature successfully saved: %s.\n", sigFileName);

	res = KSI_OK;
cleanup:
	KSI_SignatureBuilder_free(builder);
	KSI_Signature_free(sig);

	if (out != NULL) fclose(out);
	KSI_free(raw);

	return res;
}

int main(int argc, char **argv) {
	KSI_CTX *ksi = NULL;
	int res = KSI_UNKNOWN_ERROR;

	KSI_AsyncService *as = NULL;

	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;

	KSI_AggregationReq *req = NULL;
	KSI_AggregationResp *resp = NULL;

	KSI_DataHash *hsh = NULL;

	FILE *logFile = NULL;

	size_t pending = 0;
	size_t nof_requests = 0;
	size_t req_no = 0;

	size_t succeeded = 0;

	/* Handle command line parameters */
	if (argc <= NOF_STATIC_ARGS || strcmp("--", argv[ARGV_DELIM])) {
		fprintf(stderr, "Usage:\n"
				"  %s <aggregator-uri> <user> <pass> -- <in-data-file>...<in-data-file>\n", argv[ARGV_COMMAND]);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	nof_requests = argc - NOF_STATIC_ARGS;

	/* Create new KSI context for this thread. */
	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create context.\n");
		goto cleanup;
	}

	/* Configure the logger. */
	res = OpenLogging(ksi, "ksi_sign_async.log", &logFile);
	if (res != KSI_OK) goto cleanup;

	KSI_LOG_info(ksi, "Using KSI version: '%s'", KSI_getVersion());

	/* Create new async service provider. */
	res = KSI_SigningAsyncService_new(ksi, &as);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create new async service object.\n");
		goto cleanup;
	}

	res = KSI_AsyncService_setEndpoint(as, argv[ARGV_AGGR_URI], argv[ARGV_USER], argv[ARGV_PASS]);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set aggregator to the async service client.\n");
		goto cleanup;
	}
	KSI_LOG_info(ksi, "Async service endpoint initialized:");
	KSI_LOG_info(ksi, "  URI:  %s", argv[ARGV_AGGR_URI]);
	KSI_LOG_info(ksi, "  user: %s", argv[ARGV_USER]);
	KSI_LOG_info(ksi, "  pass: %s", argv[ARGV_PASS]);

#ifdef UNDATE_CONF_OPTIONS
	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, (void *)(1 << 8));
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set maximum request count.\n");
		goto cleanup;
	}

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void*)(1 << 10));
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to set request cache size.\n");
		goto cleanup;
	}
#endif

	do {
		if (req_no < nof_requests) {
			char *p_name = argv[ARGV_IN_DATA_FILE_START + req_no];

			if (reqHandle == NULL) {
				KSI_LOG_info(ksi, "Create request for file:  %s", p_name);

				/* Get the hash value of the input file. */
				res = getHash(ksi, p_name, &hsh);
				if (res != KSI_OK || hsh == NULL) {
					fprintf(stderr, "Failed to calculate the hash.\n");
					goto cleanup;
				}

				res = KSI_AggregationReq_new(ksi, &req);
				if (res == KSI_OK && req == NULL) {
					fprintf(stderr, "Unable to create aggregation request.\n");
					goto cleanup;
				}

				res = KSI_AggregationReq_setRequestHash(req, hsh);
				if (res != KSI_OK) {
					fprintf(stderr, "Unable to set request data hash.\n");
					goto cleanup;
				}
				hsh = NULL;

				res = KSI_AsyncAggregationHandle_new(ksi, req, &reqHandle);
				if (res != KSI_OK) {
					fprintf(stderr, "Unable to create async request.\n");
					goto cleanup;
				}
				req = NULL;

				res = KSI_AsyncHandle_setRequestCtx(reqHandle, (void*)p_name, NULL);
				if (res != KSI_OK) {
					fprintf(stderr, "Unable to set request context.\n");
					goto cleanup;
				}
			}

			res = KSI_AsyncService_addRequest(as, reqHandle);
			switch (res) {
				case KSI_OK:
					req_no++;
					reqHandle = NULL;
					break;
				case KSI_ASYNC_REQUEST_CACHE_FULL:
					/* The request could not be added to the cache because of unresponsed requests. */
					/* Wait for a while to avoid busy loop. */
					sleep_ms(10);
					break;
				default:
					fprintf(stderr, "Unable to add request.\n");
					goto cleanup;
			}
		}

		respHandle = NULL;
		res = KSI_AsyncService_run(as, &respHandle, &pending);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed to run async service.\n");
			goto cleanup;
		}

		if (respHandle != NULL) {
			char *p_name = NULL;
			int state = KSI_ASYNC_STATE_UNDEFINED;

			KSI_LOG_info(ksi, "Read response.");

			KSI_AsyncHandle_getState(respHandle, &state);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to get request state.\n");
				goto cleanup;
			}

			switch (state) {
				case KSI_ASYNC_STATE_RESPONSE_RECEIVED: {
						res = KSI_AsyncHandle_getAggregationResp(respHandle, &resp);
						if (res != KSI_OK) {
							fprintf(stderr, "Failed to get aggregation response.\n");
							goto cleanup;
						}

						res = KSI_AsyncHandle_getRequestCtx(respHandle, (const void**)&p_name);
						if (res != KSI_OK) {
						  fprintf(stderr, "Unable to get request context.\n");
						  goto cleanup;
						}

						res = saveSignature(p_name, resp);
						if (res != KSI_OK) {
							fprintf(stderr, "Failed to save signature for: %s\n", p_name);
							goto cleanup;
						}

						succeeded++;

						KSI_AsyncHandle_free(respHandle);
						respHandle = NULL;
					}
					break;

				case KSI_ASYNC_STATE_ERROR: {
						int err = KSI_UNKNOWN_ERROR;
						long extErr = 0L;
						KSI_Utf8String *errMsg = NULL;

						res = KSI_AsyncHandle_getError(respHandle, &err);
						if (res != KSI_OK) {
							fprintf(stderr, "Unable to get request error.\n");
							goto cleanup;
						}

						res = KSI_AsyncHandle_getErrorMessage(respHandle, &errMsg);
						if (res != KSI_OK) {
							fprintf(stderr, "Unable to get error message.\n");
							goto cleanup;
						}

						res = KSI_AsyncHandle_getExtError(respHandle, &extErr);
						if (res != KSI_OK) {
							fprintf(stderr, "Unable to get external error.\n");
							goto cleanup;
						}

						res = KSI_AsyncHandle_getRequestCtx(respHandle, (const void**)&p_name);
						if (res != KSI_OK) {
							fprintf(stderr, "Unable to get request context.\n");
							goto cleanup;
						}

						fprintf(stderr, "Request for '%s' failed. ", p_name);
						fprintf(stderr, "Error: [0x%x:%ld] %s ", err, extErr, KSI_getErrorString(err));
						if (errMsg != NULL) fprintf(stderr, "(%s) ", KSI_Utf8String_cstr(errMsg));

						res = KSI_AsyncService_addRequest(as, respHandle);
						if (res == KSI_OK) {
							fprintf(stderr, " ...resending.\n");
						} else {
							fprintf(stderr, " ...clearing.\n");
							KSI_AsyncHandle_free(respHandle);
						}
						respHandle = NULL;
					}
					break;

				default:
					/* Do nothing! */
					break;
			}
		}
	} while (pending);

	res = KSI_OK;
cleanup:
	printf("Succeeded request: %lu.\n", succeeded);
	printf("Failed request   : %lu.\n", nof_requests - succeeded);

	if (res != KSI_OK && ksi != NULL) {
		KSI_ERR_statusDump(ksi, stderr);
	}

	if (logFile != NULL) fclose(logFile);

	KSI_AsyncService_free(as);

	KSI_AsyncHandle_free(reqHandle);
	KSI_AsyncHandle_free(respHandle);

	KSI_AggregationReq_free(req);

	KSI_DataHash_free(hsh);

	KSI_CTX_free(ksi);

	return res;
}
