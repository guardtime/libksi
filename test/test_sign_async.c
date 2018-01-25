/*
 * Copyright 2013-2017 Guardtime, Inc.
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

#include "support_tests.h"

/*#define REQ_ADD_LEVEL*/
/*#define SIG_CREATE_FROM_RESPONSE*/

enum {
	ARGV_COMMAND = 0,
	ARGV_TEST_ROOT,
	ARGV_PROTOCOL,
	ARGV_LOG_LEVEL,
	AGRV_NOF_TEST_REQUESTS,
	ARGV_REQUEST_CACHE_SIZE,
	ARGV_MAX_REQUEST_COUNT,
	NOF_ARGS,
};

static int createHash(KSI_CTX *ksi, const size_t num, KSI_DataHash **hsh) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *tmp = NULL;

	if (ksi == NULL || hsh == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Create a data hasher using default algorithm. */
	res = KSI_DataHasher_open(ksi, KSI_getHashAlgorithmByName("default"), &hsr);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create hasher.\n");
		goto cleanup;
	}

	res = KSI_DataHasher_add(hsr, &num, sizeof(num));
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to add data to hasher.\n");
		goto cleanup;
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
	KSI_DataHash_free(tmp);
	KSI_DataHasher_free(hsr);

	return res;
}

#ifdef SIG_CREATE_FROM_RESPONSE
static int createSignature(const KSI_AggregationResp *resp, KSI_Signature **sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_SignatureBuilder *builder = NULL;

	if (resp == NULL || sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Generate KSI signature from aggregation response. */
	res = KSI_SignatureBuilder_openFromAggregationResp(resp, &builder);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create signature builder from aggregation response.\n");
		goto cleanup;
	}

	res = KSI_SignatureBuilder_close(builder, 0, sig);
	if (res != KSI_OK) {
		fprintf(stderr, "Failed to close signature builder.\n");
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	KSI_SignatureBuilder_free(builder);

	return res;
}
#endif

int main(int argc, char **argv) {
	KSI_CTX *ksi = NULL;
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_AggregationReq *req = NULL;
	KSI_DataHash *reqHsh = NULL;
#ifdef REQ_ADD_LEVEL
	KSI_Integer *reqLvl = NULL;
#endif
	FILE *logFile = NULL;
	size_t pending = 0;
	size_t nof_requests = 0;
	size_t req_no = 0;
	size_t succeeded = 0;
	KSITest_Conf conf;
	KSI_Signature *signature = NULL;
	time_t start;

	time(&start);

	/* Handle command line parameters. */
	if (argc < NOF_ARGS) {
		fprintf(stderr, "Usage:\n"
				"  %s <test-root> <protocol> <log-level> <nof-requests> <request-cache-size> <requests-per-round>\n",
				argv[ARGV_COMMAND]);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	initFullResourcePath(argv[ARGV_TEST_ROOT]);

	if (KSITest_Conf_load(getFullResourcePath("integrationtest.conf"), &conf)) {
		fprintf(stderr, "Unable to load configuration.\n");
		goto cleanup;
	}

	/* Create new KSI context for this thread. */
	res = KSI_CTX_new(&ksi);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create context.\n");
		goto cleanup;
	}

	/* Configure libksi logger. */
	{
		int level = atoi(argv[ARGV_LOG_LEVEL]);
		if (level) {
			logFile = fopen("test_sign_async.log", "w");
			if (logFile == NULL) {
				fprintf(stderr, "Unable to open log file.\n");
				exit(EXIT_FAILURE);
			}
			KSI_CTX_setLoggerCallback(ksi, KSI_LOG_StreamLogger, logFile);
			KSI_CTX_setLogLevel(ksi, level);
		}
	}

	KSI_LOG_info(ksi, "Using KSI version: '%s'", KSI_getVersion());

	/* Create new async service provider. */
	res = KSI_SigningAsyncService_new(ksi, &as);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to create new async service object.\n");
		goto cleanup;
	}

	res = KSI_AsyncService_setEndpoint(as, KSITest_composeUri(argv[ARGV_PROTOCOL], &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
	if (res != KSI_OK) {
		fprintf(stderr, "Unable to setup aggregator endpoint.\n");
		goto cleanup;
	}
	KSI_LOG_info(ksi, "Async service endpoint initialized:");
	KSI_LOG_info(ksi, "  URI:  %s", KSITest_composeUri(argv[ARGV_PROTOCOL], &conf.aggregator));
	KSI_LOG_info(ksi, "  user: %s", conf.aggregator.user);
	KSI_LOG_info(ksi, "  pass: %s", conf.aggregator.pass);

	{
		size_t count = atoi(argv[ARGV_MAX_REQUEST_COUNT]);
		KSI_LOG_info(ksi, "Setting max request count to: %llu", (unsigned long long)count);
		if (count) {
			res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, (void*)count);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to set maximum request count.\n");
				goto cleanup;
			}
		}
	}

	{
		size_t size = atoi(argv[ARGV_REQUEST_CACHE_SIZE]);
		KSI_LOG_info(ksi, "Setting request cache size to: %llu", (unsigned long long)size);
		if (size) {
			res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void*)size);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to set request cache size.\n");
				goto cleanup;
			}

		}
	}

	nof_requests = atoi(argv[AGRV_NOF_TEST_REQUESTS]);
	KSI_LOG_info(ksi, "Nof test requests: %llu", (unsigned long long)nof_requests);
	do {
		size_t received = 0;

		if (req_no < nof_requests) {
			if (reqHandle == NULL) {
				KSI_DataHash *hshRef = NULL;

				KSI_LOG_info(ksi, "Request #: %llu", (unsigned long long)req_no);

				/* Get the hash value of the input file. */
				res = createHash(ksi, req_no, &reqHsh);
				if (res != KSI_OK || reqHsh == NULL) {
					fprintf(stderr, "Failed to calculate the hash.\n");
					goto cleanup;
				}
				KSI_LOG_logDataHash(ksi, KSI_LOG_DEBUG, "Request hash", reqHsh);

				res = KSI_AggregationReq_new(ksi, &req);
				if (res != KSI_OK || req == NULL) {
					fprintf(stderr, "Unable to create aggregation request.\n");
					goto cleanup;
				}

				res = KSI_AggregationReq_setRequestHash(req, (hshRef = KSI_DataHash_ref(reqHsh)));
				if (res != KSI_OK) {
					KSI_DataHash_free(hshRef);
					fprintf(stderr, "Unable to set request data hash.\n");
					goto cleanup;
				}

#ifdef REQ_ADD_LEVEL
				res = KSI_Integer_new(ksi, (req_no % 5), &reqLvl);
				if (res != KSI_OK || reqLvl == NULL) {
					fprintf(stderr, "Unable to create request level.\n");
					goto cleanup;
				}

				res = KSI_AggregationReq_setRequestLevel(req, reqLvl);
				if (res != KSI_OK) {
					fprintf(stderr, "Unable to set request level.\n");
					goto cleanup;
				}
				reqLvl = NULL;
#endif

				res = KSI_AsyncAggregationHandle_new(ksi, req, &reqHandle);
				if (res != KSI_OK) {
					fprintf(stderr, "Unable to create async request.\n");
					goto cleanup;
				}
				req = NULL;

				res = KSI_AsyncHandle_setRequestCtx(reqHandle, (void*)reqHsh, (void (*)(void*))KSI_DataHash_free);
				if (res != KSI_OK) {
					fprintf(stderr, "Unable to set request context.\n");
					goto cleanup;
				}
				reqHsh = NULL;
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

		do {
			respHandle = NULL;
			res = KSI_AsyncService_run(as, &respHandle, &pending);
			if (res != KSI_OK) {
				fprintf(stderr, "Failed to run async service.\n");
				goto cleanup;
			}

			if (respHandle != NULL) {
				int state = KSI_ASYNC_STATE_UNDEFINED;

				KSI_LOG_info(ksi, "Read response.");

				KSI_AsyncHandle_getState(respHandle, &state);
				if (res != KSI_OK) {
					fprintf(stderr, "Unable to get request state.\n");
					goto cleanup;
				}

				switch (state) {
					case KSI_ASYNC_STATE_RESPONSE_RECEIVED: {
							KSI_DataHash *reqCtxHash = NULL;
							KSI_DataHash *sigDocHash = NULL;
#ifdef SIG_CREATE_FROM_RESPONSE
							KSI_AggregationResp *resp = NULL;
#endif

							KSI_LOG_info(ksi, "Handle response.");

#ifdef SIG_CREATE_FROM_RESPONSE

							res = KSI_AsyncHandle_getAggregationResp(respHandle, &resp);
							if (res != KSI_OK) {
								fprintf(stderr, "Failed to get aggregation response.\n");
								goto cleanup;
							}

							res = createSignature(resp, &signature);
							if (res != KSI_OK) {
								fprintf(stderr, "Failed to create signature.\n");
								goto cleanup;
							}
#else
							res = KSI_AsyncHandle_getSignature(respHandle, &signature);
							if (res != KSI_OK) {
								fprintf(stderr, "Failed to get signature.\n");
								goto cleanup;
							}
#endif

							res = KSI_AsyncHandle_getRequestCtx(respHandle, (const void**)&reqCtxHash);
							if (res != KSI_OK && reqCtxHash != NULL) {
							  fprintf(stderr, "Unable to get request context.\n");
							  goto cleanup;
							}


							res = KSI_Signature_getDocumentHash(signature, &sigDocHash);
							if (res != KSI_OK && sigDocHash != NULL) {
							  fprintf(stderr, "Unable to get signature document hash.\n");
							  goto cleanup;
							}

							if (!KSI_DataHash_equals(reqCtxHash, sigDocHash)) {
								KSI_LOG_error(ksi, "Request context data mismatch.");
								KSI_LOG_logDataHash(ksi, KSI_LOG_ERROR, "...Context hash ", reqCtxHash);
								KSI_LOG_logDataHash(ksi, KSI_LOG_ERROR, "...Document hash", sigDocHash);
							} else {
								succeeded++;
							}

							KSI_Signature_free(signature);    signature = NULL;
							KSI_AsyncHandle_free(respHandle); respHandle = NULL;
						}
						break;

					case KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED: {
							KSI_Config *pushConf = NULL;

							KSI_LOG_info(ksi, "Handle push configuration.");

							res = KSI_AsyncHandle_getConfig(respHandle, &pushConf);
							if (res != KSI_OK || pushConf != NULL) {
								fprintf(stderr, "Failed to extract push configuration.\n");
								goto cleanup;
							}

							KSI_AsyncHandle_free(respHandle); respHandle = NULL;
						}
						break;

					case KSI_ASYNC_STATE_ERROR: {
							KSI_DataHash *reqCtxHash = NULL;
							int err = KSI_UNKNOWN_ERROR;
							long extErr = 0L;
							KSI_Utf8String *errMsg = NULL;

							KSI_LOG_info(ksi, "Handle error.");

							res = KSI_AsyncHandle_getError(respHandle, &err);
							if (res != KSI_OK) {
								fprintf(stderr, "Unable to get request error.\n");
								goto cleanup;
							}

							res = KSI_AsyncHandle_getErrorMessage(respHandle, &errMsg);
							if (res != KSI_OK) {
								fprintf(stderr, "Unable to get request error message.\n");
								goto cleanup;
							}

							res = KSI_AsyncHandle_getExtError(respHandle, &extErr);
							if (res != KSI_OK) {
								fprintf(stderr, "Unable to get request external error.\n");
								goto cleanup;
							}

							res = KSI_AsyncHandle_getRequestCtx(respHandle, (const void**)&reqCtxHash);
							if (res != KSI_OK && reqCtxHash != NULL) {
								fprintf(stderr, "Unable to get request context.\n");
								goto cleanup;
							}

							KSI_LOG_error(ksi, "Error: [0x%x:%ld] %s (%s).", err, extErr, KSI_getErrorString(err), KSI_Utf8String_cstr(errMsg));
							KSI_LOG_logDataHash(ksi, KSI_LOG_ERROR, "...Context hash.", reqCtxHash);

							KSI_AsyncHandle_free(respHandle);  respHandle = NULL;
						}
						break;

					default:
						/* Do nothing! */
						break;
				}
			}

			res = KSI_AsyncService_getReceivedCount(as, &received);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to get received count.\n");
				goto cleanup;
			}
		} while (received % 100); /* Give it a chance to send new request out. */
	} while (pending || (req_no < nof_requests));

	res = KSI_OK;
cleanup:
	if (nof_requests) {
		printf("Succeeded request: %llu.\n", (unsigned long long)succeeded);
		printf("Failed request   : %llu.\n", (unsigned long long)(nof_requests - succeeded));
		printf("Spent time (sec) : %.0f.\n", difftime(time(NULL), start));
	}

	if (res != KSI_OK && ksi != NULL) {
		KSI_LOG_logCtxError(ksi, KSI_LOG_ERROR);
	}

	if (logFile != NULL) fclose(logFile);

	KSI_Signature_free(signature);
	KSI_AsyncService_free(as);

	KSI_AsyncHandle_free(reqHandle);
	KSI_AsyncHandle_free(respHandle);

	KSI_AggregationReq_free(req);

	KSI_DataHash_free(reqHsh);
#ifdef REQ_ADD_LEVEL
	KSI_Integer_free(reqLvl);
#endif

	KSI_CTX_free(ksi);

	return res;
}
