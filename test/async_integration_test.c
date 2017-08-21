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

#include <string.h>
#ifdef _WIN32
#  include <windows.h>
#  define sleep_ms(x) Sleep((x))
#else
#  include <unistd.h>
#  define sleep_ms(x) usleep((x)*1000)
#endif

#include "cutest/CuTest.h"
#include "all_integration_tests.h"
#include <../ksi/net_uri.h>
#include <../ksi/net_http.h>
#include <../ksi/net_tcp.h>
#include <../ksi/net.h>
#include "../src/ksi/ctx_impl.h"
#include "../src/ksi/internal.h"

extern KSI_CTX *ctx;
extern KSITest_Conf conf;

static void asyncSigning(CuTest* tc, const KSITest_ServiceConf *service, const char *scheme) {
#if 0
	int res;
	KSI_AsyncService *as = NULL;
	time_t t_finished;

	KSI_LOG_debug(ctx, "%s START: %s", __FUNCTION__, scheme);
	KSI_ERR_clearErrors(ctx);
	t_finished = time(NULL);

	res = KSI_SigningAsyncService_new(ksi, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK);

	res = KSI_AsyncService_setEndpoint(as, KSITest_composeUri(scheme, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	do {
		KSI_AsyncHandle handle = KSI_ASYNC_HANDLE_NULL;

		if (req_no < nof_requests) {
			char *p_name = argv[ARGV_IN_DATA_FILE_START + req_no];

			if (asReq == NULL) {
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

				res = KSI_AsyncRequest_new(ksi, &asReq);
				if (res == KSI_OK && req == NULL) {
					fprintf(stderr, "Unable to create async request.\n");
					goto cleanup;
				}

				res = KSI_AsyncRequest_setAggregationReq(asReq, req);
				if (res != KSI_OK) {
					fprintf(stderr, "Unable to set aggregation request.\n");
					goto cleanup;
				}
				req = NULL;

				res = KSI_AsyncRequest_setRequestContext(asReq, (void*)p_name, NULL);
				if (res != KSI_OK) {
					fprintf(stderr, "Unable to set request context.\n");
					goto cleanup;
				}
			}

			res = KSI_AsyncService_addRequest(as, asReq, &handle);
			switch (res) {
				case KSI_OK:
					req_no++;
					KSI_AsyncRequest_free(asReq);
					asReq = NULL;
					break;
				case KSI_ASYNC_MAX_PARALLEL_COUNT_REACHED:
					/* The request could not be added to the cache because of unresponsed requests. */
					/* Wait for a while to avoid busy loop. */
					sleep_ms(10);
					break;
				default:
					fprintf(stderr, "Unable to add request.\n");
					goto cleanup;
			}
		}

		handle = KSI_ASYNC_HANDLE_NULL;
		res = KSI_AsyncService_run(as, &handle, &pending);
		if (res != KSI_OK) {
			fprintf(stderr, "Failed to run async service.\n");
			goto cleanup;
		}

		if (handle != KSI_ASYNC_HANDLE_NULL) {
			char *p_name = NULL;
			int state = KSI_ASYNC_REQ_UNDEFINED;

			KSI_LOG_info(ksi, "Read response.");

			KSI_AsyncService_getRequestState(as, handle, &state);
			if (res != KSI_OK) {
				fprintf(stderr, "Unable to get request state.\n");
				goto cleanup;
			}

			switch (state) {
				case KSI_ASYNC_REQ_RESPONSE_RECEIVED:
					res = KSI_AsyncService_getResponse(as, handle, &asResp);
					if (res != KSI_OK) {
						fprintf(stderr, "Failed to get async response.\n");
						goto cleanup;
					}

					if (asResp != NULL) {
						res = KSI_AsyncResponse_getAggregationResp(asResp, &resp);
						if (res != KSI_OK) {
							fprintf(stderr, "Failed to get aggregation response.\n");
							goto cleanup;
						}

						res = KSI_AsyncResponse_getRequestContext(asResp, (void**)&p_name);
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
						KSI_AsyncResponse_free(asResp);
						asResp = NULL;
					}
					break;

				case KSI_ASYNC_REQ_ERROR: {
						int err = KSI_UNKNOWN_ERROR;

						res = KSI_AsyncService_getRequestError(as, handle, &err);
						if (res != KSI_OK) {
							fprintf(stderr, "Unable to get request state.\n");
							goto cleanup;
						}

						res = KSI_AsyncService_getRequestContext(as, handle, (void**)&p_name);
						if (res != KSI_OK) {
							fprintf(stderr, "Unable to get request state.\n");
							goto cleanup;
						}

						fprintf(stderr, "Request for '%s' failed with error: [0x%x] %s\n", p_name, err, KSI_getErrorString(err));

						res = KSI_AsyncService_recover(as, handle, KSI_ASYNC_REC_DROP);
						if (res != KSI_OK) {
							fprintf(stderr, "Failed to apply recover policy on request.\n");
							goto cleanup;
						}
					}
					break;

				default:
					/* Do nothing! */
					break;
			}
		}
	} while (pending);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), t_finished));
#endif
}

void Test_AsyncSignTcp(CuTest* tc) {
	asyncSigning(tc, &conf.aggregator, TEST_SCHEME_TCP);
}

CuSuite* AsyncIntegrationTests_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, Test_AsyncSignTcp);

	return suite;
}

