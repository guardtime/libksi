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

#include <ksi/net_uri.h>
#include <ksi/net_http.h>
#include <ksi/net_tcp.h>
#include <ksi/net_async.h>
#include <ksi/net.h>
#include <ksi/hash.h>

#include "../src/ksi/ctx_impl.h"
#include "../src/ksi/internal.h"

extern KSI_CTX *ctx;
extern KSITest_Conf conf;

static void asyncSigning(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncRequest *asReq = NULL;
	time_t startTime;
	const char *requests[] = {
		"Guardtime", "Keyless", "Signature", "Infrastructure", "(KSI)",
		"is an", "industrial", "scale", "blockchain", "platform",
		"that", "cryptographically", "ensures", "data", "integrity",
		"and", "proves", "time", "of", "existence",
		NULL
	};
	const char **p_req = NULL;
	size_t onHold = 0;

	KSI_LOG_debug(ctx, "%s: START (%s)", __FUNCTION__, url);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	p_req = requests;
	do {
		KSI_AsyncHandle handle = KSI_ASYNC_HANDLE_NULL;

		if (*p_req != NULL) {
			size_t pendingCount = 0;

			KSI_LOG_debug(ctx, "%s: REQUEST (\"%s\").", __FUNCTION__, *p_req);

			if (asReq == NULL) {
				KSI_DataHash *hsh = NULL;
				KSI_AggregationReq *req = NULL;

				res = KSI_DataHash_create(ctx, *p_req, strlen(*p_req), KSI_HASHALG_SHA2_256, &hsh);
				CuAssert(tc, "Unable to create data hash from string.", res == KSI_OK && hsh != NULL);

				res = KSI_AggregationReq_new(ctx, &req);
				CuAssert(tc, "Unable to create aggregation request.", res == KSI_OK && req != NULL);

				res = KSI_AggregationReq_setRequestHash(req, hsh);
				CuAssert(tc, "Unable to set request data hash.", res == KSI_OK);

				res = KSI_AsyncRequest_new(ctx, &asReq);
				CuAssert(tc, "Unable to create async request.", res == KSI_OK && asReq != NULL);

				res = KSI_AsyncRequest_setAggregationReq(asReq, req);
				CuAssert(tc, "Unable to set aggregation request.", res == KSI_OK);

				res = KSI_AsyncRequest_setRequestContext(asReq, (void*)KSI_DataHash_ref(hsh), (void (*)(void*))KSI_DataHash_free);
				CuAssert(tc, "Unable to set request context.", res == KSI_OK);
			}

			res = KSI_AsyncService_addRequest(as, asReq, &handle);
			switch (res) {
				case KSI_OK:
					p_req++;
					KSI_AsyncRequest_free(asReq);
					asReq = NULL;
					CuAssert(tc, "Invalid handle returned.", handle != KSI_ASYNC_HANDLE_NULL);
					break;
				case KSI_ASYNC_MAX_PARALLEL_COUNT_REACHED:
					/* The request could not be added to the cache because of unresponsed requests. */
					/* Wait for a while to avoid busy loop. */
					KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
					sleep_ms(10);
					break;
				default:
					CuAssert(tc, "Unable to add request", res == KSI_OK);
			}

			res = KSI_AsyncService_getPendingCount(as, &pendingCount);
			CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
			CuAssert(tc, "Pending count must be >0.", pendingCount > 0);
		}


		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		handle = KSI_ASYNC_HANDLE_NULL;
		res = KSI_AsyncService_run(as, &handle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (handle != KSI_ASYNC_HANDLE_NULL) {
			int state = KSI_ASYNC_REQ_UNDEFINED;

			res = KSI_AsyncService_getRequestState(as, handle, &state);
			CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_REQ_ERROR);

			switch (state) {
				case KSI_ASYNC_REQ_RESPONSE_RECEIVED: {
						KSI_DataHash *reqHsh = NULL;
						KSI_DataHash *inpHsh = NULL;
						size_t receivedCount = 0;
						KSI_AsyncResponse *asResp = NULL;
						KSI_AggregationResp *resp = NULL;
						KSI_AggregationHashChainList *aggrChainList = NULL;
						KSI_AggregationHashChain *chain = NULL;

						KSI_LOG_debug(ctx, "%s: RESPONSE.", __FUNCTION__);

						res = KSI_AsyncService_getReceivedCount(as, &receivedCount);
						CuAssert(tc, "Unable to get received count.", res == KSI_OK);
						CuAssert(tc, "Received count must be >0.", receivedCount > 0);

						res = KSI_AsyncService_getResponse(as, handle, &asResp);
						CuAssert(tc, "Failed to get async response.", res == KSI_OK && asResp != NULL);

						res = KSI_AsyncResponse_getAggregationResp(asResp, &resp);
						CuAssert(tc, "Failed to get aggregation response.", res == KSI_OK && resp != NULL);

						res = KSI_AsyncResponse_getRequestContext(asResp, (void**)&reqHsh);
						CuAssert(tc, "Unable to get request context.", res == KSI_OK);

						res = KSI_AggregationResp_getAggregationChainList(resp, &aggrChainList);
						CuAssert(tc, "Unable to get aggregation chain list.", res == KSI_OK && aggrChainList != NULL);
						CuAssert(tc, "Unable to get aggregation chain list is emty.", KSI_AggregationHashChainList_length(aggrChainList) > 0);

						res = KSI_AggregationHashChainList_elementAt(aggrChainList, 0, &chain);
						CuAssert(tc, "Unable to get aggregation chain.", res == KSI_OK && chain != NULL);

						res = KSI_AggregationHashChain_getInputHash(chain, &inpHsh);
						CuAssert(tc, "Unable to chain input hash.", res == KSI_OK && inpHsh != NULL);

						CuAssert(tc, "Data hash mismatch.", KSI_DataHash_equals(reqHsh, inpHsh));

						KSI_AsyncResponse_free(asResp);
					}
					break;

#if 0
				case KSI_ASYNC_REQ_ERROR: {
						int err = KSI_UNKNOWN_ERROR;

						KSI_LOG_debug(ctx, "%s: ERROR.", __FUNCTION__);

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
#endif

				default:
					/* Do nothing! */
					break;
			}
		}
	} while (onHold);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_AsyncSignTcp(CuTest* tc) {
	asyncSigning(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
}

CuSuite* AsyncIntegrationTests_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, Test_AsyncSignTcp);

	return suite;
}

