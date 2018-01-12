/*
 * Copyright 2013-2018 Guardtime, Inc.
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

extern KSI_CTX *ctx;
extern KSITest_Conf conf;

static void verifyOption(CuTest* tc, KSI_AsyncService *s, int opt, size_t defVal, size_t newVal) {
	int res;
	size_t optVal = 0;

	res = KSI_AsyncService_getOption(s, opt, (void *)&optVal);
	CuAssert(tc, "Async service option value mismatch.", res == KSI_OK && optVal == defVal);

	res = KSI_AsyncService_setOption(s, opt, (void *)newVal);
	CuAssert(tc, "Unable to set async service option.", res == KSI_OK);

	res = KSI_AsyncService_getOption(s, opt, (void *)&optVal);
	CuAssert(tc, "Async service option value mismatch.", res == KSI_OK && optVal == newVal);
}

static void async_verifyOptions(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;

	res = KSI_ExtendingAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	verifyOption(tc, as, KSI_ASYNC_OPT_CON_TIMEOUT, 10, 15);
	verifyOption(tc, as, KSI_ASYNC_OPT_RCV_TIMEOUT, 10, 15);
	verifyOption(tc, as, KSI_ASYNC_OPT_SND_TIMEOUT, 10, 15);
	verifyOption(tc, as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, 1, 15);
	verifyOption(tc, as, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, 1, 15);

	KSI_AsyncService_free(as);
}

void Test_AsyncExtendingService_verifyOptions_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	async_verifyOptions(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
}

void Test_AsyncExtendingService_verifyOptions_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	async_verifyOptions(tc, KSITest_composeUri(TEST_SCHEME_HTTP, &conf.extender), conf.extender.user, conf.extender.pass);
}

static void async_verifyCacheSizeOption(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	size_t optVal = 0;

	res = KSI_ExtendingAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)10);
	CuAssert(tc, "Unable to set async service option.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)10);
	CuAssert(tc, "Unable to set async service option.", res == KSI_OK);

	res = KSI_AsyncService_getOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)&optVal);
	CuAssert(tc, "Async service option value mismatch.", res == KSI_OK && optVal == 10);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)(optVal - 1));
	CuAssert(tc, "Unable to set async service option.", res == KSI_INVALID_ARGUMENT);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)(optVal + 1));
	CuAssert(tc, "Unable to set async service option.", res == KSI_OK);

	KSI_AsyncService_free(as);
}

void Test_AsyncExtendingService_verifyCacheSizeOption_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	async_verifyCacheSizeOption(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
}

void Test_AsyncExtendingService_verifyCacheSizeOption_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	async_verifyCacheSizeOption(tc, KSITest_composeUri(TEST_SCHEME_HTTP, &conf.extender), conf.extender.user, conf.extender.pass);
}

static void createExtendAsyncRequest(CuTest* tc, KSI_uint64_t aggrTime, KSI_uint64_t pubTime, KSI_AsyncHandle **ah) {
	int res;
	KSI_ExtendReq *request = NULL;
	KSI_Integer *aggr_time = NULL;
	KSI_Integer *pub_time = NULL;

	KSI_ERR_clearErrors(ctx);

	/*Create objects*/
	res = KSI_ExtendReq_new(ctx, &request);
	CuAssert(tc, "Unable to create extend request.", res == KSI_OK && request != NULL);

	res = KSI_Integer_new(ctx, aggrTime, &aggr_time);
	CuAssert(tc, "Unable to aggr time.", res == KSI_OK && aggr_time != NULL);

	res = KSI_ExtendReq_setAggregationTime(request, aggr_time);
	CuAssert(tc, "Unable set aggre time.", res == KSI_OK);

	if (pubTime != 0) {
		res = KSI_Integer_new(ctx, pubTime, &pub_time);
		CuAssert(tc, "Unable to pub time.", res == KSI_OK && pub_time != NULL);

		res = KSI_ExtendReq_setPublicationTime(request, pub_time);
		CuAssert(tc, "Unable set pub time.", res == KSI_OK);
	}

	res = KSI_AsyncExtendHandle_new(ctx, request, ah);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && *ah != NULL);
}

static void asyncExtend_loop_getResponse(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	time_t startTime;
	const size_t nofReqs = 10;
	size_t reqNo = 0;
	size_t onHold = 0;
	size_t received = 0;

	KSI_LOG_debug(ctx, "%s: START (%s)", __FUNCTION__, url);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_ExtendingAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, (void *)(1 << 3));
	CuAssert(tc, "Unable to set maximum request count.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void*)(nofReqs));
	CuAssert(tc, "Unable to set request cache size.", res == KSI_OK);

	do {
		KSI_AsyncHandle *respHandle = NULL;
		int state = KSI_ASYNC_STATE_UNDEFINED;

		if (reqNo < nofReqs) {
			const size_t reqTime = 1435740789 + reqNo;
			size_t pendingCount = 0;
			KSI_AsyncHandle *reqHandle = NULL;
			KSI_Integer *aggrTime = NULL;
			KSI_ExtendReq *req = NULL;

			KSI_LOG_debug(ctx, "%s: REQUEST (%lu).", __FUNCTION__, (unsigned long)reqTime);

			res = KSI_ExtendReq_new(ctx, &req);
			CuAssert(tc, "Unable to create extend request.", res == KSI_OK && req != NULL);

			res = KSI_Integer_new(ctx, reqTime, &aggrTime);
			CuAssert(tc, "Unable to aggr time.", res == KSI_OK && aggrTime != NULL);

			res = KSI_ExtendReq_setAggregationTime(req, aggrTime);
			CuAssert(tc, "Unable set aggre time.", res == KSI_OK);

			res = KSI_AsyncExtendHandle_new(ctx, req, &reqHandle);
			CuAssert(tc, "Unable to create async request.", res == KSI_OK && reqHandle != NULL);

			res = KSI_AsyncHandle_setRequestCtx(reqHandle, (void*)KSI_Integer_ref(aggrTime), (void (*)(void*))KSI_Integer_free);
			CuAssert(tc, "Unable to set request context.", res == KSI_OK);

			res = KSI_AsyncService_addRequest(as, reqHandle);
			CuAssert(tc, "Unable to add request", res == KSI_OK);
			reqNo++;

			res = KSI_AsyncService_getPendingCount(as, &pendingCount);
			CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
			CuAssert(tc, "Pending count must be >0.", pendingCount > 0);
		}

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		res = KSI_AsyncService_run(as, &respHandle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (respHandle == NULL) {
			if (reqNo == nofReqs) {
				/* There is nothing to be sent. */
				/* Wait for a while to avoid busy loop. */
				KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
				sleep_ms(50);
			}
			continue;
		}

		res = KSI_AsyncHandle_getState(respHandle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);

		switch (state) {
			case KSI_ASYNC_STATE_RESPONSE_RECEIVED: {
					KSI_Integer *reqCtx = NULL;
					KSI_Integer *aggrTime = NULL;
					KSI_ExtendResp *resp = NULL;
					KSI_CalendarHashChain *calChain = NULL;
					KSI_Signature *ext = NULL;
					int error = 0;
					long errorExt = 0;
					KSI_Utf8String *msg = NULL;

					KSI_LOG_debug(ctx, "%s: RESPONSE.", __FUNCTION__);

					res = KSI_AsyncHandle_getExtendResp(respHandle, &resp);
					CuAssert(tc, "Failed to get aggregation response.", res == KSI_OK && resp != NULL);

					res = KSI_AsyncHandle_getRequestCtx(respHandle, (const void**)&reqCtx);
					CuAssert(tc, "Unable to get request context.", res == KSI_OK && reqCtx != NULL);

					res = KSI_ExtendResp_getCalendarHashChain(resp, &calChain);
					CuAssert(tc, "Unable to get aggregation chain list.", res == KSI_OK && calChain != NULL);

					KSI_CalendarHashChain_getAggregationTime(calChain, &aggrTime);
					CuAssert(tc, "Unable to get aggregation time.", res == KSI_OK && aggrTime != NULL);

					CuAssert(tc, "Aggregation time mismatch.", KSI_Integer_compare(reqCtx, aggrTime) == 0);

					res = KSI_AsyncHandle_getSignature(respHandle, &ext);
					CuAssert(tc, "Initial signature is not provided.", res == KSI_INVALID_STATE && ext == NULL);

					res = KSI_AsyncHandle_getError(respHandle, &error);
					CuAssert(tc, "There should be no error.", res == KSI_OK && error == KSI_OK);

					res = KSI_AsyncHandle_getExtError(respHandle, &errorExt);
					CuAssert(tc, "There should be no external error.", res == KSI_OK && errorExt == 0);

					res = KSI_AsyncHandle_getErrorMessage(respHandle, &msg);
					CuAssert(tc, "There should be no error message.", res == KSI_OK && msg == NULL);

					received++;

					KSI_Signature_free(ext);
				}
				break;

			case KSI_ASYNC_STATE_ERROR:
				CuFail(tc, "Requests must succeed.");
				break;

			default:
				CuFail(tc, "Unknown state for finalized request.");
				break;
		}

		KSI_AsyncHandle_free(respHandle);
	} while (onHold);
	CuAssert(tc, "Response count mismatch.", nofReqs == received);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_AsyncExtend_loop_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_loop_getResponse(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
}

void Test_AsyncExtend_loop_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_loop_getResponse(tc, KSITest_composeUri(TEST_SCHEME_HTTP, &conf.extender), conf.extender.user, conf.extender.pass);
}

static void Test_AsyncExtend_noEndpoint_addRequest(CuTest* tc) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_ExtendingAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	createExtendAsyncRequest(tc, 1435740789, 1435827189, &handle);
	CuAssert(tc, "Unable to create dummy request", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request", res == KSI_INVALID_STATE);

	KSI_AsyncHandle_free(handle);
	KSI_AsyncService_free(as);
}

static void async_getError(CuTest* tc, const char *url, const char *user, const char *pass, int expected, long external) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;
	time_t startTime;
	size_t onHold = 0;

	KSI_LOG_debug(ctx, "%s: START (%s)", __FUNCTION__, url);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_ExtendingAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s: REQUEST", __FUNCTION__);

	createExtendAsyncRequest(tc, 1435740789, 1435827189, &handle);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request", res == KSI_OK);

	do {
		int state = KSI_ASYNC_STATE_UNDEFINED;
		int err = KSI_UNKNOWN_ERROR;
		long ext = 0;

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		handle = NULL;
		res = KSI_AsyncService_run(as, &handle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (handle == NULL) {
			/* There is nothing has been received. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(50);
			continue;
		}

		res = KSI_AsyncHandle_getState(handle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);
		CuAssert(tc, "Requests must fail.", state == KSI_ASYNC_STATE_ERROR);

		KSI_LOG_debug(ctx, "%s: ERROR.", __FUNCTION__);

		res = KSI_AsyncHandle_getError(handle, &err);
		CuAssert(tc, "Unable to get request error.", res == KSI_OK);
		CuAssert(tc, "Wrong error.", err == expected);
		res = KSI_AsyncHandle_getExtError(handle, &ext);
		CuAssert(tc, "Unable to get request error.", res == KSI_OK);
		CuAssert(tc, "Wrong extenral error.", ext == external);

		KSI_AsyncHandle_free(handle);
	} while (onHold);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_AsyncExtend_useAggregator_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	async_getError(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass, KSI_INVALID_FORMAT, 0);
}

void Test_AsyncExtend_useAggregator_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	async_getError(tc, KSITest_composeUri(TEST_SCHEME_HTTP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass, KSI_HTTP_ERROR, 400);
}

static void asyncExtend_toFuture(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;
	time_t startTime;
	size_t onHold = 0;

	KSI_LOG_debug(ctx, "%s: START (%s)", __FUNCTION__, url);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_ExtendingAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s: REQUEST", __FUNCTION__);

	createExtendAsyncRequest(tc, 1435740789ll, 2435827189ll, &handle);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request", res == KSI_OK);

	do {
		int state = KSI_ASYNC_STATE_UNDEFINED;
		int err = KSI_UNKNOWN_ERROR;

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		handle = NULL;
		res = KSI_AsyncService_run(as, &handle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (handle == NULL) {
			/* There is nothing has been received. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(50);
			continue;
		}

		res = KSI_AsyncHandle_getState(handle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);
		CuAssert(tc, "Requests must fail.", state == KSI_ASYNC_STATE_ERROR);

		KSI_LOG_debug(ctx, "%s: ERROR.", __FUNCTION__);

		res = KSI_AsyncHandle_getError(handle, &err);
		CuAssert(tc, "Unable to get request error.", res == KSI_OK);
		CuAssert(tc, "An error code should be returned.", err != KSI_OK);

		KSI_AsyncHandle_free(handle);
	} while (onHold);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_AsyncExtend_toFuture_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_toFuture(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
}

void Test_AsyncExtend_toFuture_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_toFuture(tc, KSITest_composeUri(TEST_SCHEME_HTTP, &conf.extender), conf.extender.user, conf.extender.pass);
}

static void asyncExtend_addEmptyReq(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;
	KSI_ExtendReq *req = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_ExtendingAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_ExtendReq_new(ctx, &req);
	CuAssert(tc, "Unable to create aggregation request.", res == KSI_OK && req != NULL);

	res = KSI_AsyncExtendHandle_new(ctx, req, &handle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request", res != KSI_OK && res != KSI_ASYNC_REQUEST_CACHE_FULL);

	KSI_AsyncHandle_free(handle);
	KSI_AsyncService_free(as);
}

void Test_AsyncExtend_addEmptyRequest_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_addEmptyReq(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
}

void Test_AsyncExtend_addEmptyRequest_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_addEmptyReq(tc, KSITest_composeUri(TEST_SCHEME_HTTP, &conf.extender), conf.extender.user, conf.extender.pass);
}

static void asyncExtend_runEmpty(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *hndl = NULL;
	size_t onHold = 0;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_ExtendingAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &hndl, &onHold);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Waiting count mismatch.", onHold == 0);
	CuAssert(tc, "Invalid handle returned.", hndl == NULL);

	KSI_AsyncService_free(as);
}

void Test_AsyncExtend_runEmpty_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_runEmpty(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
}

void Test_AsyncExtend_runEmpty_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_runEmpty(tc, KSITest_composeUri(TEST_SCHEME_HTTP, &conf.extender), conf.extender.user, conf.extender.pass);
}

static void asyncExtend_requestConfigOnly(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;
	time_t startTime;
	size_t onHold = 0;
	KSI_ExtendReq *request = NULL;
	KSI_Config *cfg = NULL;
	size_t pendingCount = 0;

	KSI_LOG_debug(ctx, "%s: START (%s)", __FUNCTION__, url);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_ExtendingAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s: REQUEST", __FUNCTION__);

	res = KSI_ExtendReq_new(ctx, &request);
	CuAssert(tc, "Unable to create extend request.", res == KSI_OK && request != NULL);

	res = KSI_Config_new(ctx, &cfg);
	CuAssert(tc, "Unable to create config object.", res == KSI_OK && cfg != NULL);

	res = KSI_ExtendReq_setConfig(request, cfg);
	CuAssert(tc, "Unable to set request data hash.", res == KSI_OK);

	res = KSI_AsyncExtendHandle_new(ctx, request, &handle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request", res == KSI_OK);

	res = KSI_AsyncService_getPendingCount(as, &pendingCount);
	CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
	CuAssert(tc, "Pending count must be 1.", pendingCount == 1);

	do {
		int state = KSI_ASYNC_STATE_UNDEFINED;
		KSI_Config *respCfg = NULL;

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		handle = NULL;
		res = KSI_AsyncService_run(as, &handle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (handle == NULL) {
			/* There is nothing has been received. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(50);
			continue;
		}

		res = KSI_AsyncHandle_getState(handle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);
		CuAssert(tc, "Invalid handle state.", state == KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED);

		KSI_LOG_debug(ctx, "%s: RESPONSE.", __FUNCTION__);

		res = KSI_AsyncHandle_getConfig(handle, &respCfg);
		CuAssert(tc, "Unable to get server config.", res == KSI_OK && respCfg != NULL);

		KSI_AsyncHandle_free(handle);
	} while (onHold);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_AsyncExtend_requestConfigOnly_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_requestConfigOnly(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
}

void Test_AsyncExtend_requestConfigOnly_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_requestConfigOnly(tc, KSITest_composeUri(TEST_SCHEME_HTTP, &conf.extender), conf.extender.user, conf.extender.pass);
}

static void asyncExtend_requestConfigWithReq(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;
	KSI_ExtendReq *request = NULL;
	KSI_Integer *aggrTime = NULL;
	time_t startTime;
	size_t onHold = 0;
	KSI_Config *cfg = NULL;
	size_t pendingCount = 0;
	char confReceived = 0;
	char respReceived = 0;

	KSI_LOG_debug(ctx, "%s: START (%s)", __FUNCTION__, url);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_ExtendingAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s: REQUEST", __FUNCTION__);

	res = KSI_ExtendReq_new(ctx, &request);
	CuAssert(tc, "Unable to create extend request.", res == KSI_OK && request != NULL);

	res = KSI_Config_new(ctx, &cfg);
	CuAssert(tc, "Unable to create config object.", res == KSI_OK && cfg != NULL);

	res = KSI_ExtendReq_setConfig(request, cfg);
	CuAssert(tc, "Unable to set request data hash.", res == KSI_OK);

	res = KSI_Integer_new(ctx, 1435740789, &aggrTime);
	CuAssert(tc, "Unable to aggr time.", res == KSI_OK && aggrTime != NULL);

	res = KSI_ExtendReq_setAggregationTime(request, aggrTime);
	CuAssert(tc, "Unable set aggre time.", res == KSI_OK);

	res = KSI_AsyncExtendHandle_new(ctx, request, &handle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request", res == KSI_OK);

	res = KSI_AsyncService_getPendingCount(as, &pendingCount);
	CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
	CuAssert(tc, "Pending count must be 2.", pendingCount == 2);

	do {
		KSI_AsyncHandle *respHandle = NULL;
		int state = KSI_ASYNC_STATE_UNDEFINED;

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		res = KSI_AsyncService_run(as, &respHandle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (respHandle == NULL) {
			/* There is nothing has been received. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(50);
			continue;
		}

		res = KSI_AsyncHandle_getState(respHandle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);

		switch (state) {
			case KSI_ASYNC_STATE_RESPONSE_RECEIVED: {
					KSI_ExtendResp *resp = NULL;

					KSI_LOG_debug(ctx, "%s: RESPONSE.", __FUNCTION__);

					res = KSI_AsyncHandle_getExtendResp(respHandle, &resp);
					CuAssert(tc, "Failed to get extend response.", res == KSI_OK && resp != NULL);

					respReceived = 1;
				}
				break;

			case KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED: {
					KSI_Config *respCfg = NULL;

					KSI_LOG_debug(ctx, "%s: CONFIG RESPONSE.", __FUNCTION__);

					res = KSI_AsyncHandle_getConfig(respHandle, &respCfg);
					CuAssert(tc, "Unable to get server config.", res == KSI_OK && respCfg != NULL);

					confReceived = 1;
				}
				break;

			case KSI_ASYNC_STATE_ERROR:
				CuFail(tc, "Requests must succeed.");
				break;

			default:
				CuFail(tc, "Unknown state for finalized request.");
				break;
		}
		KSI_AsyncHandle_free(respHandle);
	} while (onHold);
	CuAssert(tc, "Configuration response should have been received.", confReceived);
	CuAssert(tc, "Extend response should have been received.", respReceived);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_AsyncExtend_requestConfigWithReq_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_requestConfigWithReq(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
}

void Test_AsyncExtend_requestConfigWithReq_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_requestConfigWithReq(tc, KSITest_composeUri(TEST_SCHEME_HTTP, &conf.extender), conf.extender.user, conf.extender.pass);
}

static void asyncExtend_signature(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;
	KSI_ExtendReq *request = NULL;
	KSI_Integer *signTime = NULL;
	time_t startTime;
	size_t onHold = 0;
	char respReceived = 0;
	KSI_Signature *sig = NULL;

	KSI_LOG_debug(ctx, "%s: START (%s)", __FUNCTION__, url);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath("resource/tlv/ok-sig-2014-07-01.1.ksig"), &sig);
	CuAssert(tc, "Unable to read signature frome file.", res == KSI_OK && sig != NULL);

	res = KSI_ExtendingAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s: REQUEST", __FUNCTION__);

	res = KSI_AsyncExtendingHandle_new(ctx, sig, NULL, &handle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request", res == KSI_OK);

	do {
		KSI_AsyncHandle *respHandle = NULL;
		int state = KSI_ASYNC_STATE_UNDEFINED;

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		res = KSI_AsyncService_run(as, &respHandle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (respHandle == NULL) {
			/* There is nothing has been received. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(50);
			continue;
		}

		res = KSI_AsyncHandle_getState(respHandle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);

		switch (state) {
			case KSI_ASYNC_STATE_RESPONSE_RECEIVED: {
					KSI_ExtendResp *resp = NULL;
					KSI_Signature *ext = NULL;

					KSI_LOG_debug(ctx, "%s: RESPONSE.", __FUNCTION__);

					res = KSI_AsyncHandle_getExtendResp(respHandle, &resp);
					CuAssert(tc, "Failed to get extend response.", res == KSI_OK && resp != NULL);

					res = KSI_AsyncHandle_getSignature(respHandle, &ext);
					CuAssert(tc, "Failed to get extended signature.", res == KSI_OK && ext != NULL);

					/* Signature has been verified internally. */
					res = KSI_Signature_verifyWithPolicy(sig, NULL, 0, KSI_VERIFICATION_POLICY_CALENDAR_BASED, NULL);
					CuAssert(tc, "Calendar-based verification should succeed", res == KSI_OK);

					res = KSI_verifySignature(ctx, ext);
					CuAssert(tc, "Genaral policy should fail with NA.", res == KSI_VERIFICATION_FAILURE);

					KSI_Signature_free(ext);
					respReceived = 1;
				}
				break;

			default:
				CuFail(tc, "Unexpected state.");
				break;
		}
		KSI_AsyncHandle_free(respHandle);
	} while (onHold);
	CuAssert(tc, "Extend response should have been received.", respReceived);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_Signature_free(sig);
	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_AsyncExtend_signature_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_signature(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
}

void Test_AsyncExtend_signature_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtend_signature(tc, KSITest_composeUri(TEST_SCHEME_HTTP, &conf.extender), conf.extender.user, conf.extender.pass);
}

CuSuite* AsyncExtIntegrationTests_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	/* Common test cases. */
	SUITE_ADD_TEST(suite, Test_AsyncExtend_noEndpoint_addRequest);

	/* TCP test cases. */
	SUITE_ADD_TEST(suite, Test_AsyncExtendingService_verifyOptions_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncExtendingService_verifyCacheSizeOption_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_useAggregator_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_toFuture_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_runEmpty_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_addEmptyRequest_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_requestConfigOnly_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_requestConfigWithReq_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_loop_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_signature_tcp);

	/* HTTP test cases. */
	SUITE_ADD_TEST(suite, Test_AsyncExtendingService_verifyOptions_http);
	SUITE_ADD_TEST(suite, Test_AsyncExtendingService_verifyCacheSizeOption_http);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_useAggregator_http);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_toFuture_http);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_runEmpty_http);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_addEmptyRequest_http);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_requestConfigOnly_http);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_requestConfigWithReq_http);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_loop_http);
	SUITE_ADD_TEST(suite, Test_AsyncExtend_signature_http);

	return suite;
}


