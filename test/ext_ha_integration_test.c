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
#include <ksi/net_ha.h>
#include <ksi/net.h>
#include <ksi/hash.h>

extern KSI_CTX *ctx;
extern KSITest_Conf conf;

static const size_t NOF_TEST_REQUESTS = 5;

void Test_HaExtend_verifySubserviceListOption(CuTest* tc) {
	int res;
	KSI_AsyncService *s = NULL;
	size_t optVal = 0;

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &s);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && s != NULL);

	res = KSI_AsyncService_addEndpoint(s,
			KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(s, KSI_ASYNC_OPT_HA_SUBSERVICE_LIST, NULL);
	CuAssert(tc, "Getter only option.", res == KSI_INVALID_ARGUMENT);

	res = KSI_AsyncService_getOption(s, KSI_ASYNC_OPT_HA_SUBSERVICE_LIST, (void *)&optVal);
	CuAssert(tc, "Async service option value mismatch.", res == KSI_OK &&
			KSI_AsyncServiceList_length((KSI_AsyncServiceList*)optVal) == 1);

	res = KSI_AsyncService_addEndpoint(s,
			KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_getOption(s, KSI_ASYNC_OPT_HA_SUBSERVICE_LIST, (void *)&optVal);
	CuAssert(tc, "Async service option value mismatch.", res == KSI_OK &&
			KSI_AsyncServiceList_length((KSI_AsyncServiceList*)optVal) == 2);

	res = KSI_AsyncService_addEndpoint(s,
			KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_getOption(s, KSI_ASYNC_OPT_HA_SUBSERVICE_LIST, (void *)&optVal);
	CuAssert(tc, "Async service option value mismatch.", res == KSI_OK &&
			KSI_AsyncServiceList_length((KSI_AsyncServiceList*)optVal) == 3);

	res = KSI_AsyncService_setEndpoint(s,
			KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_getOption(s, KSI_ASYNC_OPT_HA_SUBSERVICE_LIST, (void *)&optVal);
	CuAssert(tc, "Async service option value mismatch.", res == KSI_OK &&
			KSI_AsyncServiceList_length((KSI_AsyncServiceList*)optVal) == 1);

	KSI_AsyncService_free(s);
}

static void verifyOption(CuTest* tc, KSI_AsyncService *s, int opt, size_t defVal, size_t newVal) {
	int res;
	size_t optVal = 0;

	res = KSI_AsyncService_getOption(s, opt, (void *)&optVal);
	CuAssert(tc, "Async service option value mismatch.", res == KSI_OK && optVal == defVal);

	res = KSI_AsyncService_setOption(s, opt, (void *)newVal);
	CuAssert(tc, "Unable to set async service option.", res == KSI_OK);

	optVal = 0;
	res = KSI_AsyncService_getOption(s, opt, (void *)&optVal);
	CuAssert(tc, "Async service option value mismatch.", res == KSI_OK && optVal == newVal);
}

static void asyncExtending_verifyOptions(CuTest* tc, const char *scheme) {
	int res;
	KSI_AsyncService *has = NULL;

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, scheme, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	verifyOption(tc, has, KSI_ASYNC_OPT_CON_TIMEOUT, 10, 15);
	verifyOption(tc, has, KSI_ASYNC_OPT_RCV_TIMEOUT, 10, 15);
	verifyOption(tc, has, KSI_ASYNC_OPT_SND_TIMEOUT, 10, 15);
	verifyOption(tc, has, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, 1, 15);
	verifyOption(tc, has, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, 1, 15);

	KSI_AsyncService_free(has);
}

void Test_HaExtend_verifyOptions_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_verifyOptions(tc, TEST_SCHEME_TCP);
}

void Test_HaExtend_verifyOptions_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_verifyOptions(tc, TEST_SCHEME_HTTP);
}

static void asyncExtending_verifyCacheSizeOption(CuTest* tc, const char *scheme) {
	int res;
	KSI_AsyncService *has = NULL;
	size_t optVal = 0;

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, scheme, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(has, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)10);
	CuAssert(tc, "Unable to set async service option.", res == KSI_OK);

	res = KSI_AsyncService_getOption(has, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)&optVal);
	CuAssert(tc, "Async service option value mismatch.", res == KSI_OK && optVal == 10);

	res = KSI_AsyncService_setOption(has, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)(optVal - 1));
	CuAssert(tc, "Unable to set async service option.", res == KSI_INVALID_ARGUMENT);

	res = KSI_AsyncService_setOption(has, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)(optVal + 1));
	CuAssert(tc, "Unable to set async service option.", res == KSI_OK);

	KSI_AsyncService_free(has);
}

void Test_HaExtend_verifyCacheSizeOption_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_verifyCacheSizeOption(tc, TEST_SCHEME_TCP);
}

void Test_HaExtend_verifyCacheSizeOption_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_verifyCacheSizeOption(tc, TEST_SCHEME_HTTP);
}

static void asyncExtending_loop_getResponse(CuTest* tc, KSI_AsyncService *as) {
	int res;
	time_t startTime;
	const size_t nofReqs = 10;
	size_t reqNo = 0;
	size_t onHold = 0;
	size_t received = 0;
	size_t slept = 0;

	KSI_LOG_debug(ctx, "%s: START", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, (void *)(1 << 3));
	CuAssert(tc, "Unable to set maximum request count.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void*)(NOF_TEST_REQUESTS));
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
			CuAssert(tc, "No response within timeout.", slept < conf.async.timeout.cumulative);

			/* There is nothing to be sent. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(conf.async.timeout.sleep);
			slept += conf.async.timeout.sleep;
			continue;
		}
		slept = 0;

		res = KSI_AsyncHandle_getState(respHandle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);
		switch (state) {
			case KSI_ASYNC_STATE_RESPONSE_RECEIVED: {
					KSI_Integer *reqCtx = NULL;
					KSI_Integer *aggrTime = NULL;
					KSI_ExtendResp *resp = NULL;
					KSI_CalendarHashChain *calChain = NULL;
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

					res = KSI_AsyncHandle_getError(respHandle, &error);
					CuAssert(tc, "There should be no error.", res == KSI_OK && error == KSI_OK);

					res = KSI_AsyncHandle_getExtError(respHandle, &errorExt);
					CuAssert(tc, "There should be no external error.", res == KSI_OK && errorExt == 0);

					res = KSI_AsyncHandle_getErrorMessage(respHandle, &msg);
					CuAssert(tc, "There should be no error message.", res == KSI_OK && msg == NULL);

					received++;
				}
				break;
			case KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED:
				/* do nothing. */
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

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_HaExtend_loop_tcp(CuTest* tc) {
	int res;
	KSI_AsyncService *has = NULL;

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, TEST_SCHEME_TCP, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_loop_getResponse(tc, has);

	KSI_AsyncService_free(has);
}

void Test_HaExtend_loop_http(CuTest* tc) {
	int res;
	KSI_AsyncService *has = NULL;

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, TEST_SCHEME_HTTP, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_loop_getResponse(tc, has);

	KSI_AsyncService_free(has);
}

void Test_HaExtend_loopResetEndpointLoop_tcp(CuTest* tc) {
	int res;
	KSI_AsyncService *has = NULL;

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, TEST_SCHEME_TCP, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_loop_getResponse(tc, has);

	res = KSI_AsyncService_setEndpoint(has,
			KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_loop_getResponse(tc, has);

	KSI_AsyncService_free(has);
}

void Test_HaExtend_loopResetEndpointLoop_http(CuTest* tc) {
	int res;
	KSI_AsyncService *has = NULL;

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, TEST_SCHEME_HTTP, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_loop_getResponse(tc, has);

	res = KSI_AsyncService_setEndpoint(has,
			KSITest_composeUri(TEST_SCHEME_HTTP, &conf.extender), conf.extender.user, conf.extender.pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_loop_getResponse(tc, has);

	KSI_AsyncService_free(has);
}

void Test_HaExtend_loop_http_tcp_http(CuTest* tc) {
	int res;
	KSI_AsyncService *has = NULL;

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	if (strlen(conf.ha.extender[0].host) == 0) {
		KSI_LOG_debug(ctx, "%s: testing with common extender conf.", __FUNCTION__);

		res = KSI_AsyncService_addEndpoint(has,
				KSITest_composeUri(TEST_SCHEME_HTTP, &conf.extender), conf.extender.user, conf.extender.pass);
		CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);
	} else {
		res = KSI_AsyncService_addEndpoint(has,
				KSITest_composeUri(TEST_SCHEME_HTTP, &conf.ha.extender[0]), conf.ha.extender[0].user, conf.ha.extender[0].pass);
		CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

		if (strlen(conf.ha.extender[1].host) != 0) {
			res = KSI_AsyncService_addEndpoint(has,
					KSITest_composeUri(TEST_SCHEME_TCP, &conf.ha.extender[1]), conf.ha.extender[1].user, conf.ha.extender[1].pass);
			CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);
		}

		if (strlen(conf.ha.extender[2].host) != 0) {
			res = KSI_AsyncService_addEndpoint(has,
					KSITest_composeUri(TEST_SCHEME_HTTP, &conf.ha.extender[2]), conf.ha.extender[2].user, conf.ha.extender[2].pass);
			CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);
		}
	}

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_loop_getResponse(tc, has);

	KSI_AsyncService_free(has);
}

void Test_HaExtend_loop_tcp_http_tcp(CuTest* tc) {
	int res;
	KSI_AsyncService *has = NULL;

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	if (strlen(conf.ha.extender[0].host) == 0) {
		KSI_LOG_debug(ctx, "%s: testing with common extender conf.", __FUNCTION__);

		res = KSI_AsyncService_addEndpoint(has,
				KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
		CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);
	} else {
		res = KSI_AsyncService_addEndpoint(has,
				KSITest_composeUri(TEST_SCHEME_TCP, &conf.ha.extender[0]), conf.ha.extender[0].user, conf.ha.extender[0].pass);
		CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

		if (strlen(conf.ha.extender[1].host) != 0) {
			res = KSI_AsyncService_addEndpoint(has,
					KSITest_composeUri(TEST_SCHEME_HTTP, &conf.ha.extender[1]), conf.ha.extender[1].user, conf.ha.extender[1].pass);
			CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);
		}

		if (strlen(conf.ha.extender[2].host) != 0) {
			res = KSI_AsyncService_addEndpoint(has,
					KSITest_composeUri(TEST_SCHEME_TCP, &conf.ha.extender[2]), conf.ha.extender[2].user, conf.ha.extender[2].pass);
			CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);
		}
	}

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_loop_getResponse(tc, has);

	KSI_AsyncService_free(has);
}


static void asyncExtending_collect_getResponse(CuTest* tc, const char *scheme) {
	int res;
	KSI_AsyncService *as = NULL;
	time_t startTime;
	const size_t nofReqs = 10;
	size_t added = 0;
	size_t received = 0;
	size_t slept = 0;
	size_t prevCount = 0;
	KSI_List *list = NULL;

	KSI_LOG_debug(ctx, "%s: START", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(as, scheme, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, (void *)(1 << 3));
	CuAssert(tc, "Unable to set maximum request count.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void*)(nofReqs));
	CuAssert(tc, "Unable to set request cache size.", res == KSI_OK);

	res = KSI_List_new(NULL, &list);
	CuAssert(tc, "Unable to create new list.", res == KSI_OK && list != NULL);


	while (added < nofReqs) {
		const size_t reqTime = 1435740789 + added;
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

		res = KSI_List_append(list, aggrTime);
		CuAssert(tc, "Unable to append to list.", res == KSI_OK);

		res = KSI_AsyncService_getPendingCount(as, &pendingCount);
		CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
		CuAssert(tc, "Pending count mitmatch.", pendingCount == ++added);
	}

	do {
		KSI_AsyncHandle *respHandle = NULL;
		int state = KSI_ASYNC_STATE_UNDEFINED;
		slept = 0;
		prevCount = received;

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);
		CuAssert(tc, "No response within timeout.", slept < KSITEST_ASYNC_NO_RESP_TIMEOUT_MS * 5);

		res = KSI_AsyncService_run(as, &respHandle, NULL);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (respHandle != NULL) {
			res = KSI_AsyncHandle_getState(respHandle, &state);
			CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);

			switch (state) {
				case KSI_ASYNC_STATE_RESPONSE_RECEIVED: {
					KSI_ExtendResp *resp = NULL;
					char *reqCtx = NULL;
					size_t pos;
					int found = 0;

					KSI_LOG_debug(ctx, "%s: RESPONSE.", __FUNCTION__);

					res = KSI_AsyncHandle_getRequestCtx(respHandle, (const void**)&reqCtx);
					CuAssert(tc, "Unable to get service request context.", res == KSI_OK && reqCtx != NULL);

					res = KSI_List_find(list, (void*)reqCtx, &found, &pos);
					CuAssert(tc, "Unable to get index.", res == KSI_OK && found != 0);

					res = KSI_List_remove(list, pos, NULL);
					CuAssert(tc, "Unable to remove from list.", res == KSI_OK);

					res = KSI_AsyncHandle_getExtendResp(respHandle, &resp);
					CuAssert(tc, "Failed to get extension response.", res == KSI_OK && resp != NULL);
					}
					received++;
					break;
				case KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED:
					/* do nothing. */
					break;

				case KSI_ASYNC_STATE_ERROR:
					CuFail(tc, "Requests must succeed.");
					break;

				default:
					CuFail(tc, "Unknown state for finalized request.");
					break;
			}

			KSI_AsyncHandle_free(respHandle);
		}

		if (received == prevCount) {
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(KSITEST_ASYNC_SLEEP_TIME_MS);
			slept += KSITEST_ASYNC_SLEEP_TIME_MS;
		} else {
			slept = 0;
		}

	} while (received != added);

	CuAssert(tc, "Response count mismatch.", added == received);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_List_free(list);
	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_HaExtend_collect_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_collect_getResponse(tc, TEST_SCHEME_TCP);
}

void Test_HaExtend_collect_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_collect_getResponse(tc, TEST_SCHEME_HTTP);
}

static void asyncExtending_getError(CuTest* tc, const char *scheme, KSITest_ServiceConf *srvCfg, KSITest_ServiceConf *haCfg, int expected, long external) {
	int res;
	const size_t reqTime = 1435740789;
	KSI_Integer *aggrTime = NULL;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;
	time_t startTime;
	size_t onHold = 0;
	KSI_ExtendReq *req = NULL;
	size_t slept = 0;

	KSI_LOG_debug(ctx, "%s: START", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(as, scheme, srvCfg, haCfg);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s: REQUEST", __FUNCTION__);

	res = KSI_ExtendReq_new(ctx, &req);
	CuAssert(tc, "Unable to create extend request.", res == KSI_OK && req != NULL);

	res = KSI_Integer_new(ctx, reqTime, &aggrTime);
	CuAssert(tc, "Unable to aggr time.", res == KSI_OK && aggrTime != NULL);

	res = KSI_ExtendReq_setAggregationTime(req, aggrTime);
	CuAssert(tc, "Unable set aggre time.", res == KSI_OK);

	res = KSI_AsyncExtendHandle_new(ctx, req, &handle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	do {
		int state = KSI_ASYNC_STATE_UNDEFINED;
		int err = KSI_UNKNOWN_ERROR;
		long ext = 0;

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		handle = NULL;
		res = KSI_AsyncService_run(as, &handle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (handle == NULL) {
			CuAssert(tc, "No response within timeout.", slept < KSITEST_ASYNC_NO_RESP_TIMEOUT_MS);
			/* There is nothing has been received. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(KSITEST_ASYNC_SLEEP_TIME_MS);
			slept += KSITEST_ASYNC_SLEEP_TIME_MS;
			continue;
		}
		slept = 0;

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


void Test_HaExtend_useAggregator_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_getError(tc, TEST_SCHEME_TCP, &conf.aggregator, conf.ha.aggregator, KSI_INVALID_FORMAT, 0);
}

void Test_HaExtend_useAggregator_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_getError(tc, TEST_SCHEME_HTTP, &conf.aggregator, conf.ha.aggregator, KSI_HTTP_ERROR, 400);
}

static int createDummyExtAsyncRequest(KSI_AsyncHandle **ah) {
	int res;
	KSI_AsyncHandle *tmp = NULL;
	KSI_ExtendReq *req = NULL;
	const size_t reqTime = 1435740789;
	KSI_Integer *aggrTime = NULL;

	res = KSI_ExtendReq_new(ctx, &req);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(ctx, reqTime, &aggrTime);
	if (res != KSI_OK) goto cleanup;

	res = KSI_ExtendReq_setAggregationTime(req, aggrTime);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AsyncExtendHandle_new(ctx, req, &tmp);
	if (res != KSI_OK) goto cleanup;
	req = NULL;

	*ah = tmp;
	tmp = NULL;
cleanup:
	KSI_ExtendReq_free(req);
	KSI_AsyncHandle_free(tmp);
	return res;
}

static void asyncExtending_fillupCache(CuTest* tc, const char *scheme) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *hndl = NULL;
	size_t i;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(as, scheme, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void*)(NOF_TEST_REQUESTS));
	CuAssert(tc, "Unable to set request cache size.", res == KSI_OK);

	/* Fill up internal cache. */
	for (i = 0; i < NOF_TEST_REQUESTS; i++) {
		hndl = NULL;
		res = createDummyExtAsyncRequest(&hndl);
		CuAssert(tc, "Unable to create dummy request.", res == KSI_OK && hndl != NULL);

		res = KSI_AsyncService_addRequest(as, hndl);
		CuAssert(tc, "Unable to add request.", res == KSI_OK);
	}
	hndl = NULL;

	/* Try to add one more request. */
	res = createDummyExtAsyncRequest(&hndl);
	CuAssert(tc, "Unable to create dummy request.", res == KSI_OK && hndl != NULL);

	res = KSI_AsyncService_addRequest(as, hndl);
	CuAssert(tc, "Must not be possible to add request to service that is full.", res == KSI_ASYNC_REQUEST_CACHE_FULL);

	KSI_AsyncHandle_free(hndl);
	KSI_AsyncService_free(as);
}

void Test_HaExtend_fillupCache_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_fillupCache(tc, TEST_SCHEME_TCP);
}

void Test_HaExtend_fillupCache_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_fillupCache(tc, TEST_SCHEME_HTTP);
}

static void asyncExtending_addEmptyReq(CuTest* tc, const char *scheme) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;
	KSI_ExtendReq *req = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(as, scheme, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_ExtendReq_new(ctx, &req);
	CuAssert(tc, "Unable to create extension request.", res == KSI_OK && req != NULL);

	res = KSI_AsyncExtendHandle_new(ctx, req, &handle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Must not be possible to add empty request.", res != KSI_OK && res != KSI_ASYNC_REQUEST_CACHE_FULL);

	KSI_AsyncHandle_free(handle);
	KSI_AsyncService_free(as);
}

void Test_HaExtend_addEmptyRequest_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_addEmptyReq(tc, TEST_SCHEME_TCP);
}

void Test_HaExtend_addEmptyRequest_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_addEmptyReq(tc, TEST_SCHEME_HTTP);
}

static void Test_HaExtend_noEndpoint_addRequest(CuTest* tc) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *hndl = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = createDummyExtAsyncRequest(&hndl);
	CuAssert(tc, "Unable to create dummy request.", res == KSI_OK && hndl != NULL);

	res = KSI_AsyncService_addRequest(as, hndl);
	CuAssert(tc, "Must not be possible to add request to service with no endpoint.", res == KSI_INVALID_STATE);

	KSI_AsyncHandle_free(hndl);
	KSI_AsyncService_free(as);
}

void Test_HaExtend_exceedMaxNofSubservices(CuTest* tc) {
	int res;
	KSI_AsyncService *has = NULL;
	size_t i;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	for (i = 0; i < KSI_CTX_HA_MAX_SUBSERVICES; i++) {
		res = KSI_AsyncService_addEndpoint(has,
				KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
		CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);
	}

	res = KSI_AsyncService_addEndpoint(has,
			KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
	CuAssert(tc, "Configuration of service endpoint should fail.", res == KSI_INVALID_STATE);

	res = KSI_CTX_setOption(ctx, KSI_OPT_HA_SAFEGUARD, (void *)(KSI_CTX_HA_MAX_SUBSERVICES + 1));
	CuAssert(tc, "Unable to set KSI_CTX option.", res == KSI_OK);

	res = KSI_AsyncService_addEndpoint(has,
			KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_addEndpoint(has,
			KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
	CuAssert(tc, "Configuration of service endpoint should fail.", res == KSI_INVALID_STATE);

	KSI_AsyncService_free(has);
}

static void asyncExtending_runEmpty(CuTest* tc, const char *scheme) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *hndl = NULL;
	size_t onHold = 0;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(as, scheme, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &hndl, &onHold);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Waiting count mismatch.", onHold == 0);
	CuAssert(tc, "Invalid handle returned.", hndl == NULL);

	KSI_AsyncService_free(as);
}

void Test_HaExtend_runEmpty_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_runEmpty(tc, TEST_SCHEME_TCP);
}

void Test_HaExtend_runEmpty_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_runEmpty(tc, TEST_SCHEME_HTTP);
}

static void asyncExtending_requestConfigOnly(CuTest* tc, KSI_AsyncService *as) {
	int res;
	KSI_AsyncHandle *handle = NULL;
	time_t startTime;
	size_t onHold = 0;
	KSI_ExtendReq *req = NULL;
	KSI_Config *cfg = NULL;
	size_t pendingCount = 0;
	size_t slept = 0;

	KSI_LOG_debug(ctx, "%s: START", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	KSI_LOG_debug(ctx, "%s: REQUEST", __FUNCTION__);

	res = KSI_ExtendReq_new(ctx, &req);
	CuAssert(tc, "Unable to create extension request.", res == KSI_OK && req != NULL);

	res = KSI_Config_new(ctx, &cfg);
	CuAssert(tc, "Unable to create config object.", res == KSI_OK && cfg != NULL);

	res = KSI_ExtendReq_setConfig(req, cfg);
	CuAssert(tc, "Unable to set config request.", res == KSI_OK);

	res = KSI_AsyncExtendHandle_new(ctx, req, &handle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_getPendingCount(as, &pendingCount);
	CuAssert(tc, "Unable to get pending count.", res == KSI_OK);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

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
			CuAssert(tc, "No response within timeout.", slept < (KSITEST_ASYNC_SLEEP_TIME_MS * 10));
			/* There is nothing has been received. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(KSITEST_ASYNC_SLEEP_TIME_MS);
			slept += KSITEST_ASYNC_SLEEP_TIME_MS;
			continue;
		}
		slept = 0;

		res = KSI_AsyncHandle_getState(handle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);
		CuAssert(tc, "Invalid handle state.", state == KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED);

		KSI_LOG_debug(ctx, "%s: RESPONSE.", __FUNCTION__);

		res = KSI_AsyncHandle_getConfig(handle, &respCfg);
		CuAssert(tc, "Unable to get server config.", res == KSI_OK && respCfg != NULL);

		KSI_AsyncHandle_free(handle);
	} while (onHold);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_HaExtend_requestConfigOnly_tcp(CuTest* tc) {
	int res;
	KSI_AsyncService *has = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, TEST_SCHEME_TCP, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	asyncExtending_requestConfigOnly(tc, has);

	KSI_AsyncService_free(has);
}

void Test_HaExtend_requestConfigOnly_http(CuTest* tc) {
	int res;
	KSI_AsyncService *has = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, TEST_SCHEME_HTTP, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	asyncExtending_requestConfigOnly(tc, has);

	KSI_AsyncService_free(has);
}

static size_t callbackCount = 0;
static int dummyCallback(KSI_CTX KSI_UNUSED(*ctx), KSI_Config KSI_UNUSED(*cnf)) {
	callbackCount++;
	return KSI_OK;
}

static void asyncExtending_requestConfigOnlyUseCallback(CuTest* tc, KSI_AsyncService *as) {
	int res;
	KSI_AsyncHandle *handle = NULL;
	time_t startTime;
	size_t onHold = 0;
	KSI_ExtendReq *req = NULL;
	KSI_Config *cfg = NULL;
	size_t pendingCount = 0;
	size_t slept = 0;

	KSI_LOG_debug(ctx, "%s: START", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	KSI_LOG_debug(ctx, "%s: REQUEST", __FUNCTION__);

	res = KSI_ExtendReq_new(ctx, &req);
	CuAssert(tc, "Unable to create extension request.", res == KSI_OK && req != NULL);

	res = KSI_Config_new(ctx, &cfg);
	CuAssert(tc, "Unable to create config object.", res == KSI_OK && cfg != NULL);

	res = KSI_ExtendReq_setConfig(req, cfg);
	CuAssert(tc, "Unable to set config request.", res == KSI_OK);

	res = KSI_AsyncExtendHandle_new(ctx, req, &handle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_getPendingCount(as, &pendingCount);
	CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
	CuAssert(tc, "Pending count must be 1.", pendingCount == 1);

	callbackCount = 0;
	do {
		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		handle = NULL;
		res = KSI_AsyncService_run(as, &handle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);
		CuAssert(tc, "No handle should be returned.", handle == NULL);

		if (onHold) {
			if (slept >= KSITEST_ASYNC_NO_RESP_TIMEOUT_MS) {
				KSI_LOG_debug(ctx, "%s: TIMEOUT.", __FUNCTION__);
				CuFail(tc, "No response within timeout.");
			}
			/* There is nothing has been received. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(KSITEST_ASYNC_SLEEP_TIME_MS);
			slept += KSITEST_ASYNC_SLEEP_TIME_MS;
		}
	} while (onHold);
	CuAssert(tc, "Callback must have been invoked.", callbackCount > 0);
	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_HaExtend_requestConfigOnlyUseCallback_tcp(CuTest* tc) {
	int res;
	KSI_AsyncService *has = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, TEST_SCHEME_TCP, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(has, KSI_ASYNC_OPT_PUSH_CONF_CALLBACK, (void *)dummyCallback);
	CuAssert(tc, "Unable to set async service option.", res == KSI_OK);

	asyncExtending_requestConfigOnlyUseCallback(tc, has);

	KSI_AsyncService_free(has);
}

void Test_HaExtend_requestConfigOnlyUseCallback_http(CuTest* tc) {
	int res;
	KSI_AsyncService *has = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, TEST_SCHEME_HTTP, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(has, KSI_ASYNC_OPT_PUSH_CONF_CALLBACK, (void *)dummyCallback);
	CuAssert(tc, "Unable to set async service option.", res == KSI_OK);

	asyncExtending_requestConfigOnlyUseCallback(tc, has);

	KSI_AsyncService_free(has);
}

static void asyncExtending_verifySubserviceCallbacksDisabled(CuTest* tc, const char *scheme) {
	int res;
	KSI_AsyncService *has = NULL;
	size_t i;
	KSI_AsyncServiceList *list = NULL;

	KSI_LOG_debug(ctx, "%s: %s", __FUNCTION__, scheme);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, scheme, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(has, KSI_ASYNC_OPT_PUSH_CONF_CALLBACK, (void *)dummyCallback);
	CuAssert(tc, "Unable to set async service option.", res == KSI_OK);

	callbackCount = 0;
	asyncExtending_requestConfigOnlyUseCallback(tc, has);
	CuAssert(tc, "Callback must have been invoked.", callbackCount > 0);

	res = KSI_AsyncService_getOption(has, KSI_ASYNC_OPT_HA_SUBSERVICE_LIST, (void *)&list);
	CuAssert(tc, "Unable to get list of subservices.", res == KSI_OK && list != NULL);
	CuAssert(tc, "Async service option value mismatch.", KSI_AsyncServiceList_length(list) > 0);

	/* Enable KSI_CTX conf callback. */
	res = KSI_CTX_setOption(ctx, KSI_OPT_EXT_CONF_RECEIVED_CALLBACK, (void *)dummyCallback);
	CuAssert(tc, "Unable to set KSI_CTX conf callback.", res == KSI_OK);

	/* Use individual subservices for communication. The callbacks should have been disabled during HA endpoint setup. */
	callbackCount = 0;
	for (i = 0; i < KSI_AsyncServiceList_length(list); i++) {
		KSI_AsyncService *sas = NULL;

		res = KSI_AsyncServiceList_elementAt(list, i, &sas);
		CuAssert(tc, "Unable to sub async service object.", res == KSI_OK && sas != NULL);

		KSI_LOG_debug(ctx, "%s: subservice %d", __FUNCTION__, (int)i);
		asyncExtending_requestConfigOnly(tc, sas);
	}
	CuAssert(tc, "Callbacks in subservices should be disabled.", callbackCount == 0);

	KSI_AsyncService_free(has);
}

static void Test_HaExtend_verifySubserviceCallbacksDisabled_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_verifySubserviceCallbacksDisabled(tc, TEST_SCHEME_TCP);
}

static void Test_HaExtend_verifySubserviceCallbacksDisabled_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_verifySubserviceCallbacksDisabled(tc, TEST_SCHEME_HTTP);
}

static void asyncExtending_requestConfigWithExtReq(CuTest* tc, const char *scheme) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;
	time_t startTime;
	size_t onHold = 0;
	KSI_ExtendReq *req = NULL;
	KSI_Config *cfg = NULL;
	const size_t reqTime = 1435740789;
	size_t pendingCount = 0;
	KSI_Integer *aggrTime = NULL;
	char confReceived = 0;
	char respReceived = 0;
	size_t slept = 0;

	KSI_LOG_debug(ctx, "%s: START", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(as, scheme, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s: REQUEST", __FUNCTION__);

	res = KSI_ExtendReq_new(ctx, &req);
	CuAssert(tc, "Unable to create extension request.", res == KSI_OK && req != NULL);

	res = KSI_Config_new(ctx, &cfg);
	CuAssert(tc, "Unable to create config object.", res == KSI_OK && cfg != NULL);

	res = KSI_ExtendReq_setConfig(req, cfg);
	CuAssert(tc, "Unable to set config request.", res == KSI_OK);

	res = KSI_Integer_new(ctx, reqTime, &aggrTime);
	CuAssert(tc, "Unable to aggr time.", res == KSI_OK && aggrTime != NULL);

	res = KSI_ExtendReq_setAggregationTime(req, aggrTime);
	CuAssert(tc, "Unable set aggre time.", res == KSI_OK);

	res = KSI_AsyncExtendHandle_new(ctx, req, &handle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

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
			if (slept >= KSITEST_ASYNC_NO_RESP_TIMEOUT_MS) {
				KSI_LOG_debug(ctx, "%s: TIMEOUT (%dms).", __FUNCTION__, KSITEST_ASYNC_NO_RESP_TIMEOUT_MS);
				CuFail(tc, "No response within timeout.");
			}
			/* There is nothing has been received. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(KSITEST_ASYNC_SLEEP_TIME_MS);
			slept += KSITEST_ASYNC_SLEEP_TIME_MS;
			continue;
		}
		slept = 0;

		res = KSI_AsyncHandle_getState(respHandle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);

		switch (state) {
			case KSI_ASYNC_STATE_RESPONSE_RECEIVED: {
					KSI_ExtendResp *resp = NULL;

					KSI_LOG_debug(ctx, "%s: RESPONSE.", __FUNCTION__);

					res = KSI_AsyncHandle_getExtendResp(respHandle, &resp);
					CuAssert(tc, "Failed to get extension response.", res == KSI_OK && resp != NULL);

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
	CuAssert(tc, "Extension response should have been received.", respReceived);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_HaExtend_requestConfigWithExtReq_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_requestConfigWithExtReq(tc, TEST_SCHEME_TCP);
}

void Test_HaExtend_requestConfigWithExtReq_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_requestConfigWithExtReq(tc, TEST_SCHEME_HTTP);
}

static void asyncExtending_requestConfigAndExtRequest_loop(CuTest* tc, const char *scheme) {
	int res;
	KSI_AsyncService *has = NULL;
	time_t startTime;
	size_t nofRequests = 0;
	size_t onHold = 0;
	size_t nofExtResponses = 0;
	size_t nofConfResponses = 0;
	KSI_Config *cfg = NULL;
	KSI_AsyncHandle *cfgHandle = NULL;
	KSI_ExtendReq *cfgReq = NULL;
	size_t slept = 0;

	KSI_LOG_debug(ctx, "%s: START", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_ExtendingHighAvailabilityService_new(ctx, &has);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && has != NULL);

	res = KSITest_HighAvailabilityService_setEndpoint(has, scheme, &conf.extender, conf.ha.extender);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(has, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, (void *)(1 << 3));
	CuAssert(tc, "Unable to set maximum request count.", res == KSI_OK);

	res = KSI_AsyncService_setOption(has, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void*)(NOF_TEST_REQUESTS + 1));
	CuAssert(tc, "Unable to set request cache size.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s: CONF REQUEST.", __FUNCTION__);

	res = KSI_ExtendReq_new(ctx, &cfgReq);
	CuAssert(tc, "Unable to create extension request.", res == KSI_OK && cfgReq != NULL);

	res = KSI_Config_new(ctx, &cfg);
	CuAssert(tc, "Unable to create config object.", res == KSI_OK && cfg != NULL);

	res = KSI_ExtendReq_setConfig(cfgReq, cfg);
	CuAssert(tc, "Unable to set request data hash.", res == KSI_OK);

	res = KSI_AsyncExtendHandle_new(ctx, cfgReq, &cfgHandle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && cfgHandle != NULL);

	res = KSI_AsyncService_addRequest(has, cfgHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	nofRequests = 0;
	do {
		KSI_AsyncHandle *respHandle = NULL;
		int state = KSI_ASYNC_STATE_UNDEFINED;

		if (nofRequests != NOF_TEST_REQUESTS) {
			size_t pendingCount = 0;
			KSI_AsyncHandle *reqHandle = NULL;
			KSI_ExtendReq *req = NULL;
			const size_t reqTime = 1435740789;
			KSI_Integer *aggrTime = NULL;

			KSI_LOG_debug(ctx, "%s: REQUEST (\"%llu\").", __FUNCTION__, (unsigned long long)nofRequests);

			res = KSI_ExtendReq_new(ctx, &req);
			CuAssert(tc, "Unable to create extension request.", res == KSI_OK && req != NULL);

			res = KSI_Integer_new(ctx, reqTime, &aggrTime);
			CuAssert(tc, "Unable to aggr time.", res == KSI_OK && aggrTime != NULL);

			res = KSI_ExtendReq_setAggregationTime(req, aggrTime);
			CuAssert(tc, "Unable set aggre time.", res == KSI_OK);

			res = KSI_AsyncExtendHandle_new(ctx, req, &reqHandle);
			CuAssert(tc, "Unable to create async request.", res == KSI_OK && reqHandle != NULL);

			res = KSI_AsyncService_addRequest(has, reqHandle);
			CuAssert(tc, "Unable to add request.", res == KSI_OK);

			nofRequests++;

			res = KSI_AsyncService_getPendingCount(has, &pendingCount);
			CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
			CuAssert(tc, "Pending count must be >0.", pendingCount > 0);

		}

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		res = KSI_AsyncService_run(has, &respHandle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);


		if (respHandle == NULL) {
			CuAssert(tc, "No response within timeout.", slept < KSITEST_ASYNC_NO_RESP_TIMEOUT_MS);
			/* There is nothing to be sent. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(KSITEST_ASYNC_SLEEP_TIME_MS);
			slept += KSITEST_ASYNC_SLEEP_TIME_MS;

			continue;
		}
		slept = 0;

		res = KSI_AsyncHandle_getState(respHandle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);

		switch (state) {
			case KSI_ASYNC_STATE_RESPONSE_RECEIVED: {
					KSI_ExtendResp *resp = NULL;

					KSI_LOG_debug(ctx, "%s: RESPONSE.", __FUNCTION__);

					res = KSI_AsyncHandle_getExtendResp(respHandle, &resp);
					CuAssert(tc, "Failed to get extension response.", res == KSI_OK && resp != NULL);

					nofExtResponses++;
				}
				break;

			case KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED: {
					KSI_Config *respCfg = NULL;

					KSI_LOG_debug(ctx, "%s: CONFIG RESPONSE.", __FUNCTION__);

					res = KSI_AsyncHandle_getConfig(respHandle, &respCfg);
					CuAssert(tc, "Unable to get server config.", res == KSI_OK && respCfg != NULL);

					nofConfResponses++;
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
	CuAssert(tc, "Extension response count mismatch.", NOF_TEST_REQUESTS == nofExtResponses);
	CuAssert(tc, "Configuration response count mismatch.", nofConfResponses > 0);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncService_free(has);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_HaExtend_requestConfigAndExtRequest_loop_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_requestConfigAndExtRequest_loop(tc, TEST_SCHEME_TCP);
}

void Test_HaExtend_requestConfigAndExtRequest_loop_http(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncExtending_requestConfigAndExtRequest_loop(tc, TEST_SCHEME_HTTP);
}

static void preTest(void) {
	KSI_CTX_setOption(ctx, KSI_OPT_AGGR_CONF_RECEIVED_CALLBACK, NULL);
	KSI_CTX_setOption(ctx, KSI_OPT_EXT_CONF_RECEIVED_CALLBACK, NULL);
	KSI_CTX_setOption(ctx, KSI_OPT_HA_SAFEGUARD, (void *)KSI_CTX_HA_MAX_SUBSERVICES);
}

CuSuite* HaExtIntegrationTests_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->preTest = preTest;

	/* Common test cases. */
	SUITE_ADD_TEST(suite, Test_HaExtend_verifySubserviceListOption);
	SUITE_ADD_TEST(suite, Test_HaExtend_noEndpoint_addRequest);
	SUITE_ADD_TEST(suite, Test_HaExtend_exceedMaxNofSubservices);

	SUITE_ADD_TEST(suite, Test_HaExtend_verifySubserviceCallbacksDisabled_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_verifySubserviceCallbacksDisabled_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_verifyOptions_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_verifyOptions_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_verifyCacheSizeOption_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_verifyCacheSizeOption_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_loop_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_loop_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_loopResetEndpointLoop_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_loopResetEndpointLoop_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_loop_http_tcp_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_loop_tcp_http_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_collect_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_collect_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_useAggregator_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_useAggregator_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_fillupCache_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_fillupCache_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_runEmpty_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_runEmpty_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_addEmptyRequest_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_addEmptyRequest_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_requestConfigOnly_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_requestConfigOnly_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_requestConfigOnlyUseCallback_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_requestConfigOnlyUseCallback_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_requestConfigWithExtReq_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_requestConfigWithExtReq_http);
	SUITE_ADD_TEST(suite, Test_HaExtend_requestConfigAndExtRequest_loop_tcp);
	SUITE_ADD_TEST(suite, Test_HaExtend_requestConfigAndExtRequest_loop_http);

	return suite;
}
