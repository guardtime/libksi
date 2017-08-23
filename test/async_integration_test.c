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

static const char *TEST_REQUESTS[] = {
	"Guardtime", "Keyless", "Signature", "Infrastructure", "(KSI)",
	"is an", "industrial", "scale", "blockchain", "platform",
	"that", "cryptographically", "ensures", "data", "integrity",
	"and", "proves", "time", "of", "existence",
	NULL
};

static void asyncSigning_loop_getResponse(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	time_t startTime;
	const char **p_req = NULL;
	size_t onHold = 0;

	KSI_LOG_debug(ctx, "%s: START (%s)", __FUNCTION__, url);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	p_req = TEST_REQUESTS;
	do {
		KSI_AsyncHandle handle = KSI_ASYNC_HANDLE_NULL;
		int state = KSI_ASYNC_REQ_UNDEFINED;

		if (*p_req != NULL) {
			size_t pendingCount = 0;
			KSI_AsyncRequest *asReq = NULL;
			KSI_DataHash *hsh = NULL;
			KSI_AggregationReq *req = NULL;

			KSI_LOG_debug(ctx, "%s: REQUEST (\"%s\").", __FUNCTION__, *p_req);

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

			res = KSI_AsyncService_addRequest(as, asReq, &handle);
			CuAssert(tc, "Unable to add request", res == KSI_OK);
			CuAssert(tc, "Invalid handle returned.", handle != KSI_ASYNC_HANDLE_NULL);
			p_req++;

			res = KSI_AsyncService_getPendingCount(as, &pendingCount);
			CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
			CuAssert(tc, "Pending count must be >0.", pendingCount > 0);
		}

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		handle = KSI_ASYNC_HANDLE_NULL;
		res = KSI_AsyncService_run(as, &handle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (handle == KSI_ASYNC_HANDLE_NULL) {
			if (*p_req == NULL) {
				/* There is nothong to be sent. */
				/* Wait for a while to avoid busy loop. */
				KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
				sleep_ms(50);
			}
			continue;
		}

		res = KSI_AsyncService_getRequestState(as, handle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_REQ_UNDEFINED);
		CuAssert(tc, "Requests must succeed.", state != KSI_ASYNC_REQ_ERROR);

		switch (state) {
			case KSI_ASYNC_REQ_RESPONSE_RECEIVED: {
					KSI_DataHash *reqCtx = NULL;
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

					res = KSI_AsyncResponse_getRequestContext(asResp, (void**)&reqCtx);
					CuAssert(tc, "Unable to get request context.", res == KSI_OK);

					res = KSI_AggregationResp_getAggregationChainList(resp, &aggrChainList);
					CuAssert(tc, "Unable to get aggregation chain list.", res == KSI_OK && aggrChainList != NULL);
					CuAssert(tc, "Unable to get aggregation chain list is emty.", KSI_AggregationHashChainList_length(aggrChainList) > 0);

					res = KSI_AggregationHashChainList_elementAt(aggrChainList, 0, &chain);
					CuAssert(tc, "Unable to get aggregation chain.", res == KSI_OK && chain != NULL);

					res = KSI_AggregationHashChain_getInputHash(chain, &inpHsh);
					CuAssert(tc, "Unable to chain input hash.", res == KSI_OK && inpHsh != NULL);

					CuAssert(tc, "Request context data mismatch.", KSI_DataHash_equals(reqCtx, inpHsh));

					KSI_AsyncResponse_free(asResp);
				}
				break;

			default:
				/* Do nothing! */
				break;
		}
	} while (onHold);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_AsyncSign_loop_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncSigning_loop_getResponse(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
}

static void asyncSigning_collect_getResponse(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	time_t startTime;
	const char **p_req = NULL;
	size_t added = 0;
	size_t receivedCount = 0;
	size_t i;
	KSI_AsyncHandle *hndls = NULL;

	KSI_LOG_debug(ctx, "%s: START (%s)", __FUNCTION__, url);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	hndls = KSI_calloc(sizeof(TEST_REQUESTS)/sizeof(TEST_REQUESTS[0]), sizeof(KSI_AsyncHandle));
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	p_req = TEST_REQUESTS;
	while (*p_req != NULL) {
		KSI_AsyncHandle handle = KSI_ASYNC_HANDLE_NULL;
		size_t pendingCount = 0;
		KSI_AsyncRequest *asReq = NULL;
		KSI_DataHash *hsh = NULL;
		KSI_AggregationReq *req = NULL;

		KSI_LOG_debug(ctx, "%s: REQUEST (\"%s\").", __FUNCTION__, *p_req);

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

		res = KSI_AsyncService_addRequest(as, asReq, &handle);
		CuAssert(tc, "Unable to add request", res == KSI_OK);
		CuAssert(tc, "Invalid handle returned.", handle != KSI_ASYNC_HANDLE_NULL);

		res = KSI_AsyncService_setRequestContext(as, handle, (void *)*p_req, NULL);
		CuAssert(tc, "Unable to set request context.", res == KSI_OK);

		hndls[added] = handle;
		p_req++;

		res = KSI_AsyncService_getPendingCount(as, &pendingCount);
		CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
		CuAssert(tc, "Pending count mitmatch.", pendingCount == ++added);
	}

	do {
		size_t prevCount = receivedCount;

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		res = KSI_AsyncService_run(as, NULL, NULL);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		res = KSI_AsyncService_getReceivedCount(as, &receivedCount);
		CuAssert(tc, "Unable to get received count.", res == KSI_OK);

		if (receivedCount == prevCount) {
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(50);
		}
	} while (receivedCount != added);

	for (i = 0; i < receivedCount; i++) {
		int state = KSI_ASYNC_REQ_UNDEFINED;

		res = KSI_AsyncService_getRequestState(as, hndls[i], &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_REQ_UNDEFINED);
		CuAssert(tc, "Requests must succeed.", state == KSI_ASYNC_REQ_RESPONSE_RECEIVED);

		switch (state) {
			case KSI_ASYNC_REQ_RESPONSE_RECEIVED: {
					KSI_AsyncResponse *asResp = NULL;
					KSI_AggregationResp *resp = NULL;
					char *reqCtx = NULL;

					KSI_LOG_debug(ctx, "%s: RESPONSE.", __FUNCTION__);

					res = KSI_AsyncService_getRequestContext(as, hndls[i], (void**)&reqCtx);
					CuAssert(tc, "Unable to get service request context.", res == KSI_OK && reqCtx != NULL);
					CuAssert(tc, "Service request context data mismatch.", strcmp(reqCtx, TEST_REQUESTS[i]) == 0);
					reqCtx = NULL;

					res = KSI_AsyncService_getResponse(as, hndls[i], &asResp);
					CuAssert(tc, "Failed to get async response.", res == KSI_OK && asResp != NULL);

					res = KSI_AsyncService_getRequestContext(as, hndls[i], (void**)&reqCtx);
					CuAssert(tc, "Service request context should be empty.", res == KSI_INVALID_STATE && reqCtx == NULL);

					res = KSI_AsyncResponse_getRequestContext(asResp, (void**)&reqCtx);
					CuAssert(tc, "Unable to get response request context.", res == KSI_OK && reqCtx != NULL);
					CuAssert(tc, "Reaponse request context data mismatch.", strcmp(reqCtx, TEST_REQUESTS[i]) == 0);

					res = KSI_AsyncResponse_getAggregationResp(asResp, &resp);
					CuAssert(tc, "Failed to get aggregation response.", res == KSI_OK && resp != NULL);

					KSI_AsyncResponse_free(asResp);
				}
				break;
		}
	}

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_free(hndls);
	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}

void Test_AsyncSign_collect_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncSigning_collect_getResponse(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
}

static void asyncSigning_getError(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	time_t startTime;
	size_t onHold = 0;
	KSI_AsyncHandle handle = KSI_ASYNC_HANDLE_NULL;
	KSI_AsyncRequest *asReq = NULL;
	KSI_AggregationReq *req = NULL;
	KSI_DataHash *hsh = NULL;

	KSI_LOG_debug(ctx, "%s: START (%s)", __FUNCTION__, url);
	KSI_ERR_clearErrors(ctx);
	startTime = time(NULL);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	KSI_LOG_debug(ctx, "%s: REQUEST", __FUNCTION__);

	res = KSI_DataHash_create(ctx, TEST_REQUESTS[0], strlen(TEST_REQUESTS[0]), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Unable to create data hash from string.", res == KSI_OK && hsh != NULL);

	res = KSI_AggregationReq_new(ctx, &req);
	CuAssert(tc, "Unable to create aggregation request.", res == KSI_OK && req != NULL);

	res = KSI_AggregationReq_setRequestHash(req, hsh);
	CuAssert(tc, "Unable to set request data hash.", res == KSI_OK);

	res = KSI_AsyncRequest_new(ctx, &asReq);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && asReq != NULL);

	res = KSI_AsyncRequest_setAggregationReq(asReq, req);
	CuAssert(tc, "Unable to set aggregation request.", res == KSI_OK);

	res = KSI_AsyncService_addRequest(as, asReq, &handle);
	CuAssert(tc, "Unable to add request", res == KSI_OK);
	CuAssert(tc, "Invalid handle returned.", handle != KSI_ASYNC_HANDLE_NULL);

	do {
		int state = KSI_ASYNC_REQ_UNDEFINED;
		int err = KSI_UNKNOWN_ERROR;

		KSI_LOG_debug(ctx, "%s: RUN.", __FUNCTION__);

		handle = KSI_ASYNC_HANDLE_NULL;
		res = KSI_AsyncService_run(as, &handle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (handle == KSI_ASYNC_HANDLE_NULL) {
			/* There is nothong to be sent. */
			/* Wait for a while to avoid busy loop. */
			KSI_LOG_debug(ctx, "%s: SLEEP.", __FUNCTION__);
			sleep_ms(50);
			continue;
		}

		res = KSI_AsyncService_getRequestState(as, handle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_REQ_UNDEFINED);
		CuAssert(tc, "Requests must fail.", state == KSI_ASYNC_REQ_ERROR);

		KSI_LOG_debug(ctx, "%s: ERROR.", __FUNCTION__);

		res = KSI_AsyncService_getRequestError(as, handle, &err);
		CuAssert(tc, "Unable to get request error.", res == KSI_OK);
		CuAssert(tc, "Wrong error.", err == KSI_NETWORK_RECIEVE_TIMEOUT);

		res = KSI_AsyncService_recover(as, handle, KSI_ASYNC_REC_DROP);
		CuAssert(tc, "Unable to drop request.", res == KSI_OK);

	} while (onHold);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncService_free(as);

	KSI_LOG_debug(ctx, "%s: FINISH in %fs.", __FUNCTION__, difftime(time(NULL), startTime));
}


void Test_AsyncSign_useExtender_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncSigning_getError(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.extender), conf.extender.user, conf.extender.pass);
}

static int createDummyAggrAsyncRequest(KSI_AsyncRequest **ar) {
	int res;
	KSI_AsyncRequest *tmp = NULL;
	KSI_AggregationReq *req = NULL;
	KSI_DataHash *hsh = NULL;

	res = KSI_AggregationReq_new(ctx, &req);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHash_createZero(ctx, KSI_HASHALG_SHA2_256, &hsh);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AggregationReq_setRequestHash(req, hsh);
	if (res != KSI_OK) goto cleanup;
	hsh = NULL;

	res = KSI_AsyncRequest_new(ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AsyncRequest_setAggregationReq(tmp, req);
	if (res != KSI_OK) goto cleanup;
	req = NULL;

	*ar = tmp;
	tmp = NULL;
cleanup:
	KSI_DataHash_free(hsh);
	KSI_AggregationReq_free(req);
	KSI_AsyncRequest_free(tmp);
	return res;
}

static void asyncSigning_fillupCache(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncRequest *ar = NULL;
	KSI_AsyncHandle hndl = KSI_ASYNC_HANDLE_NULL;
	size_t i;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	/* Fill up internal cache. */
	for (i = 1; i < KSI_ASYNC_DEFAULT_PARALLEL_REQUESTS; i++) {
		ar = NULL;
		hndl = KSI_ASYNC_HANDLE_NULL;

		res = createDummyAggrAsyncRequest(&ar);
		CuAssert(tc, "Unable to create dummy request", res == KSI_OK && ar != NULL);

		res = KSI_AsyncService_addRequest(as, ar, &hndl);
		CuAssert(tc, "Unable to add request", res == KSI_OK);
		CuAssert(tc, "Invalid handle returned.", hndl != KSI_ASYNC_HANDLE_NULL);
	}
	ar = NULL;
	hndl = KSI_ASYNC_HANDLE_NULL;

	/* Try to add one more request. */
	res = createDummyAggrAsyncRequest(&ar);
	CuAssert(tc, "Unable to create dummy request", res == KSI_OK && ar != NULL);

	res = KSI_AsyncService_addRequest(as, ar, &hndl);
	CuAssert(tc, "Unable to add request", res == KSI_ASYNC_MAX_PARALLEL_COUNT_REACHED);
	CuAssert(tc, "Invalid handle returned.", hndl == KSI_ASYNC_HANDLE_NULL);

	KSI_AsyncRequest_free(ar);
	KSI_AsyncService_free(as);
}

void Test_AsyncSign_fillupCache_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncSigning_fillupCache(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
}

static void asyncSigning_addEmptyReq(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncRequest *ar = NULL;
	KSI_AsyncHandle hndl = KSI_ASYNC_HANDLE_NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncRequest_new(ctx, &ar);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && ar != NULL);

	res = KSI_AsyncService_addRequest(as, ar, &hndl);
	CuAssert(tc, "Unable to add request", res == KSI_INVALID_STATE);
	CuAssert(tc, "Invalid handle returned.", hndl == KSI_ASYNC_HANDLE_NULL);

	KSI_AsyncRequest_free(ar);
	KSI_AsyncService_free(as);
}

void Test_AsyncSign_addEmptyRequest_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncSigning_addEmptyReq(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
}

static void asyncSigning_addExtendRequest(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncRequest *ar = NULL;
	KSI_ExtendReq *req = NULL;
	KSI_AsyncHandle hndl = KSI_ASYNC_HANDLE_NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncRequest_new(ctx, &ar);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && ar != NULL);

	res = KSI_ExtendReq_new(ctx, &req);
	CuAssert(tc, "Unable to create extend request.", res == KSI_OK && req != NULL);

	res = KSI_AsyncRequest_setExtendReq(ar, req);
	CuAssert(tc, "Unable to set aggregation request.", res == KSI_OK);

	res = KSI_AsyncService_addRequest(as, ar, &hndl);
	CuAssert(tc, "Unable to add request", res == KSI_INVALID_STATE);
	CuAssert(tc, "Invalid handle returned.", hndl == KSI_ASYNC_HANDLE_NULL);

	KSI_AsyncRequest_free(ar);
	KSI_AsyncService_free(as);
}

void Test_AsyncSign_addExtendRequest_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncSigning_addExtendRequest(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
}

static void asyncSigning_addAggrExtReqs(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncRequest *ar = NULL;
	KSI_ExtendReq *req = NULL;
	KSI_AsyncHandle hndl = KSI_ASYNC_HANDLE_NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = createDummyAggrAsyncRequest(&ar);
	CuAssert(tc, "Unable to create dummy request", res == KSI_OK && ar != NULL);

	res = KSI_ExtendReq_new(ctx, &req);
	CuAssert(tc, "Unable to create extend request.", res == KSI_OK && req != NULL);

	res = KSI_AsyncRequest_setExtendReq(ar, req);
	CuAssert(tc, "Unable to set aggregation request.", res == KSI_OK);

	res = KSI_AsyncService_addRequest(as, ar, &hndl);
	CuAssert(tc, "Unable to add request", res == KSI_INVALID_STATE);
	CuAssert(tc, "Invalid handle returned.", hndl == KSI_ASYNC_HANDLE_NULL);

	KSI_AsyncRequest_free(ar);
	KSI_AsyncService_free(as);
}

void Test_AsyncSign_addAggrExtReqs_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncSigning_addAggrExtReqs(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
}

static void Test_AsyncSign_noEndpoint_addRequest(CuTest* tc) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncRequest *ar = NULL;
	KSI_AsyncHandle hndl = KSI_ASYNC_HANDLE_NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = createDummyAggrAsyncRequest(&ar);
	CuAssert(tc, "Unable to create dummy request", res == KSI_OK && ar != NULL);

	res = KSI_AsyncService_addRequest(as, ar, &hndl);
	CuAssert(tc, "Unable to add request", res == KSI_INVALID_STATE);
	CuAssert(tc, "Invalid handle returned.", hndl == KSI_ASYNC_HANDLE_NULL);

	KSI_AsyncRequest_free(ar);
	KSI_AsyncService_free(as);
}

static void asyncSigning_timeout(CuTest* tc, const char *url, const char *user, const char *pass,
			int (*setTimeout)(KSI_AsyncService *, const size_t), const size_t timeout,
			const int resultErr) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncRequest *ar = NULL;
	KSI_AsyncHandle hndl = KSI_ASYNC_HANDLE_NULL;
	KSI_AsyncHandle reqHandle = KSI_ASYNC_HANDLE_NULL;
	int state = KSI_ASYNC_REQ_UNDEFINED;
	int err = KSI_UNKNOWN_ERROR;
	size_t onHold = 0;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, url, user, pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = setTimeout(as, timeout);
	CuAssert(tc, "Unable to set timeout", res == KSI_OK);

	res = createDummyAggrAsyncRequest(&ar);
	CuAssert(tc, "Unable to create dummy request", res == KSI_OK && ar != NULL);

	res = KSI_AsyncService_addRequest(as, ar, &reqHandle);
	CuAssert(tc, "Unable to add request", res == KSI_OK);
	CuAssert(tc, "Invalid handle returned.", reqHandle != KSI_ASYNC_HANDLE_NULL);

	hndl = KSI_ASYNC_HANDLE_NULL;
	do {
		res = KSI_AsyncService_run(as, &hndl, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);
		CuAssert(tc, "Waiting count mismatch.", onHold == 1);
	} while (hndl == KSI_ASYNC_HANDLE_NULL);

	res = KSI_AsyncService_getRequestState(as, hndl, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_REQ_UNDEFINED);
	CuAssert(tc, "Requests must fail.", state == KSI_ASYNC_REQ_ERROR);

	res = KSI_AsyncService_getRequestError(as, hndl, &err);
	CuAssert(tc, "Unable to get request error.", res == KSI_OK);
	CuAssert(tc, "Wrong error.", err == resultErr);

	KSI_AsyncService_free(as);
}

void Test_AsyncSign_sendTimeout_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncSigning_timeout(tc,
			KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass,
			KSI_AsyncService_setSendTimeout, 0,
			KSI_NETWORK_SEND_TIMEOUT);
}

void Test_AsyncSign_receiveTimeout_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncSigning_timeout(tc,
			KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass,
			KSI_AsyncService_setReceiveTimeout, 0,
			KSI_NETWORK_RECIEVE_TIMEOUT);
}

void Test_AsyncSign_connectTimeout_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncSigning_timeout(tc,
			KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass,
			KSI_AsyncService_setConnectTimeout, 0,
			KSI_NETWORK_CONNECTION_TIMEOUT);
}

static void asyncSigning_runEmpty(CuTest* tc, const char *url, const char *user, const char *pass) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle hndl = KSI_ASYNC_HANDLE_NULL;
	size_t onHold = 0;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSI_AsyncService_setEndpoint(as, KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &hndl, &onHold);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Waiting count mismatch.", onHold == 0);
	CuAssert(tc, "Invalid handle returned.", hndl == KSI_ASYNC_HANDLE_NULL);

	KSI_AsyncService_free(as);
}

void Test_AsyncSign_runEmpty_tcp(CuTest* tc) {
	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	asyncSigning_runEmpty(tc, KSITest_composeUri(TEST_SCHEME_TCP, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
}


CuSuite* AsyncIntegrationTests_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, Test_AsyncSign_loop_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncSign_collect_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncSign_useExtender_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncSign_fillupCache_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncSign_addEmptyRequest_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncSign_addExtendRequest_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncSign_addAggrExtReqs_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncSign_noEndpoint_addRequest);
	SUITE_ADD_TEST(suite, Test_AsyncSign_sendTimeout_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncSign_receiveTimeout_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncSign_connectTimeout_tcp);
	SUITE_ADD_TEST(suite, Test_AsyncSign_runEmpty_tcp);

	return suite;
}
