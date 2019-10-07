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

#include <ksi/hash.h>
#include <ksi/net.h>
#include <ksi/net_async.h>
#include <ksi/net_ha.h>

#include "cutest/CuTest.h"

#include "all_tests.h"
#include "test_mock_async.h"


extern KSI_CTX *ctx;

#define TEST_RESP_COUNT(arr) (sizeof(arr) / sizeof(arr[0]))

static const char *TEST_REQ_DATA[] = {
	"Guardtime", "KSI", "Blockchain",
	"is an", "industrial", "scale", "blockchain", "platform",
	"that", "cryptographically", "ensures", "data", "integrity",
	"and", "proves", "time", "of", "existence",
	NULL
};
static const size_t TEST_REQ_DATA_COUNT = (TEST_RESP_COUNT(TEST_REQ_DATA) - 1);

static KSI_Config *callbackConf = NULL;
static size_t callbackCalls = 0;

static int KSITest_ConfigCallback(KSI_CTX *ctx, KSI_Config *conf) {
	callbackCalls++;
	if (ctx == NULL || conf == NULL) return KSI_INVALID_ARGUMENT;
	callbackConf = KSI_Config_ref(conf);
	return KSI_OK;
}

static int KSITest_createAggrAsyncHandle(KSI_CTX *ctx,
		int isHshStr, const unsigned char *data, size_t len, int alg,
		KSI_DataHash *requestHsh, size_t requestLvl, KSI_uint64_t requestId,
		KSI_AsyncHandle **handle) {
	int res;
	KSI_AsyncHandle *tmp = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_AggregationReq *req = NULL;
	KSI_Integer *lvl = NULL;
	KSI_Integer *rId = NULL;

	if (ctx == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_AggregationReq_new(ctx, &req);
	if (res != KSI_OK) goto cleanup;

	if (requestHsh == NULL) {
		res = (isHshStr ? KSITest_DataHash_fromStr(ctx, (char *)data, &hsh) :
						  (data ? KSI_DataHash_create(ctx, data, len, alg, &hsh) :
								  KSI_DataHash_createZero(ctx, alg, &hsh)));
		if (res != KSI_OK) goto cleanup;
	} else {
		hsh = requestHsh;
	}

	res = KSI_AggregationReq_setRequestHash(req, hsh);
	if (res != KSI_OK) goto cleanup;
	hsh = NULL;

	if (requestLvl) {
		res = KSI_Integer_new(ctx, requestLvl, &lvl);
		if (res != KSI_OK) {
			goto cleanup;
		}

		res = KSI_AggregationReq_setRequestLevel(req, lvl);
		if (res != KSI_OK) goto cleanup;
		lvl = NULL;
	}

	if (requestId) {
		res = KSI_Integer_new(ctx, requestId, &rId);
		if (res != KSI_OK) {
			goto cleanup;
		}

		res = KSI_AggregationReq_setRequestId(req, rId);
		if (res != KSI_OK) goto cleanup;
		rId = NULL;
	}

	res = KSI_AsyncAggregationHandle_new(ctx, req, &tmp);
	if (res != KSI_OK) goto cleanup;
	req = NULL;

	*handle = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_Integer_free(lvl);
	KSI_Integer_free(rId);
	KSI_DataHash_free(hsh);
	KSI_AggregationReq_free(req);
	KSI_AsyncHandle_free(tmp);
	return res;
}

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

void Test_AsyncSingningService_verifyOptions(CuTest* tc) {
	int res;
	KSI_AsyncService *as = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, NULL, 0, NULL, NULL);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	verifyOption(tc, as, KSI_ASYNC_OPT_CON_TIMEOUT, 10, 15);
	verifyOption(tc, as, KSI_ASYNC_OPT_RCV_TIMEOUT, 10, 15);
	verifyOption(tc, as, KSI_ASYNC_OPT_SND_TIMEOUT, 10, 15);
	verifyOption(tc, as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, 1, 15);
	verifyOption(tc, as, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, 1, 15);

	KSI_AsyncService_free(as);
}

static int dummyCallback(KSI_CTX KSI_UNUSED(*ctx), KSI_Config KSI_UNUSED(*cnf)) {
	return KSI_OK;
}

void Test_AsyncSingningService_verifyPushConfCallbackOptions(CuTest* tc) {
	int res;
	KSI_AsyncService *as = NULL;
	size_t optVal = 0;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, NULL, 0, NULL, NULL);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_getOption(as, KSI_ASYNC_OPT_PUSH_CONF_CALLBACK, (void *)&optVal);
	CuAssert(tc, "Async service default option value mismatch.", res == KSI_OK && (KSI_Config_Callback)optVal == NULL);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_PUSH_CONF_CALLBACK, (void *)dummyCallback);
	CuAssert(tc, "Unable to set async service option.", res == KSI_OK);
	res = KSI_AsyncService_getOption(as, KSI_ASYNC_OPT_PUSH_CONF_CALLBACK, (void *)&optVal);
	CuAssert(tc, "Async service option value mismatch.", res == KSI_OK && (KSI_Config_Callback)optVal == dummyCallback);

	res = ((KSI_Config_Callback)optVal)(ctx, NULL);
	CuAssert(tc, "Async service option callcack result mismatch.", res == KSI_OK);

	KSI_AsyncService_free(as);
}

static void Test_AsyncSingningService_verifyCacheSizeOption(CuTest* tc) {
	int res;
	KSI_AsyncService *as = NULL;
	size_t optVal = 0;

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, NULL, 0, NULL, NULL);
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

static void Test_AsyncSingningService_addEmptyReq(CuTest* tc) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;
	KSI_AggregationReq *req = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, NULL, 0, "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AggregationReq_new(ctx, &req);
	CuAssert(tc, "Unable to create aggregation request.", res == KSI_OK && req != NULL);

	res = KSI_AsyncAggregationHandle_new(ctx, req, &handle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Request should not be added.", res != KSI_OK && res != KSI_ASYNC_REQUEST_CACHE_FULL);

	KSI_AsyncHandle_free(handle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSingningService_addRequest_noEndpoint(CuTest* tc) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_createAggrAsyncHandle(ctx, 0, NULL, 0, KSI_HASHALG_SHA2_256, NULL, 0, 0, &handle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request.", res == KSI_INVALID_STATE);

	KSI_AsyncHandle_free(handle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSingningService_runEmpty(CuTest* tc) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *hndl = NULL;
	size_t onHold = 0;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, NULL, 0, NULL, NULL);
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &hndl, &onHold);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Waiting count mismatch.", onHold == 0);
	CuAssert(tc, "Invalid handle returned.", hndl == NULL);

	KSI_AsyncService_free(as);
}

static void Test_AsyncSingningService_verifyReqId(CuTest* tc) {
	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *handle = NULL;
	KSI_AggregationReq *req = NULL;
	KSI_Integer *rReqId = NULL;
	KSI_uint64_t hReqId = 0;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, NULL, 0, "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0x1234, &handle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	req = NULL;
	res = KSI_AsyncHandle_getAggregationReq(handle, &req);
	CuAssert(tc, "Unable to get aggregation request.", res == KSI_OK && req != NULL);

	rReqId = NULL;
	res = KSI_AggregationReq_getRequestId(req, &rReqId);
	CuAssert(tc, "Unable to get request id.", res == KSI_OK && rReqId != NULL);
	CuAssert(tc, "Wrong request id.", KSI_Integer_getUInt64(rReqId) == 1);

	res = KSI_AsyncHandle_getRequestId(handle, &hReqId);
	CuAssert(tc, "Unable to get handle request id.", res == KSI_OK && hReqId != 0);
	CuAssert(tc, "Wrong handle request id.", KSI_Integer_getUInt64(rReqId) == hReqId);

	KSI_AsyncService_free(as);
}

static void Test_AsyncSingningService_verifyRequestCacheFull(CuTest* tc) {
	KSI_AsyncHandle *handle = NULL;
	int res;
	KSI_AsyncService *as = NULL;
	size_t cacheSize = 0;
	size_t i;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, NULL, 0, "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_getOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)&cacheSize);
	CuAssert(tc, "Unable to extract service option.", res == KSI_OK && cacheSize != 0);

	for (i = 0; i < cacheSize; i++) {
		handle = NULL;

		res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &handle);
		CuAssert(tc, "Unable to create async handle.", res == KSI_OK && handle != NULL);

		res = KSI_AsyncService_addRequest(as, handle);
		CuAssert(tc, "Unable to add request.", res == KSI_OK);
	}

	handle = NULL;
	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &handle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && handle != NULL);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request.", res == KSI_ASYNC_REQUEST_CACHE_FULL);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)++cacheSize);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_addRequest(as, handle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_verifyReqCtx(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_DataHash *reqCtx = NULL;
	KSI_DataHash *inpHsh = NULL;
	KSI_AggregationResp *resp = NULL;
	KSI_AggregationHashChainList *aggrChainList = NULL;
	KSI_AggregationHashChain *chain = NULL;
	size_t pendingCount = 0;
	size_t onHold = 0;
	int state = KSI_ASYNC_STATE_UNDEFINED;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

	res = KSITest_createAggrAsyncHandle(ctx, 0, NULL, 0, KSI_HASHALG_INVALID_VALUE, KSI_DataHash_ref(hsh), 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncHandle_setRequestCtx(reqHandle, (void*)hsh, (void (*)(void*))KSI_DataHash_free);
	CuAssert(tc, "Unable to set request context.", res == KSI_OK);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_getPendingCount(as, &pendingCount);
	CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
	CuAssert(tc, "Pending count must be 1.", pendingCount == 1);

	res = KSI_AsyncService_run(as, &respHandle, &onHold);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK && respHandle != NULL);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getAggregationResp(respHandle, &resp);
	CuAssert(tc, "Failed to get aggregation response.", res == KSI_OK && resp != NULL);

	res = KSI_AsyncHandle_getRequestCtx(respHandle, (const void**)&reqCtx);
	CuAssert(tc, "Unable to get request context.", res == KSI_OK && reqCtx != NULL);

	res = KSI_AggregationResp_getAggregationChainList(resp, &aggrChainList);
	CuAssert(tc, "Unable to get aggregation chain list.", res == KSI_OK && aggrChainList != NULL);
	CuAssert(tc, "Unable to get aggregation chain list is emty.", KSI_AggregationHashChainList_length(aggrChainList) > 0);

	res = KSI_AggregationHashChainList_elementAt(aggrChainList, 0, &chain);
	CuAssert(tc, "Unable to get aggregation chain.", res == KSI_OK && chain != NULL);

	res = KSI_AggregationHashChain_getInputHash(chain, &inpHsh);
	CuAssert(tc, "Unable to chain input hash.", res == KSI_OK && inpHsh != NULL);

	CuAssert(tc, "Request context data mismatch.", KSI_DataHash_equals(reqCtx, inpHsh));

	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_verifySignature(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-07-01.1.ksig"
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_Signature *signature = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;
	unsigned char *raw = NULL;
	size_t raw_len = 0;
	unsigned char expected[0x1ffff];
	size_t expected_len = 0;
	FILE *f = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK && respHandle != NULL);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getSignature(respHandle, &signature);
	CuAssert(tc, "Unable to extract signature.", res == KSI_OK && signature != NULL);

	res = KSI_Signature_serialize(signature, &raw, &raw_len);
	CuAssert(tc, "Unable to serialize signature.", res == KSI_OK && raw != NULL && raw_len > 0);

	f = fopen(getFullResourcePath(TEST_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to load sample signature.", f != NULL);

	expected_len = (unsigned)fread(expected, 1, sizeof(expected), f);
	CuAssert(tc, "Failed to read sample.", expected_len > 0);

	CuAssert(tc, "Serialized signature length mismatch.", expected_len == raw_len);
	CuAssert(tc, "Serialized signature content mismatch.", !memcmp(expected, raw, raw_len));

	if (f != NULL) fclose(f);
	KSI_free(raw);

	KSI_Signature_free(signature);
	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);

#undef TEST_SIGNATURE_FILE
}

static void Test_AsyncSign_oneRequest_multipleResponses_verifySignature(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-07-01.1.ksig"
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr-response-multiple-responses.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_Signature *signature = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;
	unsigned char *raw = NULL;
	size_t raw_len = 0;
	unsigned char expected[0x1ffff];
	size_t expected_len = 0;
	FILE *f = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK && respHandle != NULL);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getSignature(respHandle, &signature);
	CuAssert(tc, "Unable to extract signature.", res == KSI_OK && signature != NULL);

	res = KSI_Signature_serialize(signature, &raw, &raw_len);
	CuAssert(tc, "Unable to serialize signature.", res == KSI_OK && raw != NULL && raw_len > 0);

	f = fopen(getFullResourcePath(TEST_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to load sample signature.", f != NULL);

	expected_len = (unsigned)fread(expected, 1, sizeof(expected), f);
	CuAssert(tc, "Failed to read sample.", expected_len > 0);

	CuAssert(tc, "Serialized signature length mismatch.", expected_len == raw_len);
	CuAssert(tc, "Serialized signature content mismatch.", !memcmp(expected, raw, raw_len));

	if (f != NULL) fclose(f);
	KSI_free(raw);

	KSI_Signature_free(signature);
	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);

#undef TEST_SIGNATURE_FILE
}

static void Test_AsyncSign_oneRequest_verifyNoError(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	int error = 0;
	long errorExt = 0;
	KSI_Utf8String *msg = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK && respHandle != NULL);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getError(respHandle, &error);
	CuAssert(tc, "There should be no error.", res == KSI_OK && error == KSI_OK);

	res = KSI_AsyncHandle_getExtError(respHandle, &errorExt);
	CuAssert(tc, "There should be no external error.", res == KSI_OK && errorExt == 0);

	res = KSI_AsyncHandle_getErrorMessage(respHandle, &msg);
	CuAssert(tc, "There should be no error message.", res == KSI_OK && msg == NULL);

	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_responseWithPushConf_viaServiceCallback(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response-with-conf-and-ack.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_Integer *intVal = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_Signature *signature = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_PUSH_CONF_CALLBACK, (void *)KSITest_ConfigCallback);
	CuAssert(tc, "Unable to set conf callback.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	callbackCalls = 0;
	callbackConf = NULL;
	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	CuAssert(tc, "Conf callback has not been invoked.", callbackCalls > 0);
	CuAssert(tc, "Push conf is not set.", callbackConf != NULL);

	res = KSI_Config_getMaxRequests(callbackConf, &intVal);
	CuAssert(tc, "Conf max requests value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 4);
	intVal = NULL;

	res = KSI_Config_getAggrPeriod(callbackConf, &intVal);
	CuAssert(tc, "Conf aggregation period value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 3);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getSignature(respHandle, &signature);
	CuAssert(tc, "Signature should be returned.", res == KSI_OK && signature != NULL);

	KSI_Signature_free(signature);
	KSI_Config_free(callbackConf);
	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_responseWithPushConf_viaKsiCtxAggrCallback(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response-with-conf-and-ack.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_Integer *intVal = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_Signature *signature = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_CTX_setOption(ctx, KSI_OPT_AGGR_CONF_RECEIVED_CALLBACK, (void *)KSITest_ConfigCallback);
	CuAssert(tc, "Unable to set extender conf callback.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	callbackCalls = 0;
	callbackConf = NULL;
	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	CuAssert(tc, "Conf callback has not been invoked.", callbackCalls > 0);
	CuAssert(tc, "Push conf is not set.", callbackConf != NULL);

	res = KSI_Config_getMaxRequests(callbackConf, &intVal);
	CuAssert(tc, "Conf max requests value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 4);
	intVal = NULL;

	res = KSI_Config_getAggrPeriod(callbackConf, &intVal);
	CuAssert(tc, "Conf aggregation period value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 3);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getSignature(respHandle, &signature);
	CuAssert(tc, "Signature should be returned.", res == KSI_OK && signature != NULL);

	KSI_Signature_free(signature);
	KSI_Config_free(callbackConf);
	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_responseWithPushConf_viaHandle_setKsiCtxExtCallback(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response-with-conf-and-ack.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_Integer *intVal = NULL;
	KSI_AsyncHandle *confHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_Signature *signature = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;
	KSI_Config *pushConf = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_CTX_setOption(ctx, KSI_OPT_EXT_CONF_RECEIVED_CALLBACK, (void *)KSITest_ConfigCallback);
	CuAssert(tc, "Unable to set extender conf callback.", res == KSI_OK);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	/* Get push configuration. */
	callbackCalls = 0;
	callbackConf = NULL;
	res = KSI_AsyncService_run(as, &confHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Wrong handle.",  confHandle != reqHandle);

	CuAssert(tc, "Conf callback should have not been invoked.", callbackCalls == 0);
	CuAssert(tc, "Push conf should not be set.", callbackConf == NULL);

	res = KSI_AsyncHandle_getState(confHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED);

	res = KSI_AsyncHandle_getConfig(confHandle, &pushConf);
	CuAssert(tc, "Push configuration should be returned.", res == KSI_OK && pushConf != NULL);

	res = KSI_Config_getMaxRequests(pushConf, &intVal);
	CuAssert(tc, "Conf max requests value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 4);
	intVal = NULL;

	res = KSI_Config_getAggrPeriod(pushConf, &intVal);
	CuAssert(tc, "Conf aggregation period value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 3);

	res = KSI_AsyncHandle_getSignature(confHandle, &signature);
	CuAssert(tc, "Signature should not be returned.", res == KSI_INVALID_STATE && signature == NULL);

	/* Now get the actual response. */
	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getSignature(respHandle, &signature);
	CuAssert(tc, "Signature should be returned.", res == KSI_OK && signature != NULL);

	KSI_Signature_free(signature);
	KSI_Config_free(callbackConf);
	KSI_AsyncHandle_free(confHandle);
	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_responseWithPushConf_viaHandle(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response-with-conf-and-ack.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_Integer *intVal = NULL;
	KSI_AsyncHandle *confHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_Signature *signature = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;
	KSI_Config *pushConf = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	/* Get push configuration. */
	callbackCalls = 0;
	callbackConf = NULL;
	res = KSI_AsyncService_run(as, &confHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Wrong handle.",  confHandle != reqHandle);

	CuAssert(tc, "Conf callback should have not been invoked.", callbackCalls == 0);
	CuAssert(tc, "Push conf should not be set.", callbackConf == NULL);

	res = KSI_AsyncHandle_getState(confHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED);

	res = KSI_AsyncHandle_getConfig(confHandle, &pushConf);
	CuAssert(tc, "Push configuration should be returned.", res == KSI_OK && pushConf != NULL);

	res = KSI_Config_getMaxRequests(pushConf, &intVal);
	CuAssert(tc, "Conf max requests value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 4);
	intVal = NULL;

	res = KSI_Config_getAggrPeriod(pushConf, &intVal);
	CuAssert(tc, "Conf aggregation period value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 3);

	res = KSI_AsyncHandle_getSignature(confHandle, &signature);
	CuAssert(tc, "Signature should not be returned.", res == KSI_INVALID_STATE && signature == NULL);

	/* Now get the actual response. */
	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getSignature(respHandle, &signature);
	CuAssert(tc, "Signature should be returned.", res == KSI_OK && signature != NULL);

	KSI_Signature_free(signature);
	KSI_Config_free(callbackConf);
	KSI_AsyncHandle_free(confHandle);
	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_wrongResponse_getSignatureFail(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2016-03-08-aggr_response.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_Signature *signature = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK && respHandle != NULL);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getSignature(respHandle, &signature);
	CuAssert(tc, "Signature should not be returned.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_wrongResponseReqId(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response-wrong-id.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Nothing to be returned.", respHandle == NULL);

	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_wrongResponseReqId_rcvTimeout0(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response-wrong-id.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_Signature *signature = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;
	int error = 0;
	long errorExt = 0;
	KSI_Utf8String *msg = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_RCV_TIMEOUT, (void *)0);
	CuAssert(tc, "Unable to set option.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);
	CuAssert(tc, "Handle should be returned.", respHandle != NULL);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_ERROR);

	res = KSI_AsyncHandle_getSignature(respHandle, &signature);
	CuAssert(tc, "Signature should not be returned.", res == KSI_INVALID_STATE && signature == NULL);

	res = KSI_AsyncHandle_getError(respHandle, &error);
	CuAssert(tc, "Signing should fail error.", res == KSI_OK && error == KSI_NETWORK_RECIEVE_TIMEOUT);

	res = KSI_AsyncHandle_getExtError(respHandle, &errorExt);
	CuAssert(tc, "No extenrnal error should be present.", res == KSI_OK && errorExt == 0L);

	res = KSI_AsyncHandle_getErrorMessage(respHandle, &msg);
	CuAssert(tc, "There should be no error message.", res == KSI_OK && msg == NULL);


	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_responseVerifyWithRequest(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_DataHash *inpHsh = NULL;
	KSI_DataHash *reqHsh = NULL;
	KSI_AggregationResp *resp = NULL;
	KSI_AggregationReq *req = NULL;
	KSI_AggregationHashChainList *aggrChainList = NULL;
	KSI_AggregationHashChain *chain = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK && respHandle != NULL);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getAggregationResp(respHandle, &resp);
	CuAssert(tc, "Failed to get aggregation response.", res == KSI_OK && resp != NULL);

	res = KSI_AggregationResp_getAggregationChainList(resp, &aggrChainList);
	CuAssert(tc, "Unable to get aggregation chain list.", res == KSI_OK && aggrChainList != NULL);
	CuAssert(tc, "Unable to get aggregation chain list is emty.", KSI_AggregationHashChainList_length(aggrChainList) > 0);

	res = KSI_AggregationHashChainList_elementAt(aggrChainList, 0, &chain);
	CuAssert(tc, "Unable to get aggregation chain.", res == KSI_OK && chain != NULL);

	res = KSI_AggregationHashChain_getInputHash(chain, &inpHsh);
	CuAssert(tc, "Unable to chain input hash.", res == KSI_OK && inpHsh != NULL);

	res = KSI_AsyncHandle_getAggregationReq(respHandle, &req);
	CuAssert(tc, "Unable to get aggregation request.", res == KSI_OK && req != NULL);

	res = KSI_AggregationReq_getRequestHash(req, &reqHsh);
	CuAssert(tc, "Unable to get request hash.", res == KSI_OK && reqHsh != NULL);

	CuAssert(tc, "Request hash mismatch.", KSI_DataHash_equals(reqHsh, inpHsh));

	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_ErrorStatusWithSignatureElementsInResponse(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response-with-status-301.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	int error = 0;
	long errorExt = 0;
	KSI_Utf8String *msg = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK && respHandle != NULL);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_ERROR);

	res = KSI_AsyncHandle_getError(respHandle, &error);
	CuAssert(tc, "Signing should have failed with service upstream timeout error.", res == KSI_OK && error == KSI_SERVICE_UPSTREAM_TIMEOUT);

	res = KSI_AsyncHandle_getExtError(respHandle, &errorExt);
	CuAssert(tc, "There should be external error.", res == KSI_OK && errorExt == 0x301);

	res = KSI_AsyncHandle_getErrorMessage(respHandle, &msg);
	CuAssert(tc, "There should be no error message.", res == KSI_OK && msg == NULL);

	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_invalidResponse(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/extend_response.tlv",
	};

	int res;
	int error;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK && respHandle != NULL);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_ERROR);

	res = KSI_AsyncHandle_getError(respHandle, &error);
	CuAssert(tc, "Unable to get error.", res == KSI_OK);
	CuAssert(tc, "Error mismatch.", error == KSI_INVALID_FORMAT);

	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_twoResponsesWithSameId_validResponseFirst(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response-duplicate-response-ok.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_Signature *signature = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	/* Response contains two responses (PDUs) with same request IDs. First one is internally valid, second one is internally invalid. First one should be used and second one discarded. */
	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK && respHandle != NULL);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getSignature(respHandle, &signature);
	CuAssert(tc, "Unable to extract signature.", res == KSI_OK && signature != NULL);

	KSI_Signature_free(signature);
	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_twoResponsesWithSameId_invalidResponseFirst(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response-duplicate-response-nok.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	KSI_Signature *signature = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;
	KSI_AggregationResp *resp = NULL;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	/* Response contains two responses (PDUs) with same request IDs. First one is internally invalid, second one is internally valid. First one should be used and second one discarded. */
	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK && respHandle != NULL);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

	res = KSI_AsyncHandle_getSignature(respHandle, &signature);
	CuAssert(tc, "Signature extraction should have failed.", res == KSI_VERIFICATION_FAILURE && signature == NULL);

	res = KSI_AsyncHandle_getAggregationResp(respHandle, &resp);
	CuAssert(tc, "Unable to extract response.", res == KSI_OK && resp != NULL);

	KSI_Signature_free(signature);
	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_oneRequest_responseMissingHeader(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/nok_aggr_response_missing_header.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_AsyncHandle *reqHandle = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	int error = 0;
	int state = KSI_ASYNC_STATE_UNDEFINED;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_AGGR_RESPONSE_FILES, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_createAggrAsyncHandle(ctx, 1, (unsigned char *)"0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", 0, KSI_HASHALG_INVALID_VALUE, NULL, 0, 0, &reqHandle);
	CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

	res = KSI_AsyncService_addRequest(as, reqHandle);
	CuAssert(tc, "Unable to add request", res == KSI_OK);

	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK && respHandle != NULL);
	CuAssert(tc, "Handle mismatch.",  respHandle == reqHandle);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Unable to get request state.", res == KSI_OK && state == KSI_ASYNC_STATE_ERROR);

	res = KSI_AsyncHandle_getError(respHandle, &error);
	CuAssert(tc, "Signing should have failed with service upstream timeout error.", res == KSI_OK && error == KSI_INVALID_FORMAT);

	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_multipleRequests_loop(CuTest* tc) {
	static const char *TEST_REQ_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_01h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_02h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_03h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_04h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_05h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_06h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_07h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_08h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_09h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Ah.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Bh.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Ch.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Dh.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Eh.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Fh.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_10h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_11h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_12h.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	const char **p_req = NULL;
	size_t onHold = 0;
	size_t received = 0;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_REQ_AGGR_RESPONSE_FILES, TEST_REQ_DATA_COUNT, "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void*)(TEST_REQ_DATA_COUNT));
	CuAssert(tc, "Unable to set request cache size.", res == KSI_OK);

	p_req = TEST_REQ_DATA;
	do {
		KSI_AsyncHandle *respHandle = NULL;
		int state = KSI_ASYNC_STATE_UNDEFINED;
		KSI_Signature *signature = NULL;

		if (*p_req) {
			KSI_AsyncHandle *reqHandle = NULL;

			res = KSITest_createAggrAsyncHandle(ctx, 0, (unsigned char *)*p_req, strlen(*p_req), KSI_HASHALG_SHA2_256, NULL, 0, 0, &reqHandle);
			CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

			res = KSI_AsyncService_addRequest(as, reqHandle);
			CuAssert(tc, "Unable to add request.", res == KSI_OK);
			p_req++;
		}

		res = KSI_AsyncService_run(as, &respHandle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (respHandle == NULL) break;

		res = KSI_AsyncHandle_getState(respHandle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK);
		CuAssert(tc, "State should be RESPONSE_RECEIVED.", state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

		res = KSI_AsyncHandle_getSignature(respHandle, &signature);
		CuAssert(tc, "Unable to extract signature.", res == KSI_OK && signature != NULL);

		received++;
		KSI_Signature_free(signature);
		KSI_AsyncHandle_free(respHandle);
	} while (p_req != NULL);
	CuAssert(tc, "Response count mismatch.", TEST_REQ_DATA_COUNT == received);

	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_multipleRequests_loop_cacheSize5(CuTest* tc) {
	static const char *TEST_REQ_DATA[] = {
		"Guardtime", "KSI", "Blockchain", "is an", "industrial",
		"Guardtime", "KSI", "Blockchain", "is an", "industrial",
		"Guardtime", "KSI", "Blockchain", "is an", "industrial",
		NULL
	};
	static const size_t TEST_REQ_DATA_COUNT = TEST_RESP_COUNT(TEST_REQ_DATA) - 1;

	static const char *TEST_REQ_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_01h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_02h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_03h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_04h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_05h.tlv",

		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0100000001h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0100000002h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0100000003h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0100000004h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0100000005h.tlv",

		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0200000001h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0200000002h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0200000003h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0200000004h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0200000005h.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	const char **p_req = NULL;
	size_t onHold = 0;
	size_t received = 0;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_REQ_AGGR_RESPONSE_FILES, TEST_REQ_DATA_COUNT, "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void*)5);
	CuAssert(tc, "Unable to set request cache size.", res == KSI_OK);

	p_req = TEST_REQ_DATA;
	do {
		KSI_AsyncHandle *respHandle = NULL;
		int state = KSI_ASYNC_STATE_UNDEFINED;
		KSI_Signature *signature = NULL;

		if (*p_req) {
			KSI_AsyncHandle *reqHandle = NULL;

			res = KSITest_createAggrAsyncHandle(ctx, 0, (unsigned char *)*p_req, strlen(*p_req), KSI_HASHALG_SHA2_256, NULL, 0, 0, &reqHandle);
			CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

			res = KSI_AsyncService_addRequest(as, reqHandle);
			CuAssert(tc, "Unable to add request.", res == KSI_OK);
			p_req++;
		}

		res = KSI_AsyncService_run(as, &respHandle, &onHold);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		if (respHandle == NULL) break;

		res = KSI_AsyncHandle_getState(respHandle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK);
		CuAssert(tc, "State should be RESPONSE_RECEIVED.", state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

		res = KSI_AsyncHandle_getSignature(respHandle, &signature);
		CuAssert(tc, "Unable to extract signature.", res == KSI_OK && signature != NULL);

		received++;
		KSI_Signature_free(signature);
		KSI_AsyncHandle_free(respHandle);
	} while (p_req != NULL);
	CuAssert(tc, "Response count mismatch.", TEST_REQ_DATA_COUNT == received);

	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_multipleRequests_collect(CuTest* tc) {
	static const char *TEST_REQ_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_01h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_02h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_03h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_04h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_05h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_06h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_07h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_08h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_09h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Ah.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Bh.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Ch.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Dh.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Eh.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_0Fh.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_10h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_11h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_12h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_13h.tlv",
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-aggr_resp-req_id_14h.tlv",
	};

	int res;
	KSI_AsyncService *as = NULL;
	const char **p_req = NULL;
	size_t added = 0;
	size_t receivedCount = 0;
	size_t i;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_REQ_AGGR_RESPONSE_FILES, TEST_REQ_DATA_COUNT, "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void*)(TEST_REQ_DATA_COUNT));
	CuAssert(tc, "Unable to set request cache size.", res == KSI_OK);

	p_req = TEST_REQ_DATA;
	while (*p_req != NULL) {
		size_t pendingCount = 0;
		KSI_AsyncHandle *reqHandle = NULL;

		res = KSITest_createAggrAsyncHandle(ctx, 0, (unsigned char *)*p_req, strlen(*p_req), KSI_HASHALG_SHA2_256, NULL, 0, 0, &reqHandle);
		CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

		res = KSI_AsyncService_addRequest(as, reqHandle);
		CuAssert(tc, "Unable to add request.", res == KSI_OK);
		p_req++;

		res = KSI_AsyncService_getPendingCount(as, &pendingCount);
		CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
		CuAssert(tc, "Pending count mitmatch.", pendingCount == ++added);
	}

	do {
		res = KSI_AsyncService_run(as, NULL, NULL);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		res = KSI_AsyncService_getReceivedCount(as, &receivedCount);
		CuAssert(tc, "Unable to get received count.", res == KSI_OK);
	} while (added--);
	CuAssert(tc, "Response count mismatch.", TEST_REQ_DATA_COUNT == receivedCount);

	for (i = 0; i < receivedCount; i++) {
		int state = KSI_ASYNC_STATE_UNDEFINED;
		KSI_AsyncHandle *handle = NULL;
		KSI_Signature *signature = NULL;

		res = KSI_AsyncService_run(as, &handle, NULL);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		res = KSI_AsyncHandle_getState(handle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK && state != KSI_ASYNC_STATE_UNDEFINED);

		CuAssert(tc, "State should be RESPONSE_RECEIVED.", state == KSI_ASYNC_STATE_RESPONSE_RECEIVED);

		res = KSI_AsyncHandle_getSignature(handle, &signature);
		CuAssert(tc, "Unable to extract signature.", res == KSI_OK && signature != NULL);

		KSI_Signature_free(signature);
		KSI_AsyncHandle_free(handle);
	}

	KSI_AsyncService_free(as);
}

static void Test_AsyncSign_multipleRequests_collect_aggrResp301(CuTest* tc) {
	static const char *TEST_REQ_AGGR_RESPONSE_FILES[] = {
		"resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok_aggr_error_response_301.tlv"
	};

	int res;
	KSI_AsyncService *as = NULL;
	const char **p_req = NULL;
	size_t added = 0;
	size_t i;

	KSI_LOG_debug(ctx, "%s", __FUNCTION__);
	KSI_ERR_clearErrors(ctx);

	res = KSI_SigningAsyncService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_setEndpoint(as, TEST_REQ_AGGR_RESPONSE_FILES, 1, "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void*)(TEST_REQ_DATA_COUNT));
	CuAssert(tc, "Unable to set request cache size.", res == KSI_OK);

	p_req = TEST_REQ_DATA;
	while (*p_req != NULL) {
		size_t pendingCount = 0;
		KSI_AsyncHandle *reqHandle = NULL;

		res = KSITest_createAggrAsyncHandle(ctx, 0, (unsigned char *)*p_req, strlen(*p_req), KSI_HASHALG_SHA2_256, NULL, 0, 0, &reqHandle);
		CuAssert(tc, "Unable to create async handle.", res == KSI_OK && reqHandle != NULL);

		res = KSI_AsyncService_addRequest(as, reqHandle);
		CuAssert(tc, "Unable to add request.", res == KSI_OK);
		p_req++;

		res = KSI_AsyncService_getPendingCount(as, &pendingCount);
		CuAssert(tc, "Unable to get pending count.", res == KSI_OK);
		CuAssert(tc, "Pending count mitmatch.", pendingCount == ++added);
	}

	for (i = 0; i < added; i++) {
		int state = KSI_ASYNC_STATE_UNDEFINED;
		KSI_AsyncHandle *handle = NULL;
		KSI_Signature *signature = NULL;
		int error = 0;
		long errorExt = 0;
		KSI_Utf8String *msg = NULL;

		res = KSI_AsyncService_run(as, &handle, NULL);
		CuAssert(tc, "Failed to run async service.", res == KSI_OK);

		res = KSI_AsyncHandle_getState(handle, &state);
		CuAssert(tc, "Unable to get request state.", res == KSI_OK);
		CuAssert(tc, "State should be ERROR.", state == KSI_ASYNC_STATE_ERROR);

		res = KSI_AsyncHandle_getError(handle, &error);
		CuAssert(tc, "Signing should fail with error.", res == KSI_OK && error == KSI_SERVICE_UPSTREAM_TIMEOUT);

		res = KSI_AsyncHandle_getExtError(handle, &errorExt);
		CuAssert(tc, "There should be external error.", res == KSI_OK && errorExt == 0x301);

		res = KSI_AsyncHandle_getErrorMessage(handle, &msg);
		CuAssert(tc, "There should be error message.", res == KSI_OK && msg != NULL);
		CuAssert(tc, "Error message mismatch.", strcmp("No response from upstream servers", KSI_Utf8String_cstr(msg)) == 0);

		res = KSI_AsyncHandle_getSignature(handle, &signature);
		CuAssert(tc, "No signature in error state.", res == KSI_INVALID_STATE && signature == NULL);

		KSI_Signature_free(signature);
		KSI_AsyncHandle_free(handle);
	}

	KSI_AsyncService_free(as);
}

static void Test_HASign_confRequest_responseConfDefaultConsolidate(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES1[] = {"resource/tlv/" TEST_RESOURCE_AGGR_VER "/aggr_conf_response-max_req_512.tlv"};
	static const char *TEST_AGGR_RESPONSE_FILES2[] = {"resource/tlv/" TEST_RESOURCE_AGGR_VER "/aggr_conf_response-max_req_1024.tlv"};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_Integer *intVal = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;
	KSI_Config *cfg = NULL;
	KSI_AsyncHandle *cfgHandle = NULL;
	KSI_AggregationReq *cfgReq = NULL;

	KSI_LOG_debug(ctx, "START %s", __FUNCTION__);

	res = KSI_SigningHighAvailabilityService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_addEndpoint(as, TEST_AGGR_RESPONSE_FILES1, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES1), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_MockAsyncService_addEndpoint(as, TEST_AGGR_RESPONSE_FILES2, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES2), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AggregationReq_new(ctx, &cfgReq);
	CuAssert(tc, "Unable to create aggregation request.", res == KSI_OK && cfgReq != NULL);

	res = KSI_Config_new(ctx, &cfg);
	CuAssert(tc, "Unable to create config object.", res == KSI_OK && cfg != NULL);

	res = KSI_AggregationReq_setConfig(cfgReq, cfg);
	CuAssert(tc, "Unable to set request data hash.", res == KSI_OK);

	res = KSI_AsyncAggregationHandle_new(ctx, cfgReq, &cfgHandle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && cfgHandle != NULL);

	res = KSI_AsyncService_addRequest(as, cfgHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	callbackCalls = 0;
	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);

	CuAssert(tc, "Conf callback has been invoked.", callbackCalls == 0);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Request state mismatch.", state == KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED);

	cfg = NULL;
	res = KSI_AsyncHandle_getConfig(respHandle, &cfg);
	CuAssert(tc, "Unable to get server config.", res == KSI_OK && cfg != NULL);

	res = KSI_Config_getMaxRequests(cfg, &intVal);
	CuAssert(tc, "Conf max requests value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 1024);

	intVal = NULL;
	res = KSI_Config_getAggrPeriod(cfg, &intVal);
	CuAssert(tc, "Conf aggregation period value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 400);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static int KSITest_configConsolidateCallback(KSI_CTX *ctx, size_t id, void *userp, KSI_Config *haConfig, KSI_Config *respConfig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *haVal = NULL;
	KSI_Integer *respVal = NULL;

	KSI_LOG_debug(ctx, "%s: from %p (callback count %llu)", __FUNCTION__, (void*)id, (unsigned long long)++callbackCalls);

	if (ctx == NULL || haConfig == NULL || respConfig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if ((void*)ctx != userp) {
		KSI_LOG_debug(ctx, "%s: user poiter mismatch", __FUNCTION__);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Just store the smallest max req value from response. */
	res = KSI_Config_getMaxRequests(haConfig, &haVal);
	if (res != KSI_OK) goto cleanup;
	res = KSI_Config_getMaxRequests(respConfig, &respVal);
	if (res != KSI_OK) goto cleanup;

	if (KSI_Integer_getUInt64(haVal) == 0 || KSI_Integer_getUInt64(haVal) > KSI_Integer_getUInt64(respVal)) {
		res = KSI_Config_setMaxRequests(haConfig, respVal);
		if (res != KSI_OK) goto cleanup;
		KSI_Integer_free(haVal);
		res = KSI_Config_setMaxRequests(respConfig, NULL);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

static void Test_HASign_confRequest_responseConfConsolidateCallback(CuTest* tc) {
	static const char *TEST_AGGR_RESPONSE_FILES1[] = {"resource/tlv/" TEST_RESOURCE_AGGR_VER "/aggr_conf_response-max_req_512.tlv"};
	static const char *TEST_AGGR_RESPONSE_FILES2[] = {"resource/tlv/" TEST_RESOURCE_AGGR_VER "/aggr_conf_response-max_req_1024.tlv"};

	int res;
	KSI_AsyncService *as = NULL;
	KSI_Integer *intVal = NULL;
	KSI_AsyncHandle *respHandle = NULL;
	int state = KSI_ASYNC_STATE_UNDEFINED;
	KSI_Config *cfg = NULL;
	KSI_AsyncHandle *cfgHandle = NULL;
	KSI_AggregationReq *cfgReq = NULL;

	KSI_LOG_debug(ctx, "START %s", __FUNCTION__);

	res = KSI_SigningHighAvailabilityService_new(ctx, &as);
	CuAssert(tc, "Unable to create new async service object.", res == KSI_OK && as != NULL);

	res = KSITest_MockAsyncService_addEndpoint(as, TEST_AGGR_RESPONSE_FILES1, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES1), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSITest_MockAsyncService_addEndpoint(as, TEST_AGGR_RESPONSE_FILES2, TEST_RESP_COUNT(TEST_AGGR_RESPONSE_FILES2), "anon", "anon");
	CuAssert(tc, "Unable to configure service endpoint.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_CONF_CONSOLIDATE_CALLBACK, (void *)KSITest_configConsolidateCallback);
	CuAssert(tc, "Unable to set conf callback.", res == KSI_OK);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_CALLBACK_USERDATA, (void *)ctx);
	CuAssert(tc, "Unable to set conf callback.", res == KSI_OK);

	res = KSI_AggregationReq_new(ctx, &cfgReq);
	CuAssert(tc, "Unable to create aggregation request.", res == KSI_OK && cfgReq != NULL);

	res = KSI_Config_new(ctx, &cfg);
	CuAssert(tc, "Unable to create config object.", res == KSI_OK && cfg != NULL);

	res = KSI_AggregationReq_setConfig(cfgReq, cfg);
	CuAssert(tc, "Unable to set request data hash.", res == KSI_OK);

	res = KSI_AsyncAggregationHandle_new(ctx, cfgReq, &cfgHandle);
	CuAssert(tc, "Unable to create async request.", res == KSI_OK && cfgHandle != NULL);

	res = KSI_AsyncService_addRequest(as, cfgHandle);
	CuAssert(tc, "Unable to add request.", res == KSI_OK);

	callbackCalls = 0;
	res = KSI_AsyncService_run(as, &respHandle, NULL);
	CuAssert(tc, "Failed to run async service.", res == KSI_OK);

	CuAssert(tc, "Conf callback has not been invoked.", callbackCalls == 2);

	res = KSI_AsyncHandle_getState(respHandle, &state);
	CuAssert(tc, "Request state mismatch.", state == KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED);

	cfg = NULL;
	res = KSI_AsyncHandle_getConfig(respHandle, &cfg);
	CuAssert(tc, "Unable to get server config.", res == KSI_OK && cfg != NULL);

	res = KSI_Config_getMaxRequests(cfg, &intVal);
	CuAssert(tc, "Conf max requests value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 512);

	intVal = NULL;
	res = KSI_Config_getAggrPeriod(cfg, &intVal);
	CuAssert(tc, "Conf aggregation period value mismatch.", res == KSI_OK && KSI_Integer_getUInt64(intVal) == 0);

	KSI_LOG_debug(ctx, "%s: CLEANUP.", __FUNCTION__);

	KSI_AsyncHandle_free(respHandle);
	KSI_AsyncService_free(as);
}

static void preTest(void) {
	KSI_CTX_setOption(ctx, KSI_OPT_AGGR_CONF_RECEIVED_CALLBACK, NULL);
	KSI_CTX_setOption(ctx, KSI_OPT_EXT_CONF_RECEIVED_CALLBACK, NULL);
}

CuSuite* KSITest_NetAsync_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, Test_AsyncSingningService_verifyOptions);
	SUITE_ADD_TEST(suite, Test_AsyncSingningService_verifyPushConfCallbackOptions);
	SUITE_ADD_TEST(suite, Test_AsyncSingningService_verifyCacheSizeOption);
	SUITE_ADD_TEST(suite, Test_AsyncSingningService_addEmptyReq);
	SUITE_ADD_TEST(suite, Test_AsyncSingningService_addRequest_noEndpoint);
	SUITE_ADD_TEST(suite, Test_AsyncSingningService_runEmpty);
	SUITE_ADD_TEST(suite, Test_AsyncSingningService_verifyReqId);
	SUITE_ADD_TEST(suite, Test_AsyncSingningService_verifyRequestCacheFull);

	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_verifyReqCtx);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_verifySignature);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_multipleResponses_verifySignature);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_verifyNoError);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_responseWithPushConf_viaServiceCallback);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_responseWithPushConf_viaKsiCtxAggrCallback);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_responseWithPushConf_viaHandle_setKsiCtxExtCallback);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_responseWithPushConf_viaHandle);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_wrongResponse_getSignatureFail);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_wrongResponseReqId);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_wrongResponseReqId_rcvTimeout0);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_responseVerifyWithRequest);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_responseMissingHeader);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_ErrorStatusWithSignatureElementsInResponse);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_invalidResponse);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_twoResponsesWithSameId_validResponseFirst);
	SUITE_ADD_TEST(suite, Test_AsyncSign_oneRequest_twoResponsesWithSameId_invalidResponseFirst);

	SUITE_ADD_TEST(suite, Test_AsyncSign_multipleRequests_loop);
	SUITE_ADD_TEST(suite, Test_AsyncSign_multipleRequests_loop_cacheSize5);
	SUITE_ADD_TEST(suite, Test_AsyncSign_multipleRequests_collect);
	SUITE_ADD_TEST(suite, Test_AsyncSign_multipleRequests_collect_aggrResp301);

	SUITE_ADD_TEST(suite, Test_HASign_confRequest_responseConfDefaultConsolidate);
	SUITE_ADD_TEST(suite, Test_HASign_confRequest_responseConfConsolidateCallback);

	return suite;
}
