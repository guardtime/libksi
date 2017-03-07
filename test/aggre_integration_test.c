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
#include "cutest/CuTest.h"
#include "all_integration_tests.h"
#include <ksi/net_uri.h>
#include <ksi/net_http.h>
#include <ksi/net.h>
#include "../src/ksi/ctx_impl.h"
#include "../src/ksi/internal.h"

extern KSI_CTX *ctx;


static void Test_NOKAggr_TreeTooLarge(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationReq *request = NULL;
	KSI_RequestHandle *handle = NULL;
	KSI_AggregationResp *response = NULL;

	KSI_DataHash *hsh = NULL;
	KSI_Integer *ID = NULL;
	KSI_Integer *requestLevel = NULL;
	KSI_Integer *resp_status = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_AggregationReq_new(ctx, &request);
	CuAssert(tc, "Unable to create aggregation request.", res == KSI_OK && request != NULL);

	res = KSI_DataHash_fromDigest(ctx, KSI_getHashAlgorithmByName("sha256"), (const unsigned char*)"c8ef6d57ac28d1b4e95a513959f5fcdd0688380a43d601a5ace1d2e96884690a", 32, &hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_Integer_new(ctx, 0x5544332211, &ID);
	CuAssert(tc, "Unable to create request ID.", res == KSI_OK && ID != NULL);

	res = KSI_Integer_new(ctx, 0xffffff, &requestLevel);
	CuAssert(tc, "Unable to create request level.", res == KSI_OK && requestLevel != NULL);

	res = KSI_AggregationReq_setRequestLevel(request, requestLevel);
	CuAssert(tc, "Unable to create request level.", res == KSI_OK);
	requestLevel = NULL;

	res = KSI_AggregationReq_setRequestId(request, ID);
	CuAssert(tc, "Unable set request ID.", res == KSI_OK);
	ID = NULL;

	res = KSI_AggregationReq_setRequestHash(request, hsh);
	CuAssert(tc, "Unable set request hash.", res == KSI_OK);
	hsh = NULL;

	res = KSI_sendSignRequest(ctx, request, &handle);
	CuAssert(tc, "Unable to send (prepare) sign request.", res == KSI_OK);

	res = KSI_RequestHandle_perform(handle);
	CuAssert(tc, "Unable to send (perform) sign request.", res == KSI_OK);

	res = KSI_RequestHandle_getAggregationResponse(handle, &response);
	CuAssert(tc, "Unable to get (send and get) sign request.", res == KSI_OK && response != NULL);

	res = KSI_AggregationResp_getStatus(response, &resp_status);
	CuAssert(tc, "Unable to get response status.", res == KSI_OK && resp_status != NULL);
	CuAssert(tc, "WrongErrorCode.", KSI_Integer_equalsUInt(resp_status, 0x104));

	KSI_AggregationReq_free(request);
	KSI_RequestHandle_free(handle);
	KSI_AggregationResp_free(response);

	KSI_DataHash_free(hsh);
	KSI_Integer_free(requestLevel);
	KSI_Integer_free(ID);
	return;
}

static void Test_CreateSignatureDefaultProvider(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;


	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromDigest(ctx, KSI_getHashAlgorithmByName("sha256"), (const unsigned char*)"c8ef6d57ac28d1b4e95a513959f5fcdd0688380a43d601a5ace1d2e96884690a", 32, &hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_sign(ctx, hsh, &sig);
	CuAssert(tc, "Unable to create signature.", res == KSI_OK && sig != NULL);

	res = KSI_verifyDataHash(ctx, sig, hsh);
	CuAssert(tc, "Unable to verify signature.", res == KSI_OK);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	return;
}

static void Test_TCPCreateSignatureDefaultProvider(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;


	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromDigest(ctx, KSI_getHashAlgorithmByName("sha256"), (const unsigned char*)"c8ef6d57ac28d1b4e95a513959f5fcdd0688380a43d601a5ace1d2e96884690a", 32, &hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_CTX_setAggregator(ctx, conf.tcp_url, conf.tcp_user, conf.tcp_pass);
	CuAssert(tc, "Unable to spoil aggregator authentication data.", res == KSI_OK);

	res = KSI_Signature_sign(ctx, hsh, &sig);
	KSI_CTX_setAggregator(ctx, conf.aggregator_url, conf.aggregator_user, conf.aggregator_pass);
	CuAssert(tc, "Unable to create signature.", res == KSI_OK && sig != NULL);

	res = KSI_verifyDataHash(ctx, sig, hsh);
	CuAssert(tc, "Unable to verify signature.", res == KSI_OK);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	return;
}

static void Test_CreateSignatureWrongHMAC(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);


	res = KSI_DataHash_fromDigest(ctx, KSI_getHashAlgorithmByName("sha256"), (const unsigned char*)"c8ef6d57ac28d1b4e95a513959f5fcdd0688380a43d601a5ace1d2e96884690a", 32, &hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_CTX_setAggregator(ctx, conf.aggregator_url, "test-test", "tset-tset");
	CuAssert(tc, "Unable to spoil aggregator authentication data.", res == KSI_OK);

	/*Reset old aggregator password.*/
	res = KSI_Signature_sign(ctx, hsh, &sig);
	KSI_CTX_setAggregator(ctx, conf.aggregator_url, conf.aggregator_user, conf.aggregator_pass);
	CuAssert(tc, "Unable to create signature.", res == KSI_SERVICE_AUTHENTICATION_FAILURE && sig == NULL);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	return;
}

static void Test_CreateSignatureUsingExtender(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_CTX *ctx = NULL;

	/* Create the context. */
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Unable to create ctx.", res == KSI_OK && ctx != NULL);

	res = KSI_CTX_setAggregator(ctx, conf.extender_url, conf.extender_user, conf.extender_pass);
	CuAssert(tc, "Unable to set configure extender as aggregator.", res == KSI_OK);

	res = KSI_DataHash_fromDigest(ctx, KSI_getHashAlgorithmByName("sha256"), (const unsigned char*)"c8ef6d57ac28d1b4e95a513959f5fcdd0688380a43d601a5ace1d2e96884690a", 32, &hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_sign(ctx, hsh, &sig);
	CuAssert(tc, "The creation of signature must fail.", sig == NULL);
	CuAssert(tc, "Invalid KSI status code for mixed up request.", res == KSI_HTTP_ERROR);
	CuAssert(tc, "External error (HTTP) must be 400.", ctx_get_base_external_error(ctx) == 400);


	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	KSI_CTX_free(ctx);
	return;
}

static void Test_CreateSignature_useProvider(CuTest* tc, const char *uri_host, unsigned port, const char *user, const char *key,
		int (*createProvider)(KSI_CTX *ctx, KSI_NetworkClient **http),
		int (*setAggregator)(KSI_NetworkClient *client, const char *url_host, unsigned port, const char *user, const char *pass)) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_NetworkClient *client = NULL;
	KSI_CTX *ctx = NULL;

	/* Create the context. */
	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Unable to create ctx.", res == KSI_OK && ctx != NULL);

	res = createProvider(ctx, &client);
	CuAssert(tc, "Unable to create network client.", res == KSI_OK && client != NULL);

	res = setAggregator(client, uri_host, port, user, key);
	CuAssert(tc, "Unable to set aggregator specific service information.", res == KSI_OK);

	res = KSI_CTX_setNetworkProvider(ctx, client);
	CuAssert(tc, "Unable to set new network client.", res == KSI_OK);
	client = NULL;

	res = KSI_DataHash_fromDigest(ctx, KSI_getHashAlgorithmByName("sha256"), (const unsigned char*)"c8ef6d57ac28d1b4e95a513959f5fcdd0688380a43d601a5ace1d2e96884690a", 32, &hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_sign(ctx, hsh, &sig);
	CuAssert(tc, "The creation of signature must not fail.", sig != NULL);


	KSI_NetworkClient_free(client);
	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	KSI_CTX_free(ctx);
	return;
}

static int uri_setAggrWrapper(KSI_NetworkClient *client, const char *url_host, unsigned port, const char *user, const char *pass) {
	return KSI_UriClient_setAggregator(client, url_host, user, pass);
}

static int tcp_setAggrWrapper(KSI_NetworkClient *client, const char *url_host, unsigned port, const char *user, const char *pass) {
	return KSI_TcpClient_setAggregator(client, url_host, port, user, pass);
}

static void Test_CreateSignatureDifferentNetProviders(CuTest* tc) {
	/* Tcp provider. */
	Test_CreateSignature_useProvider(tc,
			conf.tcp_host, conf.tcp_port, conf.tcp_user, conf.tcp_pass,
			KSI_TcpClient_new,
			tcp_setAggrWrapper);

	/* Uri provider http. */
	Test_CreateSignature_useProvider(tc,
			conf.aggregator_url, 0, conf.aggregator_user, conf.aggregator_pass,
			KSI_UriClient_new,
			uri_setAggrWrapper);

	/* Uri provider */
	Test_CreateSignature_useProvider(tc,
			conf.tcp_url, 0, conf.tcp_user, conf.tcp_pass,
			KSI_UriClient_new,
			uri_setAggrWrapper);
	return;
}

static void Test_CreateSignatureUserInfoFromUrl(CuTest* tc) {
	/* Uri provider - all info is extracted from uri. */
	Test_CreateSignature_useProvider(tc,
			conf.aggregator_url, 0, NULL, NULL,
			KSI_UriClient_new,
			uri_setAggrWrapper);

	Test_CreateSignature_useProvider(tc,
			conf.tcp_url, 0, NULL, NULL,
			KSI_UriClient_new,
			uri_setAggrWrapper);
	return;
}

static void Test_Pipelining(CuTest* tc) {
	int res;
	KSI_NetworkClient *http = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_RequestHandle *handle[10];
	KSI_AggregationReq *req[10];
	KSI_Integer *reqId = NULL;
	int i;

	memset(handle, 0, sizeof(handle));
	memset(req, 0, sizeof(handle));

	KSI_LOG_debug(ctx, "Test_Pipelining: START.");

	res = KSI_CTX_setAggregator(ctx, conf.aggregator_url, conf.aggregator_user, conf.aggregator_pass);
	CuAssert(tc, "Unable to set aggregator to the http client.", res == KSI_OK);

	http = ctx->netProvider;

	res = KSI_DataHash_create(ctx, "foobar", 6, KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Unable to create data hash from string.", res == KSI_OK && hsh != NULL);

	KSI_LOG_debug(ctx, "Test_Pipelining: SEND.");

	/* Prepare and send the requests. */
	for (i = 0; i < 10; i++) {
		KSI_LOG_debug(ctx, "Test_Pipelining: Creating request %d.", i);

		res = KSI_AggregationReq_new(ctx, &req[i]);
		CuAssert(tc, "Unable to create aggregation request.", res == KSI_OK && req != NULL);

		res = KSI_AggregationReq_setRequestHash(req[i], KSI_DataHash_ref(hsh));
		CuAssert(tc, "Unable to set request data hash.", res == KSI_OK);

		res = KSI_Integer_new(ctx, i, &reqId);
		CuAssert(tc, "Unable to create reqId.", res == KSI_OK && reqId != NULL);

		res = KSI_AggregationReq_setRequestId(req[i], reqId);
		CuAssert(tc, "Unable to set request id.", res == KSI_OK);

		reqId = NULL;

		res = KSI_NetworkClient_sendSignRequest(http, req[i], &handle[i]);
		CuAssert(tc, "Unable to send first request.", res == KSI_OK && handle[i] != NULL);
	}

	KSI_LOG_debug(ctx, "Test_Pipelining: RECEIVE.");

	/* Loop over the responses and verify the signatures. */
	for (i = 0; i < 10; i++) {
		KSI_AggregationResp *resp = NULL;
		KSI_Integer *reqId = NULL;

		KSI_LOG_debug(ctx, "Test_Pipelining: Reading reponse %d.", i);

		res = KSI_RequestHandle_perform(handle[i]);
		CuAssert(tc, "Unable to perform request.", res == KSI_OK);

		res = KSI_RequestHandle_getAggregationResponse(handle[i], &resp);
		CuAssert(tc, "Unable to get agggregation response.", res == KSI_OK && resp != NULL);

		res = KSI_AggregationResp_getRequestId(resp, &reqId);
		CuAssert(tc, "Unable to get request id from response.", res == KSI_OK && reqId != NULL);

		CuAssert(tc, "Request id mismatch.", KSI_Integer_equalsUInt(reqId, i));

		KSI_AggregationResp_free(resp);
		resp = NULL;
	}

	KSI_LOG_debug(ctx, "Test_Pipelining: CLEANUP.");

	/* Cleanup. */
	KSI_DataHash_free(hsh);
	for (i = 0; i < 10; i++) {
		KSI_AggregationReq_free(req[i]);
		KSI_RequestHandle_free(handle[i]);
	}

	KSI_LOG_debug(ctx, "Test_Pipelining: FINISH.");

}

static void Test_RequestAggregatorConfig(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Config *config = NULL;

KSI_LOG_debug(ctx, ">>>>>>>>>>>> Test_RequestAggregatorConfig. START");
	res = KSI_receiveAggregatorConfig(ctx, &config);
KSI_LOG_logCtxError(ctx, KSI_LOG_DEBUG);
KSI_LOG_debug(ctx, ">>>>>>>>>>>> Test_RequestAggregatorConfig. END");
	CuAssert(tc, "Unable to receive aggregator config.", res == KSI_OK && config != NULL);

	KSI_Config_free(config);
}

static void Test_RequestAggregatorConfig_pduV2(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Config *config = NULL;

	KSI_CTX_setFlag(ctx, KSI_CTX_FLAG_AGGR_PDU_VER, (void*)KSI_PDU_VERSION_2);

KSI_LOG_debug(ctx, ">>>>>>>>>>>> Test_RequestAggregatorConfig_pduV2. START");
	res = KSI_receiveAggregatorConfig(ctx, &config);
KSI_LOG_logCtxError(ctx, KSI_LOG_DEBUG);
KSI_LOG_debug(ctx, ">>>>>>>>>>>> Test_RequestAggregatorConfig_pduV2. END");
	CuAssert(tc, "Unable to receive aggregator config.", res == KSI_OK && config != NULL);

	KSI_CTX_setFlag(ctx, KSI_CTX_FLAG_AGGR_PDU_VER, (void*)KSI_EXTENDING_PDU_VERSION);

	KSI_Config_free(config);
}


CuSuite* AggreIntegrationTests_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, Test_CreateSignatureDefaultProvider);
	SUITE_ADD_TEST(suite, Test_CreateSignatureWrongHMAC);
	SUITE_ADD_TEST(suite, Test_NOKAggr_TreeTooLarge);
	SUITE_ADD_TEST(suite, Test_TCPCreateSignatureDefaultProvider);
	SUITE_ADD_TEST(suite, Test_CreateSignatureUsingExtender);
	SUITE_ADD_TEST(suite, Test_CreateSignatureDifferentNetProviders);
	SUITE_ADD_TEST(suite, Test_CreateSignatureUserInfoFromUrl);
	SUITE_ADD_TEST(suite, Test_Pipelining);
	SUITE_ADD_TEST(suite, Test_RequestAggregatorConfig);
	SUITE_ADD_TEST(suite, Test_RequestAggregatorConfig_pduV2);

	return suite;
}

