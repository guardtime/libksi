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

#include <ksi/net.h>
#include <ksi/net_http.h>
#include <ksi/net_tcp.h>
#include <ksi/net_uri.h>

#include "cutest/CuTest.h"
#include "all_integration_tests.h"

#include "../src/ksi/internal.h"

#include "../src/ksi/impl/ctx_impl.h"

extern KSI_CTX *ctx;
extern KSITest_Conf conf;

static void postTest(void) {
	/* Restore default PDU version. */
	KSI_CTX_setFlag(ctx, KSI_OPT_AGGR_PDU_VER, (void*)KSI_AGGREGATION_PDU_VERSION);
}

static int getDataHash(KSI_DataHash **hsh) {
	return KSI_DataHash_fromDigest(ctx, KSI_getHashAlgorithmByName("sha256"), (const unsigned char*)"c8ef6d57ac28d1b4e95a513959f5fcdd0688380a43d601a5ace1d2e96884690a", 32, hsh);
}

static void nokAggr_TreeTooLarge(CuTest* tc, const char *scheme) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationReq *request = NULL;
	KSI_RequestHandle *handle = NULL;
	KSI_AggregationResp *response = NULL;

	KSI_DataHash *hsh = NULL;
	KSI_Integer *ID = NULL;
	KSI_Integer *requestLevel = NULL;
	KSI_Integer *resp_status = NULL;

	KSI_LOG_debug(ctx, "%s: %s", __FUNCTION__, scheme);
	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_setAggregator(ctx, KSITest_composeUri(scheme, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
	CuAssert(tc, "Unable to configure aggregator.", res == KSI_OK);

	res = KSI_AggregationReq_new(ctx, &request);
	CuAssert(tc, "Unable to create aggregation request.", res == KSI_OK && request != NULL);

	res = getDataHash(&hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_Integer_new(ctx, 0x5544332211ll, &ID);
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

static void Test_NOKAggr_TreeTooLarge(CuTest* tc) {
	nokAggr_TreeTooLarge(tc, TEST_SCHEME_HTTP);
	nokAggr_TreeTooLarge(tc, TEST_SCHEME_TCP);
}

static void createSignatureDefaultProvider(CuTest* tc, const char *scheme) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	KSI_LOG_debug(ctx, "%s: %s", __FUNCTION__, scheme);
	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_setAggregator(ctx, KSITest_composeUri(scheme, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
	CuAssert(tc, "Unable to configure aggregator.", res == KSI_OK);

	res = getDataHash(&hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_sign(ctx, hsh, &sig);
	CuAssert(tc, "Unable to create signature.", res == KSI_OK && sig != NULL);

	res = KSI_verifyDataHash(ctx, sig, hsh);
	CuAssert(tc, "Unable to verify signature.", res == KSI_OK);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	return;
}

static void Test_CreateSignatureDefaultProvider(CuTest* tc) {
	createSignatureDefaultProvider(tc, TEST_SCHEME_HTTP);
	createSignatureDefaultProvider(tc, TEST_SCHEME_TCP);
}

static void createSignatureUsingHashImprintWithNotImplementedHashFunction(CuTest* tc, const char *scheme) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	KSI_LOG_debug(ctx, "%s: %s", __FUNCTION__, scheme);
	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_setAggregator(ctx, KSITest_composeUri(scheme, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
	CuAssert(tc, "Unable to configure aggregator.", res == KSI_OK);

	/* Hash imprint that is using not implemented hash algorithm, must be accepted as input hash. */
	res = KSITest_DataHash_fromStr(ctx, "080000000000000000000000000000000000000000000000000000000000000000", &hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_sign(ctx, hsh, &sig);
	CuAssert(tc, "Unable to create signature.", res == KSI_OK && sig != NULL);

	res = KSI_verifyDataHash(ctx, sig, hsh);
	CuAssert(tc, "Unable to verify signature.", res == KSI_OK);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	return;
}

static void Test_createSignatureUsingHashImprintWithNotImplementedHashFunction(CuTest* tc) {
	createSignatureUsingHashImprintWithNotImplementedHashFunction(tc, TEST_SCHEME_HTTP);
	createSignatureUsingHashImprintWithNotImplementedHashFunction(tc, TEST_SCHEME_TCP);
}

static void createSignatureWrongHMAC(CuTest* tc, const char *scheme) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	KSI_LOG_debug(ctx, "%s: %s", __FUNCTION__, scheme);
	KSI_ERR_clearErrors(ctx);

	res = getDataHash(&hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_CTX_setAggregator(ctx, KSITest_composeUri(scheme, &conf.aggregator), "test-test", "tset-tset");
	CuAssert(tc, "Unable to spoil aggregator authentication data.", res == KSI_OK);

	/* Reset old aggregator password. */
	res = KSI_Signature_sign(ctx, hsh, &sig);
	CuAssert(tc, "Unable to create signature.", res == KSI_SERVICE_AUTHENTICATION_FAILURE && sig == NULL);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	return;
}

static void Test_CreateSignatureWrongHMAC(CuTest* tc) {
	createSignatureWrongHMAC(tc, TEST_SCHEME_HTTP);
	createSignatureWrongHMAC(tc, TEST_SCHEME_TCP);
}

static void createSignatureUsingExtender(CuTest* tc, const char *scheme) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	KSI_LOG_debug(ctx, "%s: %s", __FUNCTION__, scheme);
	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_setAggregator(ctx, KSITest_composeUri(scheme, &conf.extender), conf.extender.user, conf.extender.pass);
	CuAssert(tc, "Unable to configure extender as aggregator.", res == KSI_OK);

	res = getDataHash(&hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_sign(ctx, hsh, &sig);
	CuAssert(tc, "The creation of signature must fail.", sig == NULL);
	if (strcmp(scheme, TEST_SCHEME_HTTP) == 0) {
		CuAssert(tc, "Invalid KSI status code for mixed up request.", res == KSI_HTTP_ERROR);
		CuAssert(tc, "External error (HTTP) must be 400.", ctx_get_base_external_error(ctx) == 400);
	} else if (strcmp(scheme, TEST_SCHEME_TCP) == 0) {
		CuAssert(tc, "Invalid KSI status code for mixed up request.", res == KSI_INVALID_FORMAT);
	} else {
		CuFail(tc, "Unknown transport protocol.");
	}

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	return;
}

static void Test_CreateSignatureUsingExtender(CuTest* tc) {
	createSignatureUsingExtender(tc, TEST_SCHEME_HTTP);
}

static void Test_CreateSignatureUsingExtender_tcp(CuTest* tc) {
	createSignatureUsingExtender(tc, TEST_SCHEME_TCP);
}

static void Test_CreateSignature_useProvider(CuTest* tc, const KSITest_ServiceConf *service,
		int (*createProvider)(KSI_CTX *ctx, KSI_NetworkClient **http),
		int (*setAggregator)(KSI_NetworkClient *client, const KSITest_ServiceConf *service)) {
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

	res = setAggregator(client, service);
	CuAssert(tc, "Unable to set aggregator specific service information.", res == KSI_OK);

	res = KSI_CTX_setNetworkProvider(ctx, client);
	CuAssert(tc, "Unable to set new network client.", res == KSI_OK);
	client = NULL;

	res = getDataHash(&hsh);
	CuAssert(tc, "Unable to create hash.", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_sign(ctx, hsh, &sig);
	CuAssert(tc, "The creation of signature must not fail.", sig != NULL);


	KSI_NetworkClient_free(client);
	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	KSI_CTX_free(ctx);
	return;
}

static int uriHttp_setAggrWrapper(KSI_NetworkClient *client, const KSITest_ServiceConf *service) {
	return KSI_UriClient_setAggregator(client, KSITest_composeUri(TEST_SCHEME_HTTP, service), service->user, service->pass);
}

static int uriHttp_setAggrWrapper_noCred(KSI_NetworkClient *client, const KSITest_ServiceConf *service) {
	return KSI_UriClient_setAggregator(client, KSITest_composeUri(TEST_SCHEME_HTTP, service), NULL, NULL);
}

static int uriTcp_setAggrWrapper(KSI_NetworkClient *client, const KSITest_ServiceConf *service) {
	return KSI_UriClient_setAggregator(client, KSITest_composeUri(TEST_SCHEME_TCP, service), service->user, service->pass);
}

static int uriTcp_setAggrWrapper_noCred(KSI_NetworkClient *client, const KSITest_ServiceConf *service) {
	return KSI_UriClient_setAggregator(client, KSITest_composeUri(TEST_SCHEME_TCP, service), NULL, NULL);
}

static int tcp_setAggrWrapper(KSI_NetworkClient *client, const KSITest_ServiceConf *service) {
	return KSI_TcpClient_setAggregator(client, service->host, service->port, service->user, service->pass);
}

static void Test_CreateSignatureDifferentNetProviders(CuTest* tc) {
	/* Tcp provider. */
	Test_CreateSignature_useProvider(tc, &conf.aggregator,
			KSI_TcpClient_new,
			tcp_setAggrWrapper);

	/* Uri provider http. */
	Test_CreateSignature_useProvider(tc, &conf.aggregator,
			KSI_UriClient_new,
			uriHttp_setAggrWrapper);

	/* Uri provider. */
	Test_CreateSignature_useProvider(tc, &conf.aggregator,
			KSI_UriClient_new,
			uriTcp_setAggrWrapper);
	return;
}

static void Test_CreateSignatureUserInfoFromUrl(CuTest* tc) {
	/* Uri provider - all info is extracted from uri. */
	Test_CreateSignature_useProvider(tc, &conf.aggregator,
			KSI_UriClient_new,
			uriHttp_setAggrWrapper_noCred);

	Test_CreateSignature_useProvider(tc, &conf.aggregator,
			KSI_UriClient_new,
			uriTcp_setAggrWrapper_noCred);
	return;
}

static void requestAggregatorConfig(CuTest* tc, const char *scheme) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Config *config = NULL;

	KSI_LOG_debug(ctx, "%s: %s", __FUNCTION__, scheme);
	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_setAggregator(ctx, KSITest_composeUri(scheme, &conf.aggregator), conf.aggregator.user, conf.aggregator.pass);
	CuAssert(tc, "Unable to configure aggregator.", res == KSI_OK);

	res = KSI_receiveAggregatorConfig(ctx, &config);
	CuAssert(tc, "Unable to receive aggregator config.", res == KSI_OK && config != NULL);

	KSI_Config_free(config);
}

static void Test_RequestAggregatorConfig(CuTest* tc) {
	requestAggregatorConfig(tc, TEST_SCHEME_HTTP);
	requestAggregatorConfig(tc, TEST_SCHEME_TCP);
}

CuSuite* AggreIntegrationTests_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->postTest = postTest;

	SUITE_ADD_TEST(suite, Test_NOKAggr_TreeTooLarge);
	SUITE_ADD_TEST(suite, Test_CreateSignatureDefaultProvider);
	SUITE_ADD_TEST(suite, Test_createSignatureUsingHashImprintWithNotImplementedHashFunction);
	SUITE_ADD_TEST(suite, Test_CreateSignatureWrongHMAC);
	SUITE_ADD_TEST(suite, Test_CreateSignatureUsingExtender);
	SUITE_ADD_TEST(suite, Test_CreateSignatureUsingExtender_tcp);
	SUITE_ADD_TEST(suite, Test_CreateSignatureDifferentNetProviders);
	SUITE_ADD_TEST(suite, Test_CreateSignatureUserInfoFromUrl);
	SUITE_ADD_TEST(suite, Test_RequestAggregatorConfig);

	return suite;
}

