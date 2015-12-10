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
#include <ksi/net_uri.h>
#include <ksi/compatibility.h>

#include "../src/ksi/net_uri_impl.h"
#include "../src/ksi/net_http_impl.h"
#include "../src/ksi/net_tcp_impl.h"
#include "cutest/CuTest.h"
#include "all_tests.h"

extern KSI_CTX *ctx;

static 	const char *validHttpUri[] = {
		"ksi://localhost",
		"ksi://127.0.0.1",
		"ksi+http://localhost",
		"ksi+http://127.0.0.1",
		"http://localhost",
		"http://127.0.0.1",
		"ksi://localhost:12345",
		"ksi://127.0.0.1:12345",
		"ksi+http://localhost:1234",
		"ksi+http://127.0.0.1:1234",
		"http://localhost:1234",
		"http://127.0.0.1:1234",
		"localhost",
		"127.0.0.1",
		"localhost:1234",
		"127.0.0.1:1234",
		NULL
};


static const char *validTcpUri[] = {
		"ksi+tcp://localhost:1234",
		"ksi+tcp://127.0.0.1:1234",
		NULL
};

static const char *invalidUri[] = {
		"ksi+tcp://localhost",
		"ksi+tcp://127.0.0.1",
		NULL
};

static void testUriClientInit(CuTest* tc) {
	int res;
	KSI_NetworkClient *net = NULL;
	KSI_UriClient *uri = NULL;

	res = KSI_UriClient_new(ctx, &net);
	uri = net->impl;

	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && uri != NULL);
	CuAssert(tc, "URI client not initialized properly.", uri->httpClient != NULL);
	CuAssert(tc, "TCP client should not be initialized by default.", uri->tcpClient == NULL);
	CuAssert(tc, "Default client for aggregation should be the HTTP client", uri->pAggregationClient == (KSI_NetworkClient *)uri->httpClient);
	CuAssert(tc, "Default client for extending should be the HTTP client", uri->pExtendClient == (KSI_NetworkClient *)uri->httpClient);

	KSI_NetworkClient_free(net);
}

static void testValidAggregatorHttpUri(CuTest* tc) {
	int res;
	KSI_NetworkClient *net = NULL;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &net);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && net != NULL);

	uri = net->impl;

	while (validHttpUri[i]) {
		char errm[1024];
		uri->pAggregationClient = NULL;

		res = KSI_UriClient_setAggregator(net, validHttpUri[i], "dummy", "dummy");
		KSI_snprintf(errm, sizeof(errm), "Unable to set valid URI for aggregator address '%s'", validHttpUri[i]);
		CuAssert(tc, errm, res == KSI_OK);

		CuAssert(tc, "Aggregator client should be the HTTP client", uri->pAggregationClient == (KSI_NetworkClient *)uri->httpClient);

		i++;
	}

	KSI_NetworkClient_free(net);
}

static void testValidExtenderHttpUri(CuTest* tc) {
	int res;
	KSI_NetworkClient *net = NULL;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &net);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && net != NULL);

	uri = net->impl;

	while (validHttpUri[i]) {
		char errm[1024];

		uri->pExtendClient = NULL;

		res = KSI_UriClient_setExtender(net, validHttpUri[i], "dummy", "dummy");
		KSI_snprintf(errm, sizeof(errm), "Unable to set valid URI for extender address '%s'", validHttpUri[i]);
		CuAssert(tc, errm, res == KSI_OK);

		CuAssert(tc, "Extender client should be the HTTP client", uri->pExtendClient == (KSI_NetworkClient *)uri->httpClient);

		i++;
	}

	KSI_NetworkClient_free(net);
}

static void testValidAggregatorTcpUri(CuTest* tc) {
	int res;
	KSI_NetworkClient *net = NULL;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &net);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && net != NULL);

	uri = net->impl;

	while (validTcpUri[i]) {
		char errm[1024];
		uri->pAggregationClient = NULL;

		KSI_NetworkClient_free(uri->tcpClient);
		uri->tcpClient = NULL;

		res = KSI_UriClient_setAggregator(net, validTcpUri[i], "dummy", "dummy");

		KSI_snprintf(errm, sizeof(errm), "Unable to set valid URI for aggregator address '%s'", validTcpUri[i]);
		CuAssert(tc, errm, res == KSI_OK);

		KSI_snprintf(errm, sizeof(errm), "TCP client should be initialized for address '%s'", validTcpUri[i]);
		CuAssert(tc, errm, uri->tcpClient != NULL);

		CuAssert(tc, "Aggregator client should be the TCP client", uri->pAggregationClient == (KSI_NetworkClient *)uri->tcpClient);

		i++;
	}

	KSI_NetworkClient_free(net);
}

static void testValidExtenderTcpUri(CuTest* tc) {
	int res;
	KSI_NetworkClient *net = NULL;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &net);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && net != NULL);

	uri = net->impl;

	while (validTcpUri[i]) {
		char errm[1024];

		uri->pExtendClient = NULL;

		KSI_NetworkClient_free(uri->tcpClient);
		uri->tcpClient = NULL;

		res = KSI_UriClient_setExtender(net, validTcpUri[i], "dummy", "dummy");
		KSI_snprintf(errm, sizeof(errm), "Unable to set valid URI for extender address '%s'", validTcpUri[i]);
		CuAssert(tc, errm, res == KSI_OK);

		KSI_snprintf(errm, sizeof(errm), "TCP client should be initialized for address '%s'", validTcpUri[i]);
		CuAssert(tc, errm, uri->tcpClient != NULL);

		CuAssert(tc, "Extender client should be the TCP client", uri->pExtendClient == (KSI_NetworkClient *) uri->tcpClient);

		i++;
	}

	KSI_NetworkClient_free(net);
}

static void testInvalidExtenderUri(CuTest* tc) {
	int res;
	KSI_NetworkClient *net = NULL;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &net);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && net != NULL);

	uri = net->impl;

	while (invalidUri[i]) {
		char errm[1024];

		uri->pExtendClient = NULL;

		KSI_NetworkClient_free(uri->tcpClient);
		uri->tcpClient = NULL;

		res = KSI_UriClient_setExtender(net, invalidUri[i], "dummy", "dummy");
		KSI_snprintf(errm, sizeof(errm), "Invalid URI for extender should fail: '%s'", invalidUri[i]);
		CuAssert(tc, errm, res != KSI_OK);

		i++;
	}

	KSI_NetworkClient_free(net);
}

static void testInvalidAggregatorUri(CuTest* tc) {
	int res;
	KSI_NetworkClient *net = NULL;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &net);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && net != NULL);

	uri = net->impl;

	while (invalidUri[i]) {
		char errm[1024];

		uri->pExtendClient = NULL;

		KSI_NetworkClient_free(uri->tcpClient);
		uri->tcpClient = NULL;

		res = KSI_UriClient_setExtender(net, invalidUri[i], "dummy", "dummy");
		KSI_snprintf(errm, sizeof(errm), "Invalid URI for extender should fail: '%s'", invalidUri[i]);
		CuAssert(tc, errm, res != KSI_OK);

		i++;
	}

	KSI_NetworkClient_free(net);
}

static void assert_isHttpEndpointSetCorrectly(CuTest *tc, KSI_NetEndpoint *endp,
		const char *url, const char *user, const char *key){
	struct HttpClient_Endpoint_st *endp_impl = endp->implCtx;

	char *host = NULL;
	KSI_UriSplitBasic(url, NULL, &host, NULL, NULL);


	CuAssert(tc, "Http url mismatch.", host != NULL && strstr(endp_impl->url, host) != NULL);
	CuAssert(tc, "Http key mismatch.", strcmp(endp->ksi_pass, key) == 0);
	CuAssert(tc, "Http user mismatch.", strcmp(endp->ksi_user, user) == 0);
	KSI_free(host);
}

static void assert_isTcpEndpointSetCorrectly(CuTest *tc, KSI_NetEndpoint *endp,
		const char *host, int port, const char *user, const char *key){
	struct TcpClient_Endpoint_st *endp_impl = endp->implCtx;

	CuAssert(tc, "Tcp url mismatch.", strcmp(endp_impl->host, host) == 0);
	CuAssert(tc, "Tcp host mismatch.", endp_impl->port == port);
	CuAssert(tc, "Tcp key mismatch.", strcmp(endp->ksi_pass, key) == 0);
	CuAssert(tc, "Tcp user mismatch.", strcmp(endp->ksi_user, user) == 0);
}

static void assert_isHttpClientSetCorrectly(CuTest *tc, KSI_NetworkClient *uri_client,
		const char *a_url, const char *a_host, int a_port, const char *a_user, const char *a_key,
		const char *e_url, const char *e_host, int e_port, const char *e_user, const char *e_key){
	KSI_UriClient *uri = uri_client->impl;
	KSI_NetworkClient *http = uri->httpClient;
	KSI_NetEndpoint *endp_aggr = http->aggregator;
	KSI_NetEndpoint *endp_ext = http->extender;

	CuAssert(tc, "Http client is not set.", http != NULL);
	CuAssert(tc, "Http client is not set as aggregator and extender service.",
			(void*)http == (void*)(uri->pAggregationClient) &&
			(void*)http == (void*)(uri->pExtendClient));

	assert_isHttpEndpointSetCorrectly(tc, endp_aggr, a_url, a_user, a_key);
	assert_isHttpEndpointSetCorrectly(tc, endp_ext, e_url, e_user, e_key);
}

void assert_isTcpClientSetCorrectly(CuTest *tc, KSI_NetworkClient *uri_client,
		const char *a_url, const char *a_host, int a_port, const char *a_user, const char *a_key,
		const char *e_url, const char *e_host, int e_port, const char *e_user, const char *e_key){
	KSI_UriClient *uri = uri_client->impl;
	KSI_NetworkClient *tcp = uri->tcpClient;
	KSI_NetEndpoint *endp_aggr = tcp->aggregator;
	KSI_NetEndpoint *endp_ext = tcp->extender;

	CuAssert(tc, "Tcp client is not set (NULL).", tcp != NULL);
	CuAssert(tc, "Tcp client is not set as aggregator and extender service.",
			(void*)tcp == (void*)(uri->pAggregationClient) &&
			(void*)tcp == (void*)(uri->pExtendClient));

	assert_isTcpEndpointSetCorrectly(tc, endp_aggr, a_host, a_port, a_user, a_key);
	assert_isTcpEndpointSetCorrectly(tc, endp_ext, e_host, e_port, e_user, e_key);
}

static void testKsiUserAndPassFromUri(CuTest* tc) {
	int res;
	KSI_NetworkClient *uric = NULL;
	const char aggr_uri[] = "http://user_a:pass_a@ksigw.test.guardtime.com:1111/gt-signingservice";
	const char ext_uri[] = "http://user_x:pass_x@ksigw.test.guardtime.com:2222/gt-extendingservice";
	const char aggr_uri_tcp[] = "ksi+tcp://user_ta:pass_ta@ksigw.test.test.a.com:3333/gt-signingservice";
	const char ext_uri_tcp[] = "ksi+tcp://user_tx:pass_tx@ksigw.test.test.x.com:4444/gt-extendingservice";

	/* Http. Extract all data from uri. */
	res = KSI_UriClient_new(ctx, &uric);
	CuAssert(tc, "Unable to create new Http client.", res == KSI_OK && uric != NULL);

	res = KSI_UriClient_setAggregator(uric, aggr_uri, NULL, NULL);
	CuAssert(tc, "Unable parse aggregator uri.", res == KSI_OK);

	res = KSI_UriClient_setExtender(uric, ext_uri, NULL, NULL);
	CuAssert(tc, "Unable parse extender uri.", res == KSI_OK);

	assert_isHttpClientSetCorrectly(tc, uric, aggr_uri, NULL, 0, "user_a", "pass_a",
												ext_uri, NULL, 0, "user_x", "pass_x");

	/* Http. Extract all data from uri but override user and pass. */
	res = KSI_UriClient_setAggregator(uric, aggr_uri, "a1", "a2");
	CuAssert(tc, "Unable parse aggregator uri.", res == KSI_OK);

	res = KSI_UriClient_setExtender(uric, ext_uri, "x1", "x2");
	CuAssert(tc, "Unable parse extender uri.", res == KSI_OK);

	assert_isHttpClientSetCorrectly(tc, uric, aggr_uri, NULL, 0, "a1", "a2",
												ext_uri, NULL, 0, "x1", "x2");


	/* Http. Extract all data from uri but override user. */
	res = KSI_UriClient_setAggregator(uric, aggr_uri, "a1", NULL);
	CuAssert(tc, "Unable parse aggregator uri.", res == KSI_OK);

	res = KSI_UriClient_setExtender(uric, ext_uri, "x1", NULL);
	CuAssert(tc, "Unable parse extender uri.", res == KSI_OK);

	assert_isHttpClientSetCorrectly(tc, uric, aggr_uri, NULL, 0, "a1", "pass_a",
												ext_uri, NULL, 0, "x1", "pass_x");


	/* Http. Extract all data from uri but override pass. */
	res = KSI_UriClient_setAggregator(uric, aggr_uri, NULL, "a2");
	CuAssert(tc, "Unable parse aggregator uri.", res == KSI_OK);

	res = KSI_UriClient_setExtender(uric, ext_uri, NULL, "x2");
	CuAssert(tc, "Unable parse extender uri.", res == KSI_OK);

	assert_isHttpClientSetCorrectly(tc, uric, aggr_uri, NULL, 0, "user_a", "a2",
												ext_uri, NULL, 0, "user_x", "x2");

	/* Tcp. Extract all data from uri. */
	res = KSI_UriClient_setAggregator(uric, aggr_uri_tcp, NULL, NULL);
	CuAssert(tc, "Unable parse aggregator uri.", res == KSI_OK);

	res = KSI_UriClient_setExtender(uric, ext_uri_tcp, NULL, NULL);
	CuAssert(tc, "Unable parse extender uri.", res == KSI_OK);

	assert_isTcpClientSetCorrectly(tc, uric, NULL, "ksigw.test.test.a.com", 3333, "user_ta", "pass_ta",
											NULL, "ksigw.test.test.x.com", 4444, "user_tx", "pass_tx");


	/* Tcp. Extract all data from uri but override user and pass. */
	res = KSI_UriClient_setAggregator(uric, aggr_uri_tcp, "a1", "a2");
	CuAssert(tc, "Unable parse aggregator uri.", res == KSI_OK);

	res = KSI_UriClient_setExtender(uric, ext_uri_tcp, "x1", "x2");
	CuAssert(tc, "Unable parse extender uri.", res == KSI_OK);

	assert_isTcpClientSetCorrectly(tc, uric, NULL, "ksigw.test.test.a.com", 3333, "a1", "a2",
											NULL, "ksigw.test.test.x.com", 4444, "x1", "x2");


	/* Tcp. Extract all data from uri but override user. */
	res = KSI_UriClient_setAggregator(uric, aggr_uri_tcp, "a1", NULL);
	CuAssert(tc, "Unable parse aggregator uri.", res == KSI_OK);

	res = KSI_UriClient_setExtender(uric, ext_uri_tcp, "x1", NULL);
	CuAssert(tc, "Unable parse extender uri.", res == KSI_OK);

	assert_isTcpClientSetCorrectly(tc, uric, NULL, "ksigw.test.test.a.com", 3333, "a1", "pass_ta",
											NULL, "ksigw.test.test.x.com", 4444, "x1", "pass_tx");

	/* Tcp. Extract all data from uri but override pass. */
	res = KSI_UriClient_setAggregator(uric, aggr_uri_tcp, NULL, "a2");
	CuAssert(tc, "Unable parse aggregator uri.", res == KSI_OK);

	res = KSI_UriClient_setExtender(uric, ext_uri_tcp, NULL, "x2");
	CuAssert(tc, "Unable parse extender uri.", res == KSI_OK);

	assert_isTcpClientSetCorrectly(tc, uric, NULL, "ksigw.test.test.a.com", 3333, "user_ta", "a2",
											NULL, "ksigw.test.test.x.com", 4444, "user_tx", "x2");


	KSI_NetworkClient_free(uric);
}


CuSuite* KSITest_uriClient_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testUriClientInit);
	SUITE_ADD_TEST(suite, testValidAggregatorHttpUri);
	SUITE_ADD_TEST(suite, testValidExtenderHttpUri);
	SUITE_ADD_TEST(suite, testValidAggregatorTcpUri);
	SUITE_ADD_TEST(suite, testValidExtenderTcpUri);
	SUITE_ADD_TEST(suite, testInvalidExtenderUri);
	SUITE_ADD_TEST(suite, testInvalidAggregatorUri);
	SUITE_ADD_TEST(suite, testKsiUserAndPassFromUri);

	return suite;
}
