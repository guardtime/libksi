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

CuSuite* KSITest_uriClient_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testUriClientInit);
	SUITE_ADD_TEST(suite, testValidAggregatorHttpUri);
	SUITE_ADD_TEST(suite, testValidExtenderHttpUri);
	SUITE_ADD_TEST(suite, testValidAggregatorTcpUri);
	SUITE_ADD_TEST(suite, testValidExtenderTcpUri);
	SUITE_ADD_TEST(suite, testInvalidExtenderUri);
	SUITE_ADD_TEST(suite, testInvalidAggregatorUri);

	return suite;
}
