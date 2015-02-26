/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
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
	KSI_UriClient *uri = NULL;

	res = KSI_UriClient_new(ctx, &uri);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && uri != NULL);
	CuAssert(tc, "URI client not initialized properly.", uri->httpClient != NULL);
	CuAssert(tc, "TCP client should not be initialized by default.", uri->tcpClient == NULL);
	CuAssert(tc, "Default client for aggregation should be the HTTP client", uri->pAggregationClient == (KSI_NetworkClient *)uri->httpClient);
	CuAssert(tc, "Default client for extending should be the HTTP client", uri->pExtendClient == (KSI_NetworkClient *)uri->httpClient);

	KSI_UriClient_free(uri);
}

static void testValidAggregatorHttpUri(CuTest* tc) {
	int res;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &uri);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && uri != NULL);

	while (validHttpUri[i]) {
		char errm[1024];
		uri->pAggregationClient = NULL;

		res = KSI_UriClient_setAggregator(uri, validHttpUri[i], "dummy", "dummy");
		snprintf(errm, sizeof(errm), "Unable to set valid URI for aggregator address '%s'", validHttpUri[i]);
		CuAssert(tc, errm, res == KSI_OK);

		CuAssert(tc, "Aggregator client should be the HTTP client", uri->pAggregationClient == (KSI_NetworkClient *)uri->httpClient);

		i++;
	}

	KSI_UriClient_free(uri);
}

static void testValidExtenderHttpUri(CuTest* tc) {
	int res;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &uri);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && uri != NULL);

	while (validHttpUri[i]) {
		char errm[1024];

		uri->pExtendClient = NULL;

		res = KSI_UriClient_setExtender(uri, validHttpUri[i], "dummy", "dummy");
		snprintf(errm, sizeof(errm), "Unable to set valid URI for extender address '%s'", validHttpUri[i]);
		CuAssert(tc, errm, res == KSI_OK);

		CuAssert(tc, "Extender client should be the HTTP client", uri->pExtendClient == (KSI_NetworkClient *)uri->httpClient);

		i++;
	}

	KSI_UriClient_free(uri);
}

static void testValidAggregatorTcpUri(CuTest* tc) {
	int res;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &uri);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && uri != NULL);

	while (validTcpUri[i]) {
		char errm[1024];
		uri->pAggregationClient = NULL;

		KSI_TcpClient_free(uri->tcpClient);
		uri->tcpClient = NULL;

		res = KSI_UriClient_setAggregator(uri, validTcpUri[i], "dummy", "dummy");

		snprintf(errm, sizeof(errm), "Unable to set valid URI for aggregator address '%s'", validTcpUri[i]);
		CuAssert(tc, errm, res == KSI_OK);

		snprintf(errm, sizeof(errm), "TCP client should be initialized for address '%s'", validTcpUri[i]);
		CuAssert(tc, errm, uri->tcpClient != NULL);

		CuAssert(tc, "Aggregator client should be the TCP client", uri->pAggregationClient == (KSI_NetworkClient *)uri->tcpClient);

		i++;
	}

	KSI_UriClient_free(uri);
}

static void testValidExtenderTcpUri(CuTest* tc) {
	int res;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &uri);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && uri != NULL);

	while (validTcpUri[i]) {
		char errm[1024];

		uri->pExtendClient = NULL;

		KSI_TcpClient_free(uri->tcpClient);
		uri->tcpClient = NULL;

		res = KSI_UriClient_setExtender(uri, validTcpUri[i], "dummy", "dummy");
		snprintf(errm, sizeof(errm), "Unable to set valid URI for extender address '%s'", validTcpUri[i]);
		CuAssert(tc, errm, res == KSI_OK);

		snprintf(errm, sizeof(errm), "TCP client should be initialized for address '%s'", validTcpUri[i]);
		CuAssert(tc, errm, uri->tcpClient != NULL);

		CuAssert(tc, "Extender client should be the TCP client", uri->pExtendClient == (KSI_NetworkClient *)uri->tcpClient);

		i++;
	}

	KSI_UriClient_free(uri);
}

static void testInvalidExtenderUri(CuTest* tc) {
	int res;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &uri);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && uri != NULL);

	while (invalidUri[i]) {
		char errm[1024];

		uri->pExtendClient = NULL;

		KSI_TcpClient_free(uri->tcpClient);
		uri->tcpClient = NULL;

		res = KSI_UriClient_setExtender(uri, invalidUri[i], "dummy", "dummy");
		snprintf(errm, sizeof(errm), "Invalid URI for extender should fail: '%s'", invalidUri[i]);
		CuAssert(tc, errm, res != KSI_OK);

		i++;
	}

	KSI_UriClient_free(uri);
}

static void testInvalidAggregatorUri(CuTest* tc) {
	int res;
	KSI_UriClient *uri = NULL;
	int i = 0;

	res = KSI_UriClient_new(ctx, &uri);
	CuAssert(tc, "Unable to create URI client.", res == KSI_OK && uri != NULL);

	while (invalidUri[i]) {
		char errm[1024];

		uri->pExtendClient = NULL;

		KSI_TcpClient_free(uri->tcpClient);
		uri->tcpClient = NULL;

		res = KSI_UriClient_setExtender(uri, invalidUri[i], "dummy", "dummy");
		snprintf(errm, sizeof(errm), "Invalid URI for extender should fail: '%s'", invalidUri[i]);
		CuAssert(tc, errm, res != KSI_OK);

		i++;
	}

	KSI_UriClient_free(uri);
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
