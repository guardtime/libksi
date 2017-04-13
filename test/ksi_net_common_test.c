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
#include <ksi/net.h>
#include <ksi/pkitruststore.h>
#include <ksi/hashchain.h>

#include "all_tests.h"
#include "../src/ksi/ctx_impl.h"
#include "../src/ksi/net_http_impl.h"
#include "../src/ksi/net_uri_impl.h"
#include "../src/ksi/net_tcp_impl.h"
#include "ksi/net_uri.h"
#include "ksi/tree_builder.h"
#include "../src/ksi/signature_impl.h"


extern KSI_CTX *ctx;

#define TEST_USER "anon"
#define TEST_PASS "anon"

static int mockHeaderCounter = 0;

static unsigned char mockImprint[] ={0x01,
									 0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47,
									 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
									 0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59,
									 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d};

static void preTest(void) {
	ctx->netProvider->requestCount = 0;
}

static int mockHeaderCallback(KSI_Header *hdr) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *msgId = NULL;
	KSI_Integer *instId = NULL;

	++mockHeaderCounter;

	if (hdr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_Header_getInstanceId(hdr, &instId);
	if (res != KSI_OK) goto cleanup;
	if (instId != NULL) {
		res = KSI_INVALID_ARGUMENT;
		KSI_LOG_error(ctx, "Header already contains a instance Id.");
		goto cleanup;
	}

	if (mockHeaderCounter != 1) {
		return KSI_OK;
	}

	res = KSI_Header_getMessageId(hdr, &msgId);
	if (res != KSI_OK) goto cleanup;
	if (msgId != NULL) {
		res = KSI_INVALID_ARGUMENT;
		KSI_LOG_error(ctx, "Header already contains a message Id.");
		goto cleanup;
	}

	res = KSI_Integer_new(KSI_Header_getCtx(hdr), 1337, &instId);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(KSI_Header_getCtx(hdr), 5, &msgId);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Header_setMessageId(hdr, msgId);
	if (res != KSI_OK) goto cleanup;
	msgId = NULL;

	res = KSI_Header_setInstanceId(hdr, instId);
	if (res != KSI_OK) goto cleanup;
	instId = NULL;

	res = KSI_OK;

cleanup:

	KSI_Integer_free(instId);
	KSI_Integer_free(msgId);

	return res;
}

static void testAggregationHeader(CuTest* tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	KSI_AggregationReq *req = NULL;
	KSI_AggregationPdu *pdu = NULL;
	KSI_RequestHandle *handle = NULL;
	KSI_Integer *tmp = NULL;
	KSI_Header *hdr = NULL;
	KSI_Integer *reqId = NULL;
	const unsigned char *raw = NULL;
	size_t raw_len = 0;

	KSI_ERR_clearErrors(ctx);

	mockHeaderCounter = 0;

	res = KSI_CTX_setRequestHeaderCallback(ctx, mockHeaderCallback);
	CuAssert(tc, "Unable to set header callback.", res == KSI_OK);

	res = KSI_CTX_setAggregator(ctx, "file://dummy", TEST_USER, TEST_PASS);

	res = KSI_DataHash_fromImprint(ctx, mockImprint, sizeof(mockImprint), &hsh);
	CuAssert(tc, "Unable to create data hash object from raw imprint", res == KSI_OK && hsh != NULL);

	res = KSI_AggregationReq_new(ctx, &req);
	CuAssert(tc, "Unable to create aggregation request.", res == KSI_OK && req != NULL);

	res = KSI_AggregationReq_setRequestHash(req, hsh);
	CuAssert(tc, "Unable to set request data hash.", res == KSI_OK);
	hsh = NULL;

	res = KSI_Integer_new(ctx, 17, &reqId);
	CuAssert(tc, "Unable to create reqId", res == KSI_OK && reqId != NULL);

	res = KSI_AggregationReq_setRequestId(req, reqId);
	CuAssert(tc, "Unable to set request id.", res == KSI_OK);
	reqId = NULL;

	res = KSI_sendSignRequest(ctx, req, &handle);
	CuAssert(tc, "Unable to send request.", res == KSI_OK && handle != NULL);

	KSI_AggregationReq_free(req);
	req = NULL;

	res = KSI_RequestHandle_getRequest(handle, &raw, &raw_len);
	CuAssert(tc, "Unable to get request.", res == KSI_OK && raw != NULL);

	res = KSI_AggregationPdu_parse(ctx, (unsigned char *)raw, raw_len, &pdu);
	CuAssert(tc, "Unable to parse the request pdu.", res == KSI_OK && pdu != NULL);

	res = KSI_AggregationPdu_getHeader(pdu, &hdr);
	CuAssert(tc, "Unable to get header from pdu.", res == KSI_OK && hdr != NULL);

	res = KSI_Header_getMessageId(hdr, &tmp);
	CuAssert(tc, "Unable to get message id from header.", res == KSI_OK && tmp != NULL);
	CuAssert(tc, "Wrong message id.", KSI_Integer_equalsUInt(tmp, 5));
	tmp = NULL;

	res = KSI_Header_getInstanceId(hdr, &tmp);
	CuAssert(tc, "Unable to get instance id from header.", res == KSI_OK && tmp != NULL);
	CuAssert(tc, "Wrong instance id.", KSI_Integer_equalsUInt(tmp, 1337));
	tmp = NULL;

	CuAssert(tc, "Mock header callback not called.", mockHeaderCounter == 1);

	res = KSI_CTX_setRequestHeaderCallback(ctx, NULL);
	CuAssert(tc, "Unable to set NULL as header callback.", res == KSI_OK);

	KSI_Integer_free(reqId);
	KSI_DataHash_free(hsh);
	KSI_AggregationPdu_free(pdu);
	KSI_RequestHandle_free(handle);
}

static void testExtendingHeader(CuTest* tc) {
	int res;
	KSI_ExtendReq *req = NULL;
	KSI_ExtendPdu *pdu = NULL;
	KSI_RequestHandle *handle = NULL;
	KSI_Integer *tmp = NULL;
	KSI_Header *hdr = NULL;
	KSI_Integer *reqId = NULL;
	KSI_Integer *start = NULL;
	const unsigned char *raw = NULL;
	size_t raw_len = 0;

	KSI_ERR_clearErrors(ctx);

	mockHeaderCounter = 0;

	res = KSI_CTX_setRequestHeaderCallback(ctx, mockHeaderCallback);
	CuAssert(tc, "Unable to set header callback.", res == KSI_OK);

	res = KSI_CTX_setExtender(ctx, "file://dummy", TEST_USER, TEST_PASS);

	res = KSI_ExtendReq_new(ctx, &req);
	CuAssert(tc, "Unable to create extending request.", res == KSI_OK && req != NULL);

	res = KSI_Integer_new(ctx, 1435740789, &start);
	CuAssert(tc, "Unable to create start time.", res == KSI_OK && start != NULL);

	/* Set the aggregation time. */
	res = KSI_ExtendReq_setAggregationTime(req, start);
	start = NULL;

	res = KSI_Integer_new(ctx, 17, &reqId);
	CuAssert(tc, "Unable to create reqId", res == KSI_OK && reqId != NULL);

	res = KSI_ExtendReq_setRequestId(req, reqId);
	CuAssert(tc, "Unable to set request id.", res == KSI_OK);
	reqId = NULL;

	res = KSI_sendExtendRequest(ctx, req, &handle);
	CuAssert(tc, "Unable to send request.", res == KSI_OK && handle != NULL);

	KSI_ExtendReq_free(req);
	req = NULL;

	res = KSI_RequestHandle_getRequest(handle, &raw, &raw_len);
	CuAssert(tc, "Unable to get request.", res == KSI_OK && raw != NULL);

	res = KSI_ExtendPdu_parse(ctx, (unsigned char *)raw, raw_len, &pdu);
	CuAssert(tc, "Unable to parse the request pdu.", res == KSI_OK && pdu != NULL);

	res = KSI_ExtendPdu_getHeader(pdu, &hdr);
	CuAssert(tc, "Unable to get header from pdu.", res == KSI_OK && hdr != NULL);

	res = KSI_Header_getMessageId(hdr, &tmp);
	CuAssert(tc, "Unable to get message id from header.", res == KSI_OK && tmp != NULL);
	CuAssert(tc, "Wrong message id.", KSI_Integer_equalsUInt(tmp, 5));
	tmp = NULL;

	res = KSI_Header_getInstanceId(hdr, &tmp);
	CuAssert(tc, "Unable to get instance id from header.", res == KSI_OK && tmp != NULL);
	CuAssert(tc, "Wrong instance id.", KSI_Integer_equalsUInt(tmp, 1337));
	tmp = NULL;

	CuAssert(tc, "Mock header callback not called.", mockHeaderCounter == 1);

	res = KSI_CTX_setRequestHeaderCallback(ctx, NULL);
	CuAssert(tc, "Unable to set NULL as header callback.", res == KSI_OK);

	KSI_Integer_free(reqId);
	KSI_Integer_free(start);
	KSI_ExtendPdu_free(pdu);
	KSI_RequestHandle_free(handle);
}

static void testUrlSplit(CuTest *tc) {
	struct {
		int res;
		const char *uri;
		const char *expSchema;
		const char *expHost;
		const char *expPath;
		const unsigned expPort;
	} testData[] = {
	{KSI_OK, "ksi://guardtime.com:12345", "ksi", "guardtime.com", NULL, 12345},
	{KSI_OK, "ksi+http://guardtime.com", "ksi+http", "guardtime.com", NULL, 0},
	{KSI_OK, "http:///toto", "http", NULL, "/toto", 0 },
	{KSI_OK, "file://test_file.doc", "file", "test_file.doc", NULL, 0 },
	{KSI_INVALID_FORMAT, "guardtime.com:80",  NULL, "guardtime.com", NULL, 0 },
	{KSI_INVALID_FORMAT, "guardtime.com", NULL, NULL, NULL, 0},
	{-1, NULL, NULL, NULL, NULL, 0 }
};
	int i;
	for (i = 0; testData[i].res >= 0; i++) {
		char *host = NULL;
		char *schema = NULL;
		char *path = NULL;
		unsigned port = 0;
		int res;

		KSI_LOG_debug(ctx, "%s\n", testData[i].uri);
		res = KSI_UriSplitBasic(testData[i].uri, &schema, &host, &port, &path);
		KSI_LOG_debug(ctx, "schema=%s, host=%s, port=%u, path=%s\n", schema, host, port, path);
		CuAssert(tc, "KSI_UriSplitBasic did not return expected status code.", res == testData[i].res);
		if (res == KSI_OK) {
			CuAssertStrEquals_Msg(tc, "KSI_UriSplitBasic did not return expected schema", testData[i].expSchema, schema);
			CuAssertStrEquals_Msg(tc, "KSI_UriSplitBasic did not return expected host", testData[i].expHost, host);
			CuAssertStrEquals_Msg(tc, "KSI_UriSplitBasic did not return expected path", testData[i].expPath, path);
			CuAssert(tc, "KSI_UriSplitBasic did not return expected port", testData[i].expPort == port);
		}
		KSI_free(schema);
		KSI_free(host);
		KSI_free(path);
	}

}

static 	const char *validUri[] = {
	"ksi://localhost",
	"ksi://localhost/",
	"ksi://localhost/a",
	"ksi://localhost/a.txt",
	"ksi://localhost/?key=value",
	"ksi://localhost?key=value",
	"ksi://localhost?key=value#fragment",
	"ksi://localhost/#fragment",
	"ksi+http://localhost",
	"ksi://localhost:12345",
	"ksi+http://localhost:1234/",
	"http://u:p@127.0.0.1:80",
	"http://u:p@127.0.0.1:80/",
	"http://u:p@127.0.0.1:80/test",
	"http://u:p@127.0.0.1:80/test/",
	"http://u:p@127.0.0.1:80/test/a",
	"http://u:p@127.0.0.1:80/test/b/",
	"http://u:p@127.0.0.1:80/test/c//",
	"http://u:p@127.0.0.1:80/test/c/test.file",
	"http://u:p@127.0.0.1:80/test/c?a=test&b=test&c=test",
	"http://u:p@127.0.0.1:80/test/c.txt?a=test&b=test&c=test",
	"http://u:p@127.0.0.1:80/test/c.txt?a=test&b=test&c=test#fragment1",
	"http://u:p@127.0.0.1:80/test/c.txt#fragment1",
	"file://file.name",
	"file://path/to/file",
	NULL
};

static void testUriSpiltAndCompose(CuTest* tc) {
	int res;
	KSI_NetworkClient *tmp = NULL;
	size_t i = 0;
	const char *uri = NULL;

	char error[0xffff];
	char new_uri[0xffff];
	char *scheme = NULL;
	char *user = NULL;
	char *pass = NULL;
	char *host = NULL;
	unsigned port = 0;
	char *path = NULL;
	char *query = NULL;
	char *fragment = NULL;

	res = KSI_AbstractNetworkClient_new(ctx, &tmp);
	CuAssert(tc, "Unable to create abstract network provider.", res == KSI_OK && tmp != NULL);


	while ((uri = validUri[i++]) != NULL) {
		scheme = NULL;
		user = NULL;
		pass = NULL;
		host = NULL;
		port = 0;
		path = NULL;
		query = NULL;
		fragment = NULL;
		error[0] = '\0';
		new_uri[0] = '\0';

		res = tmp->uriSplit(uri, &scheme, &user, &pass, &host, &port, &path, &query, &fragment);
		if (res != KSI_OK) {
			KSI_snprintf(error, sizeof(error), "Unable to split uri '%s'.", uri);
			CuAssert(tc, error, 0);
		}

		res = tmp->uriCompose(scheme, user, pass, host, port, path, query, fragment, new_uri, sizeof(new_uri));
		if (res != KSI_OK) {
			KSI_snprintf(error, sizeof(error), "Unable to compose uri '%s'.", uri);
			CuAssert(tc, error, 0);
		}

		if (strcmp(uri, new_uri) != 0) {
			KSI_snprintf(error, sizeof(error), "New uri is '%s', but expected '%s'.", new_uri, uri);
			CuAssert(tc, error, 0);
		}


		KSI_free(scheme);
		KSI_free(user);
		KSI_free(pass);
		KSI_free(path);
		KSI_free(host);
		KSI_free(query);
		KSI_free(fragment);
	}

	KSI_NetworkClient_free(tmp);
}

CuSuite* KSITest_NetCommon_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, testAggregationHeader);
	SUITE_ADD_TEST(suite, testExtendingHeader);
	SUITE_ADD_TEST(suite, testUrlSplit);
	SUITE_ADD_TEST(suite, testUriSpiltAndCompose);

	return suite;
}

