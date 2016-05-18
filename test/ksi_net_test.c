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

#include "all_tests.h"
#include "../src/ksi/ctx_impl.h"
#include "../src/ksi/net_http_impl.h"
#include "../src/ksi/net_uri_impl.h"
#include "../src/ksi/net_tcp_impl.h"
#include "ksi/net_uri.h"
#include "ksi/tree_builder.h"

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

static void testSigning(CuTest* tc) {
#define TEST_AGGR_RESPONSE_FILE "resource/tlv/ok-sig-2014-07-01.1-aggr_response.tlv"
#define TEST_RES_SIGNATURE_FILE "resource/tlv/ok-sig-2014-07-01.1.ksig"

	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;
	unsigned char expected[0x1ffff];
	size_t expected_len = 0;
	FILE *f = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromImprint(ctx, mockImprint, sizeof(mockImprint), &hsh);
	CuAssert(tc, "Unable to create data hash object from raw imprint", res == KSI_OK && hsh != NULL);

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI", res == KSI_OK);

	res = KSI_createSignature(ctx, hsh, &sig);
	CuAssert(tc, "Unable to sign the hash", res == KSI_OK && sig != NULL);

	res = KSI_Signature_serialize(sig, &raw, &raw_len);
	CuAssert(tc, "Unable to serialize signature.", res == KSI_OK && raw != NULL && raw_len > 0);

	f = fopen(getFullResourcePath(TEST_RES_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to load sample signature.", f != NULL);

	expected_len = (unsigned)fread(expected, 1, sizeof(expected), f);
	CuAssert(tc, "Failed to read sample", expected_len > 0);

	CuAssert(tc, "Serialized signature length mismatch", expected_len == raw_len);
	CuAssert(tc, "Serialized signature content mismatch.", !memcmp(expected, raw, raw_len));

	if (f != NULL) fclose(f);
	KSI_free(raw);
	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);

#undef TEST_AGGR_RESPONSE_FILE
#undef TEST_RES_SIGNATURE_FILE
}

static void testSigningWrongResponse(CuTest* tc) {
#define TEST_AGGR_RESPONSE_FILE "resource/tlv/ok-sig-2014-07-01.1-aggr_response.tlv"
#define TEST_RES_SIGNATURE_FILE "resource/tlv/ok-sig-2014-07-01.1.ksig"

	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSITest_DataHash_fromStr(ctx, "010000000000000000000000000000000000000000000000000000000000000000", &hsh);
	CuAssert(tc, "Unable to create data hash", res == KSI_OK && hsh != NULL);

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI", res == KSI_OK);

	res = KSI_createSignature(ctx, hsh, &sig);
	CuAssert(tc, "Signing should not succeed.", res != KSI_OK && sig == NULL);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);

#undef TEST_AGGR_RESPONSE_FILE
#undef TEST_RES_SIGNATURE_FILE
}


static void testAggreAuthFailure(CuTest* tc) {
#define TEST_AGGR_RESPONSE_FILE "resource/tlv/aggr_error_pdu.tlv"

	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromImprint(ctx, mockImprint, sizeof(mockImprint), &hsh);
	CuAssert(tc, "Unable to create data hash object from raw imprint", res == KSI_OK && hsh != NULL);

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI", res == KSI_OK);

	res = KSI_createSignature(ctx, hsh, &sig);
	CuAssert(tc, "Aggregation should fail with service error.", res == KSI_SERVICE_AUTHENTICATION_FAILURE && sig == NULL);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);

#undef TEST_AGGR_RESPONSE_FILE
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

	res = KSI_Integer_new(ctx, 1337, &instId);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(ctx, 5, &msgId);
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


static void testExtending(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_RESPONSE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_RES_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	unsigned char *serialized = NULL;
	size_t serialized_len = 0;
	unsigned char expected[0x1ffff];
	size_t expected_len = 0;
	FILE *f = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extend response from file.", res == KSI_OK);

	res = KSI_extendSignature(ctx, sig, &ext);
	CuAssert(tc, "Unable to extend the signature", res == KSI_OK && ext != NULL);

	res = KSI_Signature_serialize(ext, &serialized, &serialized_len);
	CuAssert(tc, "Unable to serialize extended signature", res == KSI_OK && serialized != NULL && serialized_len > 0);

	/* Read in the expected result */
	f = fopen(getFullResourcePath(TEST_RES_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to read expected result file", f != NULL);
	expected_len = (unsigned)fread(expected, 1, sizeof(expected), f);
	fclose(f);

	CuAssert(tc, "Expected result length mismatch", expected_len == serialized_len);
	CuAssert(tc, "Unexpected extended signature.", !KSITest_memcmp(expected, serialized, expected_len));

	KSI_free(serialized);

	KSI_Signature_free(sig);
	KSI_Signature_free(ext);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_RES_SIGNATURE_FILE
}

static void testExtendTo(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_RESPONSE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_RES_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended_1400112000.ksig"

	int res;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	unsigned char *serialized = NULL;
	size_t serialized_len = 0;
	unsigned char expected[0x1ffff];
	size_t expected_len = 0;
	FILE *f = NULL;
	KSI_Integer *to = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extend response from file.", res == KSI_OK);

	KSI_Integer_new(ctx, 1400112000, &to);

	res = KSI_Signature_extendTo(sig, ctx, to, &ext);
	CuAssert(tc, "Unable to extend the signature", res == KSI_OK && ext != NULL);

	res = KSI_Signature_serialize(ext, &serialized, &serialized_len);
	CuAssert(tc, "Unable to serialize extended signature", res == KSI_OK && serialized != NULL && serialized_len > 0);

	/* Read in the expected result */
	f = fopen(getFullResourcePath(TEST_RES_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to read expected result file", f != NULL);
	expected_len = (unsigned)fread(expected, 1, sizeof(expected), f);
	fclose(f);

	CuAssert(tc, "Expected result length mismatch", expected_len == serialized_len);
	CuAssert(tc, "Unexpected extended signature.", !KSITest_memcmp(expected, serialized, expected_len));

	KSI_free(serialized);

	KSI_Integer_free(to);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_RES_SIGNATURE_FILE
}

static void testExtendSigNoCalChain(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1-no-cal-hashchain.ksig"
#define TEST_EXT_RESPONSE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_RES_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	unsigned char *serialized = NULL;
	size_t serialized_len = 0;
	unsigned char expected[0x1ffff];
	size_t expected_len = 0;
	FILE *f = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extend response from file.", res == KSI_OK);

	res = KSI_extendSignature(ctx, sig, &ext);
	CuAssert(tc, "Unable to extend the signature", res == KSI_OK && ext != NULL);

	res = KSI_Signature_serialize(ext, &serialized, &serialized_len);
	CuAssert(tc, "Unable to serialize extended signature", res == KSI_OK && serialized != NULL && serialized_len > 0);

	/* Read in the expected result */
	f = fopen(getFullResourcePath(TEST_RES_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to read expected result file", f != NULL);
	expected_len = (unsigned)fread(expected, 1, sizeof(expected), f);
	fclose(f);

	CuAssert(tc, "Expected result length mismatch", expected_len == serialized_len);

	KSI_free(serialized);

	KSI_Signature_free(sig);
	KSI_Signature_free(ext);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_RES_SIGNATURE_FILE
}

static void testExtenderWrongData(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_RESPONSE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"

	int res;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	KSI_Integer *to = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extend response from file.", res == KSI_OK);

	/* Create a random date that is different from the response. */
	KSI_Integer_new(ctx, 1400112222, &to);

	res = KSI_Signature_extendTo(sig, ctx, to, &ext);
	CuAssert(tc, "Wrong answer from extender should not be tolerated.", res != KSI_OK && ext == NULL);

	KSI_Integer_free(to);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testExtendInvalidSignature(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/nok-sig-wrong-aggre-time.tlv"
#define TEST_EXT_RESPONSE_FILE  "resource/tlv/nok-sig-wrong-aggre-time-extend_response.tlv"

	int res;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extend response from file.", res == KSI_OK);

	res = KSI_Signature_extendTo(sig, ctx, NULL, &ext);
	CuAssert(tc, "It should not be possible to extend this signature.", res != KSI_OK && ext == NULL);

	KSI_Signature_free(sig);
	KSI_Signature_free(ext);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
}

static void testExtAuthFailure(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_RESPONSE_FILE  "resource/tlv/ext_error_pdu.tlv"
#define TEST_CRT_FILE           "resource/tlv/mock.crt"

	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI Truststore", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CRT_FILE));
	CuAssert(tc, "Unable to add test certificate to truststore.", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extend response from file.", res == KSI_OK);

	res = KSI_extendSignature(ctx, sig, &ext);
	CuAssert(tc, "Extend should fail with service error.", res == KSI_SERVICE_AUTHENTICATION_FAILURE && ext == NULL);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_CRT_FILE
}

static void testExtendingWithoutPublication(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_RESPONSE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_RES_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-head.ksig"
#define TEST_CRT_FILE           "resource/tlv/mock.crt"

	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	unsigned char *serialized = NULL;
	size_t serialized_len = 0;
	unsigned char expected[0x1ffff];
	size_t expected_len = 0;
	FILE *f = NULL;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI Truststore", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CRT_FILE));
	CuAssert(tc, "Unable to add test certificate to truststore.", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extend response from file.", res == KSI_OK);

	res = KSI_Signature_extend(sig, ctx, NULL, &ext);
	CuAssert(tc, "Unable to extend the signature to the head", res == KSI_OK && ext != NULL);

	res = KSI_Signature_serialize(ext, &serialized, &serialized_len);
	CuAssert(tc, "Unable to serialize extended signature", res == KSI_OK && serialized != NULL && serialized_len > 0);
	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Signature extended to head", serialized, serialized_len);

	/* Read in the expected result */
	f = fopen(getFullResourcePath(TEST_RES_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to read expected result file", f != NULL);
	expected_len = (unsigned)fread(expected, 1, sizeof(expected), f);
	fclose(f);

	CuAssert(tc, "Expected result length mismatch", expected_len == serialized_len);
	CuAssert(tc, "Unexpected extended signature.", !memcmp(expected, serialized, expected_len));

	KSI_free(serialized);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_RES_SIGNATURE_FILE
#undef TEST_CRT_FILE
}

static void testExtendingToNULL(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_RESPONSE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_RES_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-head.ksig"
#define TEST_CRT_FILE           "resource/tlv/mock.crt"

	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	unsigned char *serialized = NULL;
	size_t serialized_len = 0;
	unsigned char expected[0x1ffff];
	size_t expected_len = 0;
	FILE *f = NULL;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI Truststore", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CRT_FILE));
	CuAssert(tc, "Unable to add test certificate to truststore.", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extend response from file.", res == KSI_OK);

	res = KSI_Signature_extendTo(sig, ctx, NULL, &ext);
	CuAssert(tc, "Unable to extend the signature to the head", res == KSI_OK && ext != NULL);

	res = KSI_Signature_serialize(ext, &serialized, &serialized_len);
	CuAssert(tc, "Unable to serialize extended signature", res == KSI_OK && serialized != NULL && serialized_len > 0);
	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Signature extended to head", serialized, serialized_len);

	/* Read in the expected result */
	f = fopen(getFullResourcePath(TEST_RES_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to read expected result file", f != NULL);
	expected_len = (unsigned)fread(expected, 1, sizeof(expected), f);
	fclose(f);

	CuAssert(tc, "Expected result length mismatch", expected_len == serialized_len);
	CuAssert(tc, "Unexpected extended signature.", !memcmp(expected, serialized, expected_len));

	KSI_free(serialized);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_RES_SIGNATURE_FILE
#undef TEST_CRT_FILE
}

static void testSigningInvalidResponse(CuTest* tc){
#define TEST_AGGR_RESPONSE_FILE "resource/tlv/nok_aggr_response_missing_header.tlv"

	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromImprint(ctx, mockImprint, sizeof(mockImprint), &hsh);
	CuAssert(tc, "Unable to create data hash object from raw imprint", res == KSI_OK && hsh != NULL);

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI", res == KSI_OK);

	res = KSI_createSignature(ctx, hsh, &sig);
	CuAssert(tc, "Signature should not be created with invalid aggregation response", res == KSI_INVALID_FORMAT && sig == NULL);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);

#undef TEST_AGGR_RESPONSE_FILE
}

static void testSigningInvalidAggrChainReturned(CuTest* tc){
#define TEST_AGGR_RESPONSE_FILE "resource/tlv/nok_aggr_response-invalid-aggr-chain.tlv"

	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	unsigned char imprint[] = {0x01, 0xc5, 0xf3, 0x30, 0x84, 0x32, 0x8a, 0x04, 0xa4, 0xee, 0x5c, 0x75, 0xa9, 0xeb, 0x8c, 0x9a, 0xe0, 0x0c, 0x22, 0x14, 0xdf, 0x70, 0x4c, 0x7c, 0xf6, 0x8b, 0xb3, 0x09, 0x5c, 0xec, 0xbc, 0x71, 0xca};


	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromImprint(ctx, imprint, sizeof(imprint), &hsh);
	CuAssert(tc, "Unable to create data hash object from raw imprint", res == KSI_OK && hsh != NULL);

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI", res == KSI_OK);

	res = KSI_createSignature(ctx, hsh, &sig);
	CuAssert(tc, "Signature should not be created with invalid aggregation response", res != KSI_OK);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);

#undef TEST_AGGR_RESPONSE_FILE
}

static void testSigningErrorResponse(CuTest *tc) {
#define TEST_AGGR_RESPONSE_FILE "resource/tlv/ok_aggr_err_response-1.tlv"

	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromImprint(ctx, mockImprint, sizeof(mockImprint), &hsh);
	CuAssert(tc, "Unable to create data hash object from raw imprint", res == KSI_OK && hsh != NULL);

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI", res == KSI_OK);

	res = KSI_createSignature(ctx, hsh, &sig);
	CuAssert(tc, "Signature should not be created due to server error.", res == KSI_SERVICE_INVALID_PAYLOAD && sig == NULL);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);

#undef TEST_AGGR_RESPONSE_FILE
}

static void testExtendingErrorResponse(CuTest *tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
#define TEST_EXT_RESPONSE_FILE  "resource/tlv/ok_extend_err_response-1.tlv"
#define TEST_CRT_FILE           "resource/tlv/mock.crt"

	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI Truststore", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath(TEST_CRT_FILE));
	CuAssert(tc, "Unable to add test certificate to truststore.", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extend response from file.", res == KSI_OK);

	res = KSI_Signature_extend(sig, ctx, NULL, &ext);
	CuAssert(tc, "Extend should fail with server error", res == KSI_SERVICE_INVALID_PAYLOAD && ext == NULL);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_CRT_FILE
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

static void testLocalAggregationSigning(CuTest* tc) {
#define TEST_AGGR_RESPONSE_FILE "resource/tlv/ok-local_aggr_lvl4_resp.tlv"

	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_DataHash_fromImprint(ctx, mockImprint, sizeof(mockImprint), &hsh);
	CuAssert(tc, "Unable to create data hash object from raw imprint", res == KSI_OK && hsh != NULL);

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI", res == KSI_OK);

	res = KSI_Signature_signAggregated(ctx, hsh, 4, &sig);
	CuAssert(tc, "Unable to sign the hash", res == KSI_OK && sig != NULL);

	res = KSI_verifySignature(ctx, sig);
	CuAssert(tc, "Signature should not be verifiable without local aggregation level.", res == KSI_VERIFICATION_FAILURE);

	res = KSI_Signature_verifyAggregated(sig, NULL, 4);
	CuAssert(tc, "Locally aggregated signature was not verifiable.", res == KSI_OK);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);

#undef TEST_AGGR_RESPONSE_FILE
}

static void testExtendExtended(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.2-extended.ksig"
#define TEST_EXT_RESPONSE_FILE  "resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv"
#define TEST_RES_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1-extended.ksig"

	int res;
	KSI_Signature *sig = NULL;
	KSI_Signature *ext = NULL;
	unsigned char *serialized = NULL;
	size_t serialized_len = 0;
	unsigned char expected[0x1ffff];
	size_t expected_len = 0;
	FILE *f = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_CTX_setExtender(ctx, getFullResourcePathUri(TEST_EXT_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set extend response from file.", res == KSI_OK);

	res = KSI_extendSignature(ctx, sig, &ext);
	CuAssert(tc, "Unable to extend the signature", res == KSI_OK && ext != NULL);

	res = KSI_Signature_serialize(ext, &serialized, &serialized_len);
	CuAssert(tc, "Unable to serialize extended signature", res == KSI_OK && serialized != NULL && serialized_len > 0);

	/* Read in the expected result */
	f = fopen(getFullResourcePath(TEST_RES_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to read expected result file", f != NULL);
	expected_len = (unsigned)fread(expected, 1, sizeof(expected), f);
	fclose(f);

	CuAssert(tc, "Expected result length mismatch", expected_len == serialized_len);
	CuAssert(tc, "Unexpected extended signature.", !KSITest_memcmp(expected, serialized, expected_len));

	KSI_free(serialized);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);

#undef TEST_SIGNATURE_FILE
#undef TEST_EXT_RESPONSE_FILE
#undef TEST_RES_SIGNATURE_FILE
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

static void testCreateAggregated(CuTest *tc) {
#define TEST_AGGR_RESPONSE_FILE "resource/tlv/ok-sig-2016-03-08-aggr_response.tlv"
	int res;
	const char data[] = "Test";
	const char clientStr[] = "Dummy";

	KSI_DataHash *docHash = NULL;
	KSI_MetaData *metaData = NULL;
	KSI_Utf8String *clientId = NULL;

	KSI_AggregationHashChain *chn = NULL;

	KSI_TreeBuilder *tb = NULL;
	KSI_TreeLeafHandle *leaf = NULL;

	unsigned char *raw = NULL;
	size_t raw_len = 0;

	KSI_Signature *sig = NULL;

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI", res == KSI_OK);

	/* Create the hash for the initial document. */
	res = KSI_DataHash_create(ctx, data, sizeof(data), KSI_HASHALG_SHA2_256, &docHash);
	CuAssert(tc, "Unable to create data hash", res == KSI_OK && docHash != NULL);

	/* Create client id object. */
	res = KSI_Utf8String_new(ctx, clientStr, sizeof(clientStr), &clientId);
	CuAssert(tc, "Unable to create client id", res == KSI_OK && clientId != NULL);

	/* Create the metadata object. */
	res = KSI_MetaData_new(ctx, &metaData);
	CuAssert(tc, "Unable to create metadata", res == KSI_OK && metaData != NULL);

	res = KSI_MetaData_setClientId(metaData, clientId);
	CuAssert(tc, "Unable to set meta data client id", res == KSI_OK);

	/* Create a tree builder. */
	res = KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &tb);
	CuAssert(tc, "Unable to create tree builder.", res == KSI_OK && tb != NULL);

	/* Add the document hash as the first leaf. */
	res = KSI_TreeBuilder_addDataHash(tb, docHash, 0, &leaf);
	CuAssert(tc, "Unable to add leaf to the tree builder.", res == KSI_OK && leaf != NULL);

	res = KSI_TreeBuilder_addMetaData(tb, metaData, 0, NULL);
	CuAssert(tc, "Unable to add meta data to the tree builder.", res == KSI_OK);

	/* Finalize the tree. */
	res = KSI_TreeBuilder_close(tb);
	CuAssert(tc, "Unable to close the tree.", res == KSI_OK);

	/* Extract the aggregation hash chain. */
	res = KSI_TreeLeafHandle_getAggregationChain(leaf, &chn);
	CuAssert(tc, "Unable to extract the aggregation hash chain.", res == KSI_OK && chn != NULL);

	res = KSI_Signature_signAggregationChain(ctx, 0, chn, &sig);
	CuAssert(tc, "Unable to sign aggregation chain.", res == KSI_OK && sig != NULL);


	/* Serialize the signature. */
	res = KSI_Signature_serialize(sig, &raw, &raw_len);
	CuAssert(tc, "Unable to serialize signature.", res == KSI_OK && raw != NULL && raw_len > 0);
	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Serialized:", raw, raw_len);

	KSI_Signature_free(sig);
	sig = NULL;

	/* Parse the signature. */
	res = KSI_Signature_parse(ctx, raw, raw_len, &sig);
	CuAssert(tc, "Unable to parse the serialized signature.", res == KSI_OK && sig != NULL);

	KSI_AggregationHashChain_free(chn);
	KSI_TreeBuilder_free(tb);
	KSI_TreeLeafHandle_free(leaf);
	KSI_DataHash_free(docHash);
	KSI_MetaData_free(metaData);
	KSI_Signature_free(sig);
	KSI_free(raw);

#undef TEST_AGGR_RESPONSE_FILE
}


CuSuite* KSITest_NET_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, testSigning);
	SUITE_ADD_TEST(suite, testSigningWrongResponse);
	SUITE_ADD_TEST(suite, testAggreAuthFailure);
	SUITE_ADD_TEST(suite, testExtending);
	SUITE_ADD_TEST(suite, testExtendTo);
	SUITE_ADD_TEST(suite, testExtendSigNoCalChain);
	SUITE_ADD_TEST(suite, testExtenderWrongData);
	SUITE_ADD_TEST(suite, testExtAuthFailure);
	SUITE_ADD_TEST(suite, testExtendingWithoutPublication);
	SUITE_ADD_TEST(suite, testExtendingToNULL);
	SUITE_ADD_TEST(suite, testSigningInvalidResponse);
	SUITE_ADD_TEST(suite, testSigningInvalidAggrChainReturned);
	SUITE_ADD_TEST(suite, testAggregationHeader);
	SUITE_ADD_TEST(suite, testSigningErrorResponse);
	SUITE_ADD_TEST(suite, testExtendingErrorResponse);
	SUITE_ADD_TEST(suite, testUrlSplit);
	SUITE_ADD_TEST(suite, testUriSpiltAndCompose);
	SUITE_ADD_TEST(suite, testLocalAggregationSigning);
	SUITE_ADD_TEST(suite, testExtendInvalidSignature);
	SUITE_ADD_TEST(suite, testCreateAggregated);
	SUITE_ADD_TEST(suite, testExtendExtended);

	return suite;
}

