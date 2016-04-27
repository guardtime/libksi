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
#include <ksi/ksi.h>
#include <ksi/blocksigner.h>

#include "cutest/CuTest.h"
#include "all_tests.h"

extern KSI_CTX *ctx;

#define TEST_USER "anon"
#define TEST_PASS "anon"

static const char *input_data[] = { "test1", "test2", "test3", "test4", "test5", "test6", "test7", NULL };

static void addInput(CuTest *tc, KSI_BlockSigner *bs) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	KSI_DataHash *hsh = NULL;


	for (i = 0; input_data[i] != NULL; i++) {
		res = KSI_DataHash_create(ctx, input_data[i], strlen(input_data[i]), KSI_HASHALG_SHA2_256, &hsh);
		CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

		res = KSI_BlockSigner_add(bs, hsh);
		CuAssert(tc, "Unable to add data hash to the block signer.", res == KSI_OK);

		KSI_DataHash_free(hsh);
		hsh = NULL;
	}
}

static void testFreeBeforeClose(CuTest *tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *bs = NULL;

	res = KSI_BlockSigner_new(ctx, KSI_HASHALG_SHA1, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	addInput(tc, bs);

	KSI_BlockSigner_free(bs);
}

static void testMultiSig(CuTest *tc) {
#define TEST_AGGR_RESPONSE_FILE  "resource/tlv/ok-aggr-resp-1460631424.tlv"
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *bs = NULL;
	KSI_MultiSignature *ms = NULL;
	size_t i;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;

	res = KSI_BlockSigner_new(ctx, KSI_HASHALG_SHA1, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	addInput(tc, bs);

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI.", res == KSI_OK);

	res = KSI_BlockSigner_close(bs, &ms);
	CuAssert(tc, "Unable to close block signer and extract multi signature.", res == KSI_OK && ms != NULL);

	res = KSITest_setDefaultPubfileAndVerInfo(ctx);
	CuAssert(tc, "Unable to set default pubfile, default cert and default pki constraints.", res == KSI_OK);

	/* Lets loop over all the inputs and try to verify them. */
	for (i = 0; input_data[i] != NULL; i++) {
		res = KSI_DataHash_create(ctx, input_data[i], strlen(input_data[i]), KSI_HASHALG_SHA2_256, &hsh);
		CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

		res = KSI_MultiSignature_get(ms, hsh, &sig);
		CuAssert(tc, "Unable to extract signature from the multi signature container.", res == KSI_OK && sig != NULL);

		res = KSI_Signature_verifyDocument(sig, ctx, (void *)input_data[i], strlen(input_data[i]));
		CuAssert(tc, "Unable to verify the input data.", res == KSI_OK);

		KSI_Signature_free(sig);
		sig = NULL;

		KSI_DataHash_free(hsh);
		hsh = NULL;
	}

	KSI_DataHash_free(hsh);
	KSI_MultiSignature_free(ms);
	KSI_BlockSigner_free(bs);
#undef TEST_AGGR_RESPONSE_FILE
}


static int createMetaData(const char *userId, KSI_MetaData **md) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MetaData *tmp = NULL;
	KSI_Utf8String *cId = NULL;

	res = KSI_MetaData_new(ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Utf8String_new(ctx, userId, strlen(userId) + 1, &cId);
	if (res != KSI_OK) goto cleanup;

	res = KSI_MetaData_setClientId(tmp, cId);
	if (res != KSI_OK) goto cleanup;
	cId = NULL;

	*md = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_MetaData_free(tmp);
	KSI_Utf8String_free(cId);

	return res;
}

static void testMedaData(CuTest *tc) {
#define TEST_AGGR_RESPONSE_FILE  "resource/tlv/ok-sig-2016-04-13-preaggr_response.tlv"
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *bs = NULL;
	KSI_MetaData *md = NULL;
	char data[] = "LAPTOP";
	char *clientId[] = { "Alice", "Bob", "Claire", NULL };
	size_t i;
	KSI_DataHash *hsh = NULL;
	KSI_BlockSignerHandle *hndl[] = {NULL, NULL, NULL};
	KSI_Signature *sig = NULL;
	char *id = NULL;

	res = KSI_DataHash_create(ctx, data, strlen(data), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

	res = KSI_BlockSigner_new(ctx, KSI_HASHALG_SHA2_256, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	for (i = 0; clientId[i] != NULL; i++) {
		res = createMetaData(clientId[i], &md);
		CuAssert(tc, "Unable to create meta-data.", res == KSI_OK && md != NULL);

		res = KSI_BlockSigner_addLeaf(bs, hsh, 0, md, &hndl[i]);
		CuAssert(tc, "Unable to add leaf to the block signer.", res == KSI_OK && hndl[i] != NULL);

		KSI_MetaData_free(md);
		md = NULL;

	}

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI.", res == KSI_OK);

	res = KSI_BlockSigner_close(bs, NULL);
	CuAssert(tc, "Unable to close the blocksigner.", res == KSI_OK);

	res = KSITest_setDefaultPubfileAndVerInfo(ctx);
	CuAssert(tc, "Unable to set default pubfile, default cert and default pki constraints.", res == KSI_OK);

	/* Loop over all the handles, and extract the signature. */
	for (i = 0; clientId[i] != NULL; i++) {
		char expId[0xff];

		/* Extract the signature. */
		res = KSI_BlockSignerHandle_getSignature(hndl[i], &sig);
		CuAssert(tc, "Unable to extract signature.", res == KSI_OK && sig != NULL);

		/* Verify the signature. */
		res = KSI_verifySignature(ctx, sig);
		CuAssert(tc, "Unable to verify the extracted signature.", res == KSI_OK);

		/* Extract the id attribution. */
		res = KSI_Signature_getSignerIdentity(sig, &id);
		CuAssert(tc, "Unable to extract the signer identity.", res == KSI_OK && id != NULL);

		/* Create the expected id value. */
		KSI_snprintf(expId, sizeof(expId), "%s :: %s", "GT :: GT :: release test :: anon http", clientId[i]);
		CuAssert(tc, "Client id not what expected.", !strcmp(id, expId));

		/* Cleanup. */
		KSI_Signature_free(sig);
		sig = NULL;

		KSI_free(id);
		id = NULL;

		KSI_BlockSignerHandle_free(hndl[i]);
	}


	KSI_DataHash_free(hsh);
	KSI_MetaData_free(md);
	KSI_BlockSigner_free(bs);
#undef TEST_AGGR_RESPONSE_FILE
}

static void testSingle(CuTest *tc) {
#define TEST_AGGR_RESPONSE_FILE  "resource/tlv/ok-sig-2014-07-01.1-aggr_response.tlv"
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *bs = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_BlockSignerHandle *h = NULL;
	KSI_Signature *sig = NULL;
	unsigned char *raw = NULL;
	size_t len = 0;

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI.", res == KSI_OK);

	res = KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

	res = KSI_BlockSigner_new(ctx, KSI_HASHALG_SHA1, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, &h);
	CuAssert(tc, "Unable to add hash to the blocksigner.", res == KSI_OK && h != NULL);

	res = KSI_BlockSigner_close(bs, NULL);
	CuAssert(tc, "Unable to close blocksigner.", res == KSI_OK);

	res = KSI_BlockSignerHandle_getSignature(h, &sig);
	CuAssert(tc, "Unable to extract signature from the blocksigner.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_serialize(sig, &raw, &len);
	CuAssert(tc, "Unable to serialize signature.", res == KSI_OK && raw != NULL && len > 0);

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Serialized single signature from block signer.", raw, len);

	KSI_BlockSignerHandle_free(h);
	KSI_Signature_free(sig);
	KSI_BlockSigner_free(bs);
	KSI_DataHash_free(hsh);
	KSI_free(raw);
#undef TEST_AGGR_RESPONSE_FILE
}

static void testReset(CuTest *tc) {
#define TEST_AGGR_RESPONSE_FILE  "resource/tlv/ok-sig-2014-07-01.1-aggr_response.tlv"
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *bs = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_BlockSignerHandle *h = NULL;
	KSI_Signature *sig = NULL;
	unsigned char *raw = NULL;
	size_t len = 0;

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI.", res == KSI_OK);

	res = KSITest_DataHash_fromStr(ctx, "0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", &hsh);
	CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

	res = KSI_BlockSigner_new(ctx, KSI_HASHALG_SHA1, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	/* Add the temporary leafs. */

	res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, NULL);
	CuAssert(tc, "Unable to add 1st mock hash to the blocksigner.", res == KSI_OK);

	res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, NULL);
	CuAssert(tc, "Unable to add 2nd hash to the blocksigner.", res == KSI_OK);

	res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, NULL);
	CuAssert(tc, "Unable to add 3rd hash to the blocksigner.", res == KSI_OK);

	res = KSI_BlockSigner_reset(bs);
	CuAssert(tc, "Unable to reset the block signer", res == KSI_OK);

	res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, &h);
	CuAssert(tc, "Unable to add actual hash to the blocksigner.", res == KSI_OK && h != NULL);

	res = KSI_BlockSigner_close(bs, NULL);
	CuAssert(tc, "Unable to close blocksigner.", res == KSI_OK);

	res = KSI_BlockSignerHandle_getSignature(h, &sig);
	CuAssert(tc, "Unable to extract signature from the blocksigner.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_serialize(sig, &raw, &len);
	CuAssert(tc, "Unable to serialize signature.", res == KSI_OK && raw != NULL && len > 0);

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Serialized single signature from block signer.", raw, len);

	KSI_BlockSignerHandle_free(h);
	KSI_Signature_free(sig);
	KSI_BlockSigner_free(bs);
	KSI_DataHash_free(hsh);
	KSI_free(raw);
#undef TEST_AGGR_RESPONSE_FILE
}

CuSuite* KSITest_Blocksigner_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testFreeBeforeClose);
	SUITE_ADD_TEST(suite, testMultiSig);
	SUITE_ADD_TEST(suite, testMedaData);
	SUITE_ADD_TEST(suite, testSingle);
	SUITE_ADD_TEST(suite, testReset);

	return suite;
}
