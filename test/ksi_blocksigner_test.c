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

#include "../src/ksi/impl/ctx_impl.h"
#include "../src/ksi/impl/net_http_impl.h"

extern KSI_CTX *ctx;

#define TEST_USER "anon"
#define TEST_PASS "anon"

static const char *input_data[] = { "test1", "test2", "test3", "test4", "test5", "test6", "test7", NULL };


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

	*md = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_MetaData_free(tmp);
	KSI_Utf8String_free(cId);

	return res;
}

static void addInput(CuTest *tc, KSI_BlockSigner *bs, int genMeta) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	KSI_DataHash *hsh = NULL;
	KSI_MetaData *md = NULL;

	for (i = 0; input_data[i] != NULL; i++) {
		res = KSI_DataHash_create(ctx, input_data[i], strlen(input_data[i]), KSI_HASHALG_SHA2_256, &hsh);
		CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

		if (genMeta) {
			char clientId[100];
			KSI_snprintf(clientId, sizeof(clientId), "Client-%d", i);

			res = createMetaData(clientId, &md);
			CuAssert(tc, "Unable to create metadata.", res == KSI_OK && md != NULL);

			res = KSI_BlockSigner_addLeaf(bs, hsh, 0, md, NULL);
			CuAssert(tc, "Unable to add leaf with meta data.", res == KSI_OK);

			KSI_MetaData_free(md);
			md = NULL;
		} else {
			res = KSI_BlockSigner_add(bs, hsh);
			CuAssert(tc, "Unable to add data hash to the block signer.", res == KSI_OK);
		}
		KSI_DataHash_free(hsh);
		hsh = NULL;
	}
}

static void testFreeBeforeClose(CuTest *tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *bs = NULL;

	res = KSI_BlockSigner_new(ctx, KSI_HASHALG_SHA2_256, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	addInput(tc, bs, 0);

	KSI_BlockSigner_free(bs);
}

static void testMedaData(CuTest *tc) {
#define TEST_AGGR_RESPONSE_FILE  "resource/tlv/" TEST_RESOURCE_AGGR_VER "/test_meta_data_response.tlv"
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *bs = NULL;
	KSI_MetaData *md = NULL;
	char data[] = "LAPTOP";
	char *clientId[] = { "Alice", "Bob", "Claire", NULL };
	char *idPrefix[] = {"GT", "GT", "release test", "anon http", NULL};
	size_t i;
	KSI_DataHash *hsh = NULL;
	KSI_BlockSignerHandle *hndl[] = {NULL, NULL, NULL};
	KSI_Signature *sig = NULL;
	char *id = NULL;
	KSI_Utf8String *pIdStr = NULL;
	KSI_HashChainLinkIdentity *pId = NULL;
	KSI_LIST(KSI_HashChainLinkIdentity) *idList = NULL;

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

	res = KSI_BlockSigner_closeAndSign(bs);
	CuAssert(tc, "Unable to close the blocksigner.", res == KSI_OK);

	/* Loop over all the handles, and extract the signature. */
	for (i = 0; clientId[i] != NULL; i++) {
		size_t j = 0;

		/* Extract the signature. */
		res = KSI_BlockSignerHandle_getSignature(hndl[i], &sig);
		CuAssert(tc, "Unable to extract signature.", res == KSI_OK && sig != NULL);

		/* Verify the signature. */
		res = KSI_verifySignature(ctx, sig);
		CuAssert(tc, "Unable to verify the extracted signature.", res == KSI_OK);

		/* Extract the id attribution. */
		res = KSI_Signature_getAggregationHashChainIdentity(sig, &idList);
		CuAssert(tc, "Unable to get signer identity from signature.", res == KSI_OK && idList != NULL);

		while (idPrefix[j] != NULL) {
			pId = NULL;
			res = KSI_HashChainLinkIdentityList_elementAt(idList, j, &pId);
			CuAssert(tc, "Unable to get signer identity.", res == KSI_OK && pId != NULL);

			pIdStr = NULL;
			res = KSI_HashChainLinkIdentity_getClientId(pId, &pIdStr);
			CuAssert(tc, "Unable to get signer identity string.", res == KSI_OK && pIdStr != NULL);

			CuAssert(tc, "Unexpected signer identity.", !strncmp(idPrefix[j], KSI_Utf8String_cstr(pIdStr), strlen(idPrefix[j])));
			++j;
		}

		pId = NULL;
		res = KSI_HashChainLinkIdentityList_elementAt(idList, j++, &pId);
		CuAssert(tc, "Unable to get signer identity.", res == KSI_OK && pId != NULL);

		pIdStr = NULL;
		res = KSI_HashChainLinkIdentity_getClientId(pId, &pIdStr);
		CuAssert(tc, "Unable to get signer identity string.", res == KSI_OK && pIdStr != NULL);

		CuAssert(tc, "Unexpected signer identity.", !strncmp(clientId[i], KSI_Utf8String_cstr(pIdStr), strlen(clientId[i])));

		CuAssert(tc, "Signer identity length mismatch.", j == KSI_HashChainLinkIdentityList_length(idList));

		KSI_HashChainLinkIdentityList_free(idList);

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

static void testIdentityMedaData(CuTest *tc) {
#define TEST_AGGR_RESPONSE_FILE  "resource/tlv/" TEST_RESOURCE_AGGR_VER "/test_meta_data_response.tlv"
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *bs = NULL;
	KSI_MetaData *md = NULL;
	char data[] = "LAPTOP";
	const char *chainId[] = { "GT", "GT", "release test", "anon http" };
	char *userId[] = { "Alice", "Bob", "Claire", NULL };
	size_t i;
	KSI_DataHash *hsh = NULL;
	KSI_BlockSignerHandle *hndl[] = {NULL, NULL, NULL};
	KSI_Signature *sig = NULL;
	KSI_HashChainLinkIdentityList *identityList = NULL;

	res = KSI_DataHash_create(ctx, data, strlen(data), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

	res = KSI_BlockSigner_new(ctx, KSI_HASHALG_SHA2_256, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	for (i = 0; userId[i] != NULL; i++) {
		res = createMetaData(userId[i], &md);
		CuAssert(tc, "Unable to create meta-data.", res == KSI_OK && md != NULL);

		res = KSI_BlockSigner_addLeaf(bs, hsh, 0, md, &hndl[i]);
		CuAssert(tc, "Unable to add leaf to the block signer.", res == KSI_OK && hndl[i] != NULL);

		KSI_MetaData_free(md);
		md = NULL;

	}

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI.", res == KSI_OK);

	res = KSI_BlockSigner_closeAndSign(bs);
	CuAssert(tc, "Unable to close the blocksigner.", res == KSI_OK);

	/* Loop over all the handles, and extract the signature. */
	for (i = 0; userId[i] != NULL; i++) {
		size_t k;

		/* Extract the signature. */
		res = KSI_BlockSignerHandle_getSignature(hndl[i], &sig);
		CuAssert(tc, "Unable to extract signature.", res == KSI_OK && sig != NULL);

		/* Verify the signature. */
		res = KSI_verifySignature(ctx, sig);
		CuAssert(tc, "Unable to verify the extracted signature.", res == KSI_OK);

		res = KSI_Signature_getAggregationHashChainIdentity(sig, &identityList);
		CuAssert(tc, "Unable to get identity list from signature.", res == KSI_OK && identityList != NULL);

		for (k = 0; k < KSI_HashChainLinkIdentityList_length(identityList); k++) {
			KSI_HashChainLinkIdentity *identity = NULL;
			KSI_Utf8String *clientId = NULL;

			res = KSI_HashChainLinkIdentityList_elementAt(identityList, k, &identity);
			CuAssert(tc, "Unable to get identity from identity list.", res == KSI_OK && identity != NULL);

			res = KSI_HashChainLinkIdentity_getClientId(identity, &clientId);
			CuAssert(tc, "Unable to get client id from identity list.", res == KSI_OK && clientId != NULL);

			if (k < KSI_HashChainLinkIdentityList_length(identityList) - 1) {
				CuAssert(tc, "Unexpected client id.", !strncmp(chainId[k], KSI_Utf8String_cstr(clientId), strlen(chainId[k])));
			} else {
				CuAssert(tc, "Unexpected client id.", !strncmp(userId[i], KSI_Utf8String_cstr(clientId), strlen(userId[i])));
			}
		}

		/* Cleanup. */
		KSI_Signature_free(sig);
		sig = NULL;

		KSI_HashChainLinkIdentityList_free(identityList);
		identityList = NULL;

		KSI_BlockSignerHandle_free(hndl[i]);
	}

	KSI_DataHash_free(hsh);
	KSI_MetaData_free(md);
	KSI_BlockSigner_free(bs);
#undef TEST_AGGR_RESPONSE_FILE
}

static void testSingle(CuTest *tc) {
#define TEST_AGGR_RESPONSE_FILE  "resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response.tlv"
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

	res = KSI_BlockSigner_new(ctx, KSI_HASHALG_SHA2_256, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, &h);
	CuAssert(tc, "Unable to add hash to the blocksigner.", res == KSI_OK && h != NULL);

	res = KSI_BlockSigner_closeAndSign(bs);
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
#define TEST_AGGR_RESPONSE_FILE  "resource/tlv/" TEST_RESOURCE_AGGR_VER "/ok-sig-2014-07-01.1-aggr_response.tlv"
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

	res = KSI_BlockSigner_new(ctx, KSI_HASHALG_SHA2_256, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	/* Add the temporary leafs. */

	res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, NULL);
	CuAssert(tc, "Unable to add 1st mock hash to the blocksigner.", res == KSI_OK);

	res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, NULL);
	CuAssert(tc, "Unable to add 2nd hash to the blocksigner.", res == KSI_OK);

	res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, NULL);
	CuAssert(tc, "Unable to add 3rd hash to the blocksigner.", res == KSI_OK);

	res = KSI_BlockSigner_reset(bs);
	CuAssert(tc, "Unable to reset the block signer.", res == KSI_OK);

	res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, &h);
	CuAssert(tc, "Unable to add actual hash to the blocksigner.", res == KSI_OK && h != NULL);

	res = KSI_BlockSigner_closeAndSign(bs);
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

static void testCreateBlockSigner(CuTest *tc) {
	static const unsigned char diceRolls[] = {0xd5, 0x58, 0xaf, 0xfa, 0x80, 0x67, 0xf4, 0x2c, 0xd9, 0x48, 0x36, 0x21, 0xd1, 0xab,
			0xae, 0x23, 0xed, 0xd6, 0xca, 0x04, 0x72, 0x7e, 0xcf, 0xc7, 0xdb, 0xc7, 0x6b, 0xde, 0x34, 0x77, 0x1e, 0x53};
	int res;
	KSI_BlockSigner *bs = NULL;
	KSI_OctetString *iv = NULL;
	KSI_DataHash *zero = NULL;
	size_t i;

	struct {
		KSI_CTX *ctx;
		KSI_HashAlgorithm algo_id;
		KSI_DataHash *prevHash;
		KSI_OctetString *iv;
		KSI_BlockSigner **bs;
		int expectedRes;
	} tests[] = {
			{NULL, KSI_HASHALG_SHA3_512, NULL, NULL, NULL, KSI_INVALID_ARGUMENT},
			{NULL, KSI_HASHALG_SHA3_512, NULL, NULL, &bs, KSI_INVALID_ARGUMENT},
			{NULL, KSI_HASHALG_SHA3_512, NULL, iv, &bs, KSI_INVALID_ARGUMENT},
			{NULL, KSI_HASHALG_SHA3_512, zero, NULL, &bs, KSI_INVALID_ARGUMENT},
			{ctx, KSI_HASHALG_SHA3_512, NULL, NULL, &bs, KSI_UNAVAILABLE_HASH_ALGORITHM},
			{NULL, KSI_HASHALG_SHA2_512, NULL, NULL, NULL, KSI_INVALID_ARGUMENT},
			{NULL, KSI_HASHALG_SHA2_512, NULL, NULL, &bs, KSI_INVALID_ARGUMENT},
			{NULL, KSI_HASHALG_SHA2_512, NULL, iv, &bs, KSI_INVALID_ARGUMENT},
			{NULL, KSI_HASHALG_SHA2_512, zero, NULL, &bs, KSI_INVALID_ARGUMENT},
			{ctx, KSI_HASHALG_SHA2_512, zero, NULL, &bs, KSI_OK},
			{ctx, KSI_HASHALG_SHA1, zero, iv, &bs, KSI_UNTRUSTED_HASH_ALGORITHM},
			{ctx, KSI_HASHALG_SHA1, zero, NULL, &bs, KSI_UNTRUSTED_HASH_ALGORITHM},
			{NULL, -1, NULL, NULL, NULL, -1}
	};

	/* Create zero hash. */
	res = KSI_DataHash_createZero(ctx, KSI_HASHALG_SHA2_512, &zero);
	CuAssert(tc, "Unable to create zero hash.", res == KSI_OK && zero != NULL);

	/* Create random initial vector. */
	res = KSI_OctetString_new(ctx, diceRolls, sizeof(diceRolls), &iv);
	CuAssert(tc, "Unable to create initial vector.", res == KSI_OK && iv != NULL);

	for (i = 0; tests[i].expectedRes != -1; i++) {
		res = KSI_BlockSigner_new(tests[i].ctx, tests[i].algo_id, tests[i].prevHash, tests[i].iv, tests[i].bs);
		KSI_BlockSigner_free(bs);
		bs = NULL;
		if (res != tests[i].expectedRes) {
			char buf[1000];
			KSI_snprintf(buf, sizeof(buf), "Unexpected result @%i (expected = '%s', but was '%s').", i, KSI_getErrorString(tests[i].expectedRes), KSI_getErrorString(res));
			CuFail(tc, buf);
		}
	}

	KSI_OctetString_free(iv);
	KSI_DataHash_free(zero);
}

static void testAddDeprecatedLeaf(CuTest *tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_BlockSigner *bs = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_BlockSignerHandle *h = NULL;

	res = KSITest_DataHash_fromStr(ctx, "00a7d2c6238a92878b2a578c2477e8a33f9d8591ab", &hsh);
	CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

	res = KSI_BlockSigner_new(ctx, KSI_HASHALG_SHA2_256, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	res = KSI_BlockSigner_addLeaf(bs, hsh, 0, NULL, &h);
	CuAssert(tc, "Unable to add hash to the blocksigner.", res == KSI_UNTRUSTED_HASH_ALGORITHM && h == NULL);

	KSI_BlockSignerHandle_free(h);
	KSI_BlockSigner_free(bs);
	KSI_DataHash_free(hsh);
}


static void preTest(void) {
	ctx->netProvider->requestCount = 0;
}

CuSuite* KSITest_Blocksigner_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	suite->preTest = preTest;

	SUITE_ADD_TEST(suite, testFreeBeforeClose);
	SUITE_ADD_TEST(suite, testMedaData);
	SUITE_ADD_TEST(suite, testIdentityMedaData);
	SUITE_ADD_TEST(suite, testSingle);
	SUITE_ADD_TEST(suite, testReset);
	SUITE_ADD_TEST(suite, testCreateBlockSigner);
	SUITE_ADD_TEST(suite, testAddDeprecatedLeaf);

	return suite;
}
