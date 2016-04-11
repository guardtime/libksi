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

static void addInput(CuTest *tc, KSI_Blocksigner *bs) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	const char *dat[] = { "test1", "test2", "test3", "test4", "test5", "test6", "test7", NULL };
	KSI_DataHash *hsh = NULL;


	for (i = 0; dat[i] != NULL; i++) {
		res = KSI_DataHash_create(ctx, dat[i], strlen(dat[i]), KSI_HASHALG_SHA2_256, &hsh);
		CuAssert(tc, "Unable to create datahash.", res == KSI_OK && hsh != NULL);

		res = KSI_Blocksigner_add(bs, hsh);
		CuAssert(tc, "Unable to add datahash to the block signer.", res == KSI_OK);

		KSI_DataHash_free(hsh);
		hsh = NULL;
	}
}

static void testBasic(CuTest *tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Blocksigner *bs = NULL;

	res = KSI_Blocksigner_new(ctx, KSI_HASHALG_SHA1, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	addInput(tc, bs);

	KSI_Blocksigner_free(bs);
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
#define TEST_AGGR_RESPONSE_FILE "resource/tlv/ok-sig-2014-07-01.1-aggr_response.tlv"
	int res = KSI_UNKNOWN_ERROR;
	KSI_Blocksigner *bs = NULL;
	KSI_MetaData *md = NULL;
	char data[] = "LAPTOP";
	char *clientId[] = { "Alice", "Bob", "Claire", NULL };
	size_t i;
	KSI_DataHash *hsh = NULL;
	KSI_BlocksignerHandle *hndl[] = {NULL, NULL, NULL};

	res = KSI_DataHash_create(ctx, data, strlen(data), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

	res = KSI_Blocksigner_new(ctx, KSI_HASHALG_SHA1, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	for (i = 0; clientId[i] != NULL; i++) {
		res = createMetaData(clientId[i], &md);
		CuAssert(tc, "Unable to create meta-data.", res == KSI_OK && md != NULL);

		res = KSI_Blocksigner_addLeaf(bs, hsh, 0, md, &hndl[i]);
		CuAssert(tc, "Unable to add leaf to the block signer.", res == KSI_OK && hndl[i] != NULL);

		KSI_MetaData_free(md);
		md = NULL;

	}

	res = KSI_CTX_setAggregator(ctx, getFullResourcePathUri(TEST_AGGR_RESPONSE_FILE), TEST_USER, TEST_PASS);
	CuAssert(tc, "Unable to set aggregator file URI", res == KSI_OK);

	res = KSI_Blocksigner_close(bs, NULL);
	CuAssert(tc, "Unable to close the blocksigner.", res == KSI_OK);

	for (i = 0; clientId[i] != NULL; i++) {

		KSI_BlocksignerHandle_free(hndl[i]);
	}


	KSI_DataHash_free(hsh);
	KSI_MetaData_free(md);
	KSI_Blocksigner_free(bs);
}



static void dummy(CuTest *tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Blocksigner *bs = NULL;

	res = KSI_Blocksigner_new(ctx, KSI_HASHALG_SHA1, NULL, NULL, &bs);
	CuAssert(tc, "Unable to create block signer instance.", res == KSI_OK && bs != NULL);

	KSI_Blocksigner_free(bs);
}


CuSuite* KSITest_Blocksigner_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testBasic);
	SUITE_ADD_TEST(suite, testMedaData);

	return suite;
}
