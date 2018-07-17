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
#include <stdlib.h>
#include <string.h>

#include "all_tests.h"

#include <ksi/tree_builder.h>
#include <ksi/hashchain.h>

extern KSI_CTX *ctx;

static void testCreateTreeBuilder(CuTest* tc) {
	int res;
	KSI_TreeBuilder *builder = NULL;

	res = KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);
	CuAssert(tc, "Unable to create tree builder.", res == KSI_OK && builder != NULL);

	KSI_TreeBuilder_free(builder);
}

static void testTreeBuilderAddLeafs(CuTest* tc) {
	int res;
	KSI_TreeBuilder *builder = NULL;
	char *data[] = { "test1", "test2", "test3", "test4", NULL, "test5", "test6", NULL};
	size_t i;
	KSI_DataHash *hsh = NULL;

	res = KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);
	CuAssert(tc, "Unable to create tree builder.", res == KSI_OK && builder != NULL);

	for (i = 0; data[i] != NULL; i++) {
		res = KSI_DataHash_create(ctx, data[i], strlen(data[i]), KSI_HASHALG_SHA2_256, &hsh);
		CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

		res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, NULL);
		CuAssert(tc, "Unable to add data hash to the tree builder", res == KSI_OK);

		KSI_DataHash_free(hsh);
		hsh = NULL;
	}

	res = KSI_TreeBuilder_close(builder);
	CuAssert(tc, "Unable to close a valid builder.", res == KSI_OK);

	KSI_TreeBuilder_free(builder);
}

static void testGetAggregationChain(CuTest* tc) {
	int res;
	KSI_TreeBuilder *builder = NULL;
	char *data[] = { "test1", "test2", "test3", "test4", "test5", "test6", "test7", "test8", "test9", "test10", NULL};
	KSI_TreeLeafHandle *handles[] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
	size_t i;
	KSI_DataHash *hsh = NULL;
	KSI_AggregationHashChain *chn = NULL;
	KSI_DataHash *root = NULL;
	KSI_DataHash *tmp = NULL;

	res = KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);
	CuAssert(tc, "Unable to create tree builder.", res == KSI_OK && builder != NULL);

	for (i = 0; data[i] != NULL; i++) {
		res = KSI_DataHash_create(ctx, data[i], strlen(data[i]), KSI_HASHALG_SHA1, &hsh);
		CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

		res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, &handles[i]);
		CuAssert(tc, "Unable to add data hash to the tree builder.", res == KSI_OK);

		KSI_DataHash_free(hsh);
		hsh = NULL;
	}

	/* Finalize the tree. */
	res = KSI_TreeBuilder_close(builder);
	CuAssert(tc, "Unable to close a valid builder.", res == KSI_OK);

	/* Calculate the root hash for every aggr chain. */
	for (i = 0; data[i] != NULL; i++) {
		res = KSI_TreeLeafHandle_getAggregationChain(handles[i], &chn);
		CuAssert(tc, "Unable to extract aggregation chain.", res == KSI_OK && chn != NULL);

		res = KSI_AggregationHashChain_aggregate(chn, 0, NULL, &tmp);
		CuAssert(tc, "Unable to aggregate the aggregation hash chain.", res == KSI_OK && tmp != NULL);

		if (root == NULL) {
			root = tmp;
		} else {
			KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Expected root hash", root);
			KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Actual root hash  ", tmp);
			CuAssert(tc, "Root hashes mismatch.", KSI_DataHash_equals(root, tmp));
			KSI_DataHash_free(tmp);
			tmp = NULL;
		}

		KSI_AggregationHashChain_free(chn);
		chn = NULL;

		KSI_TreeLeafHandle_free(handles[i]);
	}


	KSI_DataHash_free(root);
	KSI_TreeBuilder_free(builder);
}

static void testMaxTreeLevelt1(CuTest *tc) {
	int res;
	KSI_TreeBuilder *builder = NULL;
	KSI_DataHash *hsh = NULL;

	KSITest_DataHash_fromStr(ctx, "0168a0d7327ae5d25da38fbb903b73903e9db33cf52345a940a467134f3e81128e", &hsh);
	KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);

	builder->maxTreeLevel = 1;
	/* Should succeed. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, NULL);
	CuAssert(tc, "Unable to add data 1st hash.", res == KSI_OK);

	/* Should succeed. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, NULL);
	CuAssert(tc, "Unable to add data 2nd hash.", res == KSI_OK);

	/* Should fail. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, NULL);
	CuAssert(tc, "Adding 3rd hash should fail.", res != KSI_OK);

	KSI_TreeBuilder_free(builder);
	KSI_DataHash_free(hsh);
}

static void testMaxTreeLevelWithAbove0Level(CuTest *tc) {
	int res;
	KSI_TreeBuilder *builder = NULL;
	KSI_DataHash *hsh = NULL;

	KSITest_DataHash_fromStr(ctx, "0168a0d7327ae5d25da38fbb903b73903e9db33cf52345a940a467134f3e81128e", &hsh);
	KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);

	builder->maxTreeLevel = 2;
	/* Should succeed. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, NULL);
	CuAssert(tc, "Unable to add data 1st hash.", res == KSI_OK);

	/* Should succeed. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 1, NULL);
	CuAssert(tc, "Unable to add data 2nd hash.", res == KSI_OK);

	/* Should fail. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 2, NULL);
	CuAssert(tc, "Adding 3rd hash should not succeed.", res == KSI_BUFFER_OVERFLOW);

	res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, NULL);
	CuAssert(tc, "Adding 4th leaf should not fail.", res == KSI_OK);

	res = KSI_TreeBuilder_close(builder);
	CuAssert(tc, "Closing the builder should not fail", res == KSI_OK);

	CuAssert(tc, "The root hash node must have a lower level value than the max level.", (short)builder->rootNode->level <= builder->maxTreeLevel);

	KSI_TreeBuilder_free(builder);
	KSI_DataHash_free(hsh);
}

static void testMaxTreeLevelWithFullTree(CuTest *tc) {
	int res;
	KSI_TreeBuilder *builder = NULL;
	KSI_DataHash *hsh = NULL;
	int i;

	KSITest_DataHash_fromStr(ctx, "0168a0d7327ae5d25da38fbb903b73903e9db33cf52345a940a467134f3e81128e", &hsh);
	KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);

	builder->maxTreeLevel = 3;
	for (i = 0; i < 8; i++) {
		/* Should succeed. */
		res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, NULL);
		CuAssert(tc, "Unable to add data 1st hash.", res == KSI_OK);
	}

	/* Should fail. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, NULL);
	CuAssert(tc, "Adding yet another hash should not succeed.", res == KSI_BUFFER_OVERFLOW);

	/* Should fail. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 3, NULL);
	CuAssert(tc, "Adding yet another hash with max level should not succeed.", res == KSI_BUFFER_OVERFLOW);

	res = KSI_TreeBuilder_close(builder);
	CuAssert(tc, "Closing the builder should not fail", res == KSI_OK);

	CuAssert(tc, "The root hash node must have a lower level value than the max level.", (short)builder->rootNode->level <= builder->maxTreeLevel);

	KSI_TreeBuilder_free(builder);
	KSI_DataHash_free(hsh);
}

static void testMaxTreeLevelDoubleHighestLevel(CuTest *tc) {
	int res;
	KSI_TreeBuilder *builder = NULL;
	KSI_DataHash *hsh = NULL;

	KSITest_DataHash_fromStr(ctx, "0168a0d7327ae5d25da38fbb903b73903e9db33cf52345a940a467134f3e81128e", &hsh);
	KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);

	builder->maxTreeLevel = 3;

	/* Should not fail. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 3, NULL);
	CuAssert(tc, "Adding a hash with max level should succeed.", res == KSI_OK);

	/* Should fail. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 3, NULL);
	CuAssert(tc, "Adding yet another hash with max level should not succeed.", res == KSI_BUFFER_OVERFLOW);

	res = KSI_TreeBuilder_close(builder);
	CuAssert(tc, "Closing the builder should not fail", res == KSI_OK);

	CuAssert(tc, "The root hash node must have a lower level value than the max level.", (short)builder->rootNode->level <= builder->maxTreeLevel);

	KSI_TreeBuilder_free(builder);
	KSI_DataHash_free(hsh);
}

static void testEmptyTreeBuilderClosing(CuTest *tc) {
	int res;
	KSI_TreeBuilder *builder = NULL;
	char buf[1024];

	res = KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);
	CuAssert(tc, "Unable to create new tree builder.", res == KSI_OK);

	res = KSI_TreeBuilder_close(builder);
	CuAssert(tc, "Close on empty tree should not succeed.", res == KSI_INVALID_STATE);
	res = KSI_ERR_getBaseErrorMessage(ctx, buf, sizeof(buf), NULL, NULL);
	CuAssert(tc, "Unable to get error data.", res == KSI_OK && strcmp(buf, "The tree has no leafs.") == 0);

	KSI_TreeBuilder_free(builder);
}

static void testEmptyTreeBuilderWithMaxLevelClosing(CuTest *tc) {
	int res;
	KSI_TreeBuilder *builder = NULL;
	char buf[1024];

	res = KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);
	CuAssert(tc, "Unable to create new tree builder.", res == KSI_OK);

	res = KSI_TreeBuilder_close(builder);
	CuAssert(tc, "Close on empty tree should not succeed.", res == KSI_INVALID_STATE);
	res = KSI_ERR_getBaseErrorMessage(ctx, buf, sizeof(buf), NULL, NULL);
	CuAssert(tc, "Unable to get error data.", strcmp(buf, "The tree has no leafs.") == 0);

	KSI_TreeBuilder_free(builder);
}

static void testTreeBuilderDoubleClose(CuTest *tc) {
	int res;
	KSI_TreeBuilder *builder = NULL;
	KSI_DataHash *hsh = NULL;
	char buf[1024];

	KSITest_DataHash_fromStr(ctx, "0168a0d7327ae5d25da38fbb903b73903e9db33cf52345a940a467134f3e81128e", &hsh);

	res = KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);
	CuAssert(tc, "Unable to create new tree builder.", res == KSI_OK);

	/* Should succeed. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, NULL);
	CuAssert(tc, "Unable to add data 1st hash.", res == KSI_OK);

	res = KSI_TreeBuilder_close(builder);
	CuAssert(tc, "Unable to close tree builder.", res == KSI_OK);

	res = KSI_TreeBuilder_close(builder);
	CuAssert(tc, "Close on closed tree should not succeed.", res == KSI_INVALID_STATE);
	res = KSI_ERR_getBaseErrorMessage(ctx, buf, sizeof(buf), NULL, NULL);
	CuAssert(tc, "Unable to get error data.", strcmp(buf, "The tree has already been closed.") == 0);

	KSI_TreeBuilder_free(builder);
	KSI_DataHash_free(hsh);
}

static void testMaxTreeLevelWithLevel(CuTest *tc) {
	int res;
	KSI_TreeBuilder *builder = NULL;
	KSI_DataHash *hsh = NULL;

	KSITest_DataHash_fromStr(ctx, "0168a0d7327ae5d25da38fbb903b73903e9db33cf52345a940a467134f3e81128e", &hsh);
	KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);

	builder->maxTreeLevel = 3;
	/* Should succeed. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, NULL);
	CuAssert(tc, "Unable to add data 1st hash.", res == KSI_OK);

	/* Should succeed. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 1, NULL);
	CuAssert(tc, "Unable to add data 2nd hash.", res == KSI_OK);

	/* Should fail. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 3, NULL);
	CuAssert(tc, "Adding 3rd hash should not succeed.", res == KSI_BUFFER_OVERFLOW);

	/* Should fail. */
	res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, NULL);
	CuAssert(tc, "Adding 4th hash may not fail.", res == KSI_OK);

	KSI_TreeBuilder_free(builder);
	KSI_DataHash_free(hsh);
}


CuSuite* KSITest_TreeBuilder_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testCreateTreeBuilder);
	SUITE_ADD_TEST(suite, testTreeBuilderAddLeafs);
	SUITE_ADD_TEST(suite, testGetAggregationChain);
	SUITE_ADD_TEST(suite, testMaxTreeLevelt1);
	SUITE_ADD_TEST(suite, testMaxTreeLevelWithAbove0Level);
	SUITE_ADD_TEST(suite, testMaxTreeLevelWithFullTree);
	SUITE_ADD_TEST(suite, testMaxTreeLevelDoubleHighestLevel);
	SUITE_ADD_TEST(suite, testEmptyTreeBuilderClosing);
	SUITE_ADD_TEST(suite, testEmptyTreeBuilderWithMaxLevelClosing);
	SUITE_ADD_TEST(suite, testTreeBuilderDoubleClose);
	SUITE_ADD_TEST(suite, testMaxTreeLevelWithLevel);

	return suite;
}
