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

#include  <ksi/tree_builder.h>

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
	char *data[] = { "test1", "test2", "test3", "test4", NULL};
	size_t i;
	KSI_DataHash *hsh = NULL;

	res = KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);
	CuAssert(tc, "Unable to create tree builder.", res == KSI_OK && builder != NULL);

	for (i = 0; data[i] != NULL; i++) {
		res = KSI_DataHash_create(ctx, data[i], strlen(data[i]), KSI_HASHALG_SHA2_256, &hsh);
		CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

		res = KSI_TreeBuilder_addLeaf(builder, hsh, i, NULL);
		if (res != KSI_OK) {
			KSI_ERR_statusDump(ctx, stderr);
			exit(1);
		}
		CuAssert(tc, "Unable to add data hash to the tree builder", res == KSI_OK);

		KSI_DataHash_free(hsh);
		hsh = NULL;
	}

	KSI_TreeBuilder_free(builder);
}


CuSuite* KSITest_TreeBuilder_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testCreateTreeBuilder);
	SUITE_ADD_TEST(suite, testTreeBuilderAddLeafs);

	return suite;
}
