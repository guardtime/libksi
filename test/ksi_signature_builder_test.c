/*
 * Copyright 2013-2016 Guardtime, Inc.
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
#include <stdlib.h>

#include "all_tests.h"
#include <ksi/ksi.h>
#include <ksi/signature_builder.h>
#include <ksi/hashchain.h>
#include "../src/ksi/signature_impl.h"
#include <ksi/tree_builder.h>

extern KSI_CTX *ctx;

static void testEmpty(CuTest* tc) {
	int res;
	KSI_SignatureBuilder *bldr = NULL;
	KSI_Signature *out = NULL;

	res = KSI_SignatureBuilder_open(ctx, &bldr);
	CuAssert(tc, "Failed to initialize builder.", res == KSI_OK && bldr != NULL);

	res = KSI_SignatureBuilder_close(bldr, 0, &out);
	CuAssert(tc, "Closing an empty signature builder should fail.", res != KSI_OK);
	CuAssert(tc, "Signature should still be NULL", out == NULL);

	KSI_SignatureBuilder_free(bldr);
}

static void testNoClose(CuTest* tc) {
	int res;
	KSI_SignatureBuilder *bldr = NULL;

	res = KSI_SignatureBuilder_open(ctx, &bldr);
	CuAssert(tc, "Failed to initialize builder.", res == KSI_OK && bldr != NULL);

	KSI_SignatureBuilder_free(bldr);
}

static void testCorrectWithPublication(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.2-extended.ksig"
	int res;
	KSI_Signature *sig = NULL;
	KSI_SignatureBuilder *bldr = NULL;
	KSI_Signature *out = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_SignatureBuilder_open(ctx, &bldr);
	CuAssert(tc, "Failed to initialize builder.", res == KSI_OK && bldr != NULL);

	/* Add the publication record to the builder. */
	res = KSI_SignatureBuilder_setPublication(bldr, sig->publication);
	CuAssert(tc, "Unable to add publication to the builder", res == KSI_OK);

	/* Add the calendar hash chain to the builder. */
	res = KSI_SignatureBuilder_setCalendarHashChain(bldr, sig->calendarChain);
	CuAssert(tc, "Unable to add calendar hash chain to the builder", res == KSI_OK);

	{
		size_t i;
		for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
			KSI_AggregationHashChain *ptr = NULL;

			res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &ptr);
			CuAssert(tc, "Unable to get aggregation chain from the sample signature.", res == KSI_OK && ptr != NULL);

			res = KSI_SignatureBuilder_addAggregationChain(bldr, ptr);
			CuAssert(tc, "Unable to add aggregation chain to the signature builder.", res == KSI_OK);
		}
	}

	res = KSI_SignatureBuilder_close(bldr, 0, &out);
	CuAssert(tc, "Unable to create valid signature from builder.", res == KSI_OK && out != NULL);

	KSI_SignatureBuilder_free(bldr);
	KSI_Signature_free(out);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testCorrectWithCalAuthRec(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
	int res;
	KSI_Signature *sig = NULL;
	KSI_SignatureBuilder *bldr = NULL;
	KSI_Signature *out = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_SignatureBuilder_open(ctx, &bldr);
	CuAssert(tc, "Failed to initialize builder.", res == KSI_OK && bldr != NULL);

	/* Add the calendar auth record to the builder. */
	res = KSI_SignatureBuilder_setCalendarAuthRecord(bldr, sig->calendarAuthRec);
	CuAssert(tc, "Unable to add calendar authentication record to the builder", res == KSI_OK);

	/* Add the calendar hash chain to the builder. */
	res = KSI_SignatureBuilder_setCalendarHashChain(bldr, sig->calendarChain);
	CuAssert(tc, "Unable to add calendar hash chain to the builder", res == KSI_OK);

	{
		size_t i;
		for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
			KSI_AggregationHashChain *ptr = NULL;

			res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &ptr);
			CuAssert(tc, "Unable to get aggregation chain from the sample signature.", res == KSI_OK && ptr != NULL);

			res = KSI_SignatureBuilder_addAggregationChain(bldr, ptr);
			CuAssert(tc, "Unable to add aggregation chain to the signature builder.", res == KSI_OK);
		}
	}

	res = KSI_SignatureBuilder_close(bldr, 0, &out);
	CuAssert(tc, "Unable to create valid signature from builder.", res == KSI_OK && out != NULL);

	KSI_SignatureBuilder_free(bldr);
	KSI_Signature_free(out);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testCorrectRFC3161(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-legacy-sig-2014-06.gtts.ksig"
	int res;
	KSI_Signature *sig = NULL;
	KSI_SignatureBuilder *bldr = NULL;
	KSI_Signature *out = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_SignatureBuilder_open(ctx, &bldr);
	CuAssert(tc, "Failed to initialize builder.", res == KSI_OK && bldr != NULL);

	/* Add the calendar auth record to the builder. */
	res = KSI_SignatureBuilder_setCalendarAuthRecord(bldr, sig->calendarAuthRec);
	CuAssert(tc, "Unable to add calendar authentication record to the builder", res == KSI_OK);

	/* Add the RFC3161 record. */
	res = KSI_SignatureBuilder_setRFC3161(bldr, sig->rfc3161);
	CuAssert(tc, "Unable to add RFC3161 record to the signature builder.", res == KSI_OK);

	/* Add the calendar hash chain to the signature builder. */
	res = KSI_SignatureBuilder_setCalendarHashChain(bldr, sig->calendarChain);
	CuAssert(tc, "Unable to add calendar hash chain to the builder", res == KSI_OK);

	{
		size_t i;
		for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
			KSI_AggregationHashChain *ptr = NULL;

			res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &ptr);
			CuAssert(tc, "Unable to get aggregation chain from the sample signature.", res == KSI_OK && ptr != NULL);

			res = KSI_SignatureBuilder_addAggregationChain(bldr, ptr);
			CuAssert(tc, "Unable to add aggregation chain to the signature builder.", res == KSI_OK);
		}
	}

	res = KSI_SignatureBuilder_close(bldr, 0, &out);
	CuAssert(tc, "Unable to create valid signature from builder.", res == KSI_OK && out != NULL);

	KSI_SignatureBuilder_free(bldr);
	KSI_Signature_free(out);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testRecoverAfterEarlyClose(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
	int res;
	KSI_Signature *sig = NULL;
	KSI_SignatureBuilder *bldr = NULL;
	KSI_Signature *out = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_SignatureBuilder_open(ctx, &bldr);
	CuAssert(tc, "Failed to initialize builder.", res == KSI_OK && bldr != NULL);

	/* Try closing the builder before we have added anything - should fail. */
	res = KSI_SignatureBuilder_close(bldr, 0, &out);
	CuAssert(tc, "Closing an empty signature builder should fail.", res != KSI_OK);
	CuAssert(tc, "Signature should still be NULL", out == NULL);

	/* Add the calendar authentication record to the builder. */
	res = KSI_SignatureBuilder_setCalendarAuthRecord(bldr, sig->calendarAuthRec);
	CuAssert(tc, "Unable to add calendar authentication record to the builder", res == KSI_OK);

	/* Try closing the builder before we add the calendar hash chain - should fail. */
	res = KSI_SignatureBuilder_close(bldr, 0, &out);
	CuAssert(tc, "Closing an empty signature builder should fail.", res != KSI_OK);
	CuAssert(tc, "Signature should still be NULL", out == NULL);

	/* Add the calendar hash chain to the builder. */
	res = KSI_SignatureBuilder_setCalendarHashChain(bldr, sig->calendarChain);
	CuAssert(tc, "Unable to add calendar hash chain to the builder", res == KSI_OK);

	{
		size_t i;
		for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
			KSI_AggregationHashChain *ptr = NULL;

			res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &ptr);
			CuAssert(tc, "Unable to get aggregation chain from the sample signature.", res == KSI_OK && ptr != NULL);

			/* Try closing the builder before we add the next aggregation chain. This is going to fail on every
			 * iteration. */
			res = KSI_SignatureBuilder_close(bldr, 0, &out);
			CuAssert(tc, "Closing an empty signature builder should fail.", res != KSI_OK);
			CuAssert(tc, "Signature should still be NULL", out == NULL);

			res = KSI_SignatureBuilder_addAggregationChain(bldr, ptr);
			CuAssert(tc, "Unable to add aggregation chain to the signature builder.", res == KSI_OK);
		}
	}

	/* At this point the builder must succeed. */
	res = KSI_SignatureBuilder_close(bldr, 0, &out);
	CuAssert(tc, "Unable to create valid signature from builder.", res == KSI_OK && out != NULL);

	KSI_SignatureBuilder_free(bldr);
	KSI_Signature_free(out);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testPreAggregated(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
	int res;
	KSI_Signature *sig = NULL;
	KSI_SignatureBuilder *bldr = NULL;
	KSI_Signature *out = NULL;
	int firstLevel = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_SignatureBuilder_open(ctx, &bldr);
	CuAssert(tc, "Failed to initialize builder.", res == KSI_OK && bldr != NULL);

	/* Add the calendar authentication record to the builder. */
	res = KSI_SignatureBuilder_setCalendarAuthRecord(bldr, sig->calendarAuthRec);
	CuAssert(tc, "Unable to add calendar authentication record to the builder", res == KSI_OK);

	/* Add the calendar hash chain to the builder. */
	res = KSI_SignatureBuilder_setCalendarHashChain(bldr, sig->calendarChain);
	CuAssert(tc, "Unable to add calendar hash chain to the builder", res == KSI_OK);

	{
		size_t i;
		for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
			KSI_AggregationHashChain *ptr = NULL;

			res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &ptr);
			CuAssert(tc, "Unable to get aggregation chain from the sample signature.", res == KSI_OK && ptr != NULL);

			if (i == 0) {
				res = KSI_AggregationHashChain_aggregate(ptr, 0, &firstLevel, NULL);
				CuAssert(tc, "Unable to aggregate first aggregation hash chain.", res == KSI_OK && firstLevel != 0);
			} else {
				res = KSI_SignatureBuilder_addAggregationChain(bldr, ptr);
				CuAssert(tc, "Unable to add aggregation chain to the signature builder.", res == KSI_OK);
			}
		}
	}

	res = KSI_SignatureBuilder_close(bldr, 0, &out);
	CuAssert(tc, "Signature should not be created with input level 0.", res != KSI_OK && out == NULL);

	res = KSI_SignatureBuilder_close(bldr, firstLevel, &out);
	CuAssert(tc, "Unable to create valid signature.", res == KSI_OK && out != NULL);

	KSI_SignatureBuilder_free(bldr);
	KSI_Signature_free(out);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testOpenWithSignature(CuTest* tc) {
#define TEST_SIGNATURE_FILE     "resource/tlv/ok-sig-2014-04-30.1.ksig"
	int res;
	KSI_Signature *sig = NULL;
	KSI_SignatureBuilder *bldr = NULL;
	KSI_Signature *out = NULL;
	unsigned char *rawSig = NULL;
	size_t rawSig_len = 0;
	unsigned char *rawOut = NULL;
	size_t rawOut_len = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_SignatureBuilder_openFromSignature(sig, &bldr);
	CuAssert(tc, "Failed to initialize builder.", res == KSI_OK && bldr != NULL);

	res = KSI_SignatureBuilder_close(bldr, 0, &out);
	CuAssert(tc, "Unable to create valid signature from builder.", res == KSI_OK && out != NULL);

	CuAssert(tc, "Output signature should be a new copy of input signature.", sig != out);

	res = KSI_Signature_serialize(sig, &rawSig, &rawSig_len);
	CuAssert(tc, "Unable to serialize signature.", res == KSI_OK && rawSig != NULL && rawSig_len > 0);

	res = KSI_Signature_serialize(sig, &rawOut, &rawOut_len);
	CuAssert(tc, "Unable to serialize signature.", res == KSI_OK && rawOut != NULL && rawOut_len > 0);

	CuAssert(tc, "Serialized signature length mismatch", rawSig_len == rawOut_len);
	CuAssert(tc, "Serialized signature content mismatch.", !memcmp(rawSig, rawOut, rawSig_len));

	KSI_SignatureBuilder_free(bldr);
	KSI_Signature_free(out);
	KSI_Signature_free(sig);
	KSI_free(rawSig);
	KSI_free(rawOut);

#undef TEST_SIGNATURE_FILE
}

static void testAppendChain(CuTest* tc) {
#define TEST_SIGNATURE_FILE	"resource/tlv/ok-sig_local-aggr.ksig"

	int res;
	KSI_TreeBuilder *builder = NULL;
	char *data[] = { "test1", "test2", "test3", "test4", "test5", "test6", "test7", "test8", "test9", "test10", NULL};
	KSI_TreeLeafHandle *handles[] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
	size_t i;
	KSI_Signature *rootSig = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_AggregationHashChain *chn = NULL;
	KSI_DataHash *rootHsh = NULL;
	unsigned char *rawRoot = NULL;
	size_t rawRoot_len = 0;

	res = KSI_TreeBuilder_new(ctx, KSI_HASHALG_SHA2_256, &builder);
	CuAssert(tc, "Unable to create tree builder.", res == KSI_OK && builder != NULL);

	for (i = 0; data[i] != NULL; i++) {
		res = KSI_DataHash_create(ctx, data[i], strlen(data[i]), KSI_HASHALG_SHA1, &hsh);
		CuAssert(tc, "Unable to create data hash.", res == KSI_OK && hsh != NULL);

		res = KSI_TreeBuilder_addDataHash(builder, hsh, 0, &handles[i]);
		CuAssert(tc, "Unable to add data hash to the tree builder", res == KSI_OK);

		KSI_DataHash_free(hsh);
		hsh = NULL;
	}

	/* Finalize the tree. */
	res = KSI_TreeBuilder_close(builder);
	CuAssert(tc, "Unable to close a valid builder.", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &rootSig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && rootSig != NULL);

	res = KSI_Signature_getDocumentHash(rootSig, &rootHsh);
	CuAssert(tc, "Unable to get signature input hash.", res == KSI_OK && rootHsh != NULL);

	res = KSI_Signature_serialize(rootSig, &rawRoot, &rawRoot_len);
	CuAssert(tc, "Unable to serialize signature.", res == KSI_OK && rawRoot != NULL && rawRoot_len > 0);

	/* Calculate the root hash for every aggr chain. */
	for (i = 0; data[i] != NULL; i++) {
		KSI_Signature *leafSig = NULL;
		unsigned char *rawLeaf = NULL;
		size_t rawLeaf_len = 0;
		int rootLevel = 0;
		KSI_DataHash *aggrHsh = NULL;
		KSI_SignatureBuilder *bldr = NULL;

		res = KSI_TreeLeafHandle_getAggregationChain(handles[i], &chn);
		CuAssert(tc, "Unable to extract aggregation chain,", res == KSI_OK && chn != NULL);

		res = KSI_AggregationHashChain_aggregate(chn, 0, &rootLevel, &aggrHsh);
		CuAssert(tc, "Unable to aggregate the aggregation hash chain.", res == KSI_OK && aggrHsh != NULL);

		CuAssert(tc, "Root hashes mismatch.", KSI_DataHash_equals(rootHsh, aggrHsh));

		res = KSI_SignatureBuilder_openFromSignature(rootSig, &bldr);
		CuAssert(tc, "Failed to initialize builder.", res == KSI_OK && bldr != NULL);

		res = KSI_SignatureBuilder_appendAggregationChain(bldr, chn);
		CuAssert(tc, "Failed to append aggregation hash chain.", res == KSI_OK);

		res = KSI_SignatureBuilder_close(bldr, 0, &leafSig);
		CuAssert(tc, "Unable to create valid signature from builder.", res == KSI_OK && leafSig != NULL);

		res = KSI_Signature_serialize(leafSig, &rawLeaf, &rawLeaf_len);
		CuAssert(tc, "Unable to serialize signature.", res == KSI_OK && rawLeaf != NULL && rawLeaf_len > 0);

		CuAssert(tc, "Leaf signature size should exceed the size of root signature.", rawRoot_len < rawLeaf_len);

		KSI_SignatureBuilder_free(bldr);
		KSI_DataHash_free(aggrHsh);
		KSI_AggregationHashChain_free(chn);
		KSI_TreeLeafHandle_free(handles[i]);
		KSI_Signature_free(leafSig);
		KSI_free(rawLeaf);
	}

	KSI_TreeBuilder_free(builder);
	KSI_Signature_free(rootSig);
	KSI_free(rawRoot);

#undef TEST_SIGNATURE_FILE
}

CuSuite* KSITest_SignatureBuilder_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testEmpty);
	SUITE_ADD_TEST(suite, testNoClose);
	SUITE_ADD_TEST(suite, testCorrectWithPublication);
	SUITE_ADD_TEST(suite, testCorrectWithCalAuthRec);
	SUITE_ADD_TEST(suite, testCorrectRFC3161);
	SUITE_ADD_TEST(suite, testRecoverAfterEarlyClose);
	SUITE_ADD_TEST(suite, testPreAggregated);
	SUITE_ADD_TEST(suite, testOpenWithSignature);
	SUITE_ADD_TEST(suite, testAppendChain);

	return suite;
}
