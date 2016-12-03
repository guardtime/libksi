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
	size_t firstLevel = 0;

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
				KSI_LIST(KSI_HashChainLink) *linksp = NULL;
				res = KSI_AggregationHashChain_getChain(ptr, &linksp);

				CuAssert(tc, "Unable to extract the links of the first aggregation hash chain.", res == KSI_OK && linksp != NULL);

				firstLevel = KSI_HashChainLinkList_length(linksp);
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

CuSuite* KSITest_SignatureBuilder_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testEmpty);
	SUITE_ADD_TEST(suite, testNoClose);
	SUITE_ADD_TEST(suite, testCorrectWithPublication);
	SUITE_ADD_TEST(suite, testCorrectWithCalAuthRec);
	SUITE_ADD_TEST(suite, testCorrectRFC3161);
	SUITE_ADD_TEST(suite, testRecoverAfterEarlyClose);
	SUITE_ADD_TEST(suite, testPreAggregated);

	return suite;
}
