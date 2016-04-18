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
#include <string.h>
#include <ksi/tlv.h>
#include <ksi/hashchain.h>

#include "all_tests.h"

extern KSI_CTX *ctx;

static int KSI_HashChain_appendLink(KSI_DataHash *siblingHash, KSI_OctetString *legacyId, KSI_MetaData *metaData, int isLeft, int levelCorrection, KSI_LIST(KSI_HashChainLink) **chain) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HashChainLink *link = NULL;
	KSI_LIST(KSI_HashChainLink) *tmp = NULL;
	int mode = 0;
	KSI_Integer *lvlCorr = NULL;

	/* Create new link. */
	res = KSI_HashChainLink_new(ctx, &link);
	if (res != KSI_OK) goto cleanup;

	/* Is the siblin right of left. */
	res = KSI_HashChainLink_setIsLeft(link, isLeft);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(ctx, levelCorrection, &lvlCorr);
	if (res != KSI_OK) goto cleanup;

	/* Chain link level correction. */
	res = KSI_HashChainLink_setLevelCorrection(link, lvlCorr);
	if (res != KSI_OK) goto cleanup;
	lvlCorr = NULL;


	if (siblingHash != NULL) mode |= 0x01;
	if (legacyId != NULL) mode |= 0x02;
	if (metaData != NULL) mode |= 0x04;

	switch (mode) {
		case 0x01:
			res = KSI_HashChainLink_setImprint(link, siblingHash);
			if (res != KSI_OK) goto cleanup;
			break;
		case 0x02:
			res = KSI_HashChainLink_setLegacyId(link, legacyId);
			if (res != KSI_OK) goto cleanup;
			break;
		case 0x04:
			res = KSI_HashChainLink_setMetaData(link, metaData);
			if (res != KSI_OK) goto cleanup;
			break;
		default:
			res = KSI_UNKNOWN_ERROR;
			goto cleanup;
	}

	tmp = *chain;

	if (tmp == NULL) {
		res = KSI_HashChainLinkList_new(&tmp);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_HashChainLinkList_append(tmp, link);
	if (res != KSI_OK) goto cleanup;
	link = NULL;

	*chain = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Integer_free(lvlCorr);
	KSI_HashChainLinkList_free(tmp);
	KSI_HashChainLink_free(link);

	return res;
}


static void buildHashChain(CuTest *tc, const char *hexImprint, int isLeft, int levelCorrection, KSI_LIST(KSI_HashChainLink) **chn) {
	unsigned char buf[1024];
	size_t buf_len;
	int res;
	KSI_DataHash *hsh = NULL;

	if (*chn == NULL) {
		res = KSI_HashChainLinkList_new(chn);
		CuAssert(tc, "Unable to build hash chain.", res == KSI_OK && *chn != NULL);
	}

	res = KSITest_decodeHexStr(hexImprint, buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Unable to parse hex imprint", res == KSI_OK);

	res = KSI_DataHash_fromImprint(ctx, buf, buf_len, &hsh);
	CuAssert(tc, "Unable to create data hash", res == KSI_OK && hsh != NULL);

	res = KSI_HashChain_appendLink(hsh, NULL, NULL, isLeft, levelCorrection, chn);
	CuAssert(tc, "Unable to append hash chain link", res == KSI_OK && chn != NULL);

}

static void buildMetaDataHashChain(CuTest *tc, KSI_MetaData *metaData, int isLeft, int levelCorrection, KSI_LIST(KSI_HashChainLink) **chn) {
	int res;

	if (*chn == NULL) {
		res = KSI_HashChainLinkList_new(chn);
		CuAssert(tc, "Unable to build hash chain.", res == KSI_OK && *chn != NULL);
	}

	res = KSI_HashChain_appendLink(NULL, NULL, metaData, isLeft, levelCorrection, chn);
	CuAssert(tc, "Unable to append hash chain link", res == KSI_OK && chn != NULL);
}

static void testCalChainBuild(CuTest* tc) {
	KSI_LIST(KSI_HashChainLink) *chn = NULL;
	KSI_DataHash *in = NULL;
	KSI_DataHash *out = NULL;
	KSI_DataHash *exp = NULL;
	unsigned char buf[1024];
	size_t buf_len;
	int res;

	KSI_ERR_clearErrors(ctx);

	buildHashChain(tc, "012002c58133ff4b62425cba5eb566dc1719c162447426cae8e17dbc8375fb6e19", 0, 0, &chn);
	buildHashChain(tc, "0105f0f7825d98f4d7906bbae24d4355fd53f0706cf5bb97b83ee7621416684d67", 0, 0, &chn);
	buildHashChain(tc, "01ac9c6ff7b23cb36d8de52d9bdce843c11a2e6027bf545dc295a852c104068e01", 0, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "01f20c6082041dd7a2c25378180b5316498ae001c75171c0f007eefbeaab75d693", 0, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "01bc90b6d9576e0c71531a87902e7c75c9f87953b3259de73cfcc6e32f9bc8b278", 0, 0, &chn);
	buildHashChain(tc, "0108399c114fe431fd3473747db1ccda24cb029b3e074d92c4b18a36377fe2c42a", 0, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "011d0f23e0d8b55e0d976051d9d0731aba89e00afde190369f95bace6f14738391", 0, 0, &chn);
	buildHashChain(tc, "0137d9d2142ffd90fce6fa98d6facd691af7d517090ef81d842dc2b7c5f52a6f5a", 0, 0, &chn);
	buildHashChain(tc, "0178121429d107909e4b6e34b94546dfcb567fa114b76db6989e79fe656acb3151", 0, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "013a200e08600bb7a5ce5be6e9abb53a3f6092cb29c50ccb0b28db0c91c8e61321", 0, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "01cce512ef8331811171fb4b3b114955b8d26ab36bdfaa262c385b5f2db22cc043", 0, 0, &chn);
	buildHashChain(tc, "01fd93fe8f407f0ac9100a1dd0bbedbabd9e3fd3df39276c952211997bdce35290", 0, 0, &chn);
	buildHashChain(tc, "0178b8694789525fada3647ff135d932030401e0f3488ace7647c40e5771061d5a", 0, 0, &chn);
	buildHashChain(tc, "0127daa39b399071d1229dba6de8857f8bcf070e8ff649ee9065103eb7953f56b9", 0, 0, &chn);
	buildHashChain(tc, "01ad4caad8c098977a4340ffee4e1b124557aa47ac4e43bdd24cef22f45a00f96c", 0, 0, &chn);
	buildHashChain(tc, "011c102667ac4fbc8d91b99ef4a7c78bee2448ff52aa6cd1d557595f23510e98ea", 0, 0, &chn);
	buildHashChain(tc, "01fb79b43e0aa6bee9173839c051d3d0dac6f8efbd487331b5b86a214c42faa81c", 0, 0, &chn);
	buildHashChain(tc, "01496fc0120d854e7534b992ab32ec3045b20d4bee1bfbe4564fd092ceafa08b72", 0, 0, &chn);
	buildHashChain(tc, "01bb44fd36a5f3cdee7b5c6df3a6098a09e353335b6029f1477502588a7e37be00", 0, 0, &chn);


	res = KSITest_decodeHexStr("019e03cd3829beb2f9d4001f17070e25d9a4d3ef25adc39e8907ce3cdca7bebbb3", buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Unable to decode input hash", res == KSI_OK);

	res = KSI_DataHash_fromImprint(ctx, buf, buf_len, &in);
	CuAssert(tc, "Unable to create input data hash", res == KSI_OK && in != NULL);

	res = KSI_HashChain_aggregateCalendar(ctx, chn, in, &out);
	CuAssert(tc, "Unable to aggregate calendar chain", res == KSI_OK && out != NULL);

	/* Expected out hash. */
	res = KSITest_decodeHexStr("0166b4fb533791e50c5ca8f6415ab8de7cdde9f563449ad6f7252385b6e1dc29c1", buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Unable to decode expected output hash", res == KSI_OK);

	res = KSI_DataHash_fromImprint(ctx, buf, buf_len, &exp);
	CuAssert(tc, "Unable to create expected output data hash", res == KSI_OK && exp != NULL);

	KSI_DataHash_free(exp);
	KSI_DataHash_free(in);
	KSI_DataHash_free(out);
	KSI_HashChainLinkList_free(chn);
}

static void testAggrChainBuilt(CuTest *tc) {
	int res;
	unsigned char buf[1024];
	size_t buf_len;
	KSI_LIST(KSI_HashChainLink) *chn = NULL;
	KSI_DataHash *in = NULL;
	KSI_DataHash *out = NULL;
	KSI_DataHash *exp = NULL;

	buildHashChain(tc, "010101010101010101010101010101010101010101010101010101010101010101", 1, 0, &chn);
	buildHashChain(tc, "010101010101010101010101010101010101010101010101010101010101010101", 1, 13, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 2, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 0, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 7, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "0103ce8a99d60a808deb9872ec92846f5a56c816ad446824923f53c03691c88b8c", 1, 0, &chn);
	buildHashChain(tc, "011d6a55ab55eb586e6b4cf355825026deaa2b015c9dd271a6300f91044f2bcc78", 0, 7, &chn);
	buildHashChain(tc, "010abe6ec096b46a9015c6644d3fadd55d4124b49260d1d86fb77eb495e0c9b9fc", 1, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "018f59acda513c536ed30101d54bbb98c04ce8962b4144763a9c8dc7814f85ee15", 1, 0, &chn);
	buildHashChain(tc, "0165c015619a742dc61594f95e990b563a078d9fe7b92fecb04e20ccf262fa48e1", 1, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "019eaa47c788a21835616e504d2ed960afb9ec5e867643f50c223db15fff53d636", 1, 0, &chn);
	buildHashChain(tc, "015e13631c36caa14a5a3b74da179db614a7ed778ce634c4c8a132007f9756cc1f", 0, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 14, &chn);
	buildHashChain(tc, "01eaa8541261f66a1cc4c29119569df7293bd52c64dcfa73b47987683af0705b8d", 1, 46, &chn);
	buildHashChain(tc, "01adad105926792ab36994e394c5dc36be56fbb50b76534fcecfe6b08f4deadfea", 1, 0, &chn);

	res = KSITest_decodeHexStr("0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Unable to decode input hash", res == KSI_OK);

	res = KSI_DataHash_fromImprint(ctx, buf, buf_len, &in);
	CuAssert(tc, "Unable to create input data hash", res == KSI_OK && in != NULL);

	res = KSI_HashChain_aggregate(ctx, chn, in, 0, KSI_HASHALG_SHA2_256, NULL, &out);
	CuAssert(tc, "Unable to aggregate chain", res == KSI_OK && out != NULL);

	/* Expected out hash. */
	res = KSITest_decodeHexStr("01559c8ba6dfd2c048ad117a0dea339db9477513af2065fedd23a4da1c69120bc8", buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Unable to decode expected output hash", res == KSI_OK);

	res = KSI_DataHash_fromImprint(ctx, buf, buf_len, &exp);
	CuAssert(tc, "Unable to create expected output data hash", res == KSI_OK && exp != NULL);

	KSI_DataHash_free(exp);
	KSI_DataHash_free(in);
	KSI_DataHash_free(out);
	KSI_HashChainLinkList_free(chn);
}

static void testAggrChainBuiltWithMetaData(CuTest *tc) {
	int res;
	unsigned char buf[1024];
	size_t buf_len;

	KSI_LIST(KSI_HashChainLink) *chn = NULL;
	KSI_DataHash *in = NULL;
	KSI_DataHash *out = NULL;
	KSI_DataHash *exp = NULL;

	KSI_MetaData *tmp_metaData = NULL;
	KSI_Utf8String *clientId = NULL;
	KSI_TLV *metaDataTLV = NULL;
	KSI_MetaData *metaData = NULL;


	res = KSI_MetaData_new(ctx, &tmp_metaData);
	CuAssert(tc, "Unable to create meta data object.", res == KSI_OK);

	res = KSI_Utf8String_new(ctx, "test",5, &clientId);
	CuAssert(tc, "Unable create client ID string.", res == KSI_OK && clientId != NULL);

	res = KSI_MetaData_setClientId(tmp_metaData, clientId);
	CuAssert(tc, "Unable to set client ID", res == KSI_OK);
	clientId = NULL;

	res = KSI_MetaData_toTlv(ctx, tmp_metaData, 0x04, 0, 0, &metaDataTLV);
	CuAssert(tc, "Unable to TLV", res == KSI_OK);

	res = KSI_MetaData_fromTlv(metaDataTLV, &metaData);
	CuAssert(tc, "Unable to from TLV", res == KSI_OK);

/*
	metadata [01 05 74 65 73 74 00]

	[01] || H([0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d] || [019eaa47c788a21835616e504d2ed960afb9ec5e867643f50c223db15fff53d636] || [01])
	[01] || [50e7605eba534abb0f515f1f3b3359d6d909499ec102d4eafa30941c7c75109f]

	[01] || H([0150e7605eba534abb0f515f1f3b3359d6d909499ec102d4eafa30941c7c75109f] || [01 05 74 65 73 74 00] || [02])
	[01] || [9bfd782cbe11e1e6011196d21a9ea78a68121b972f9aecd2617d26598d5f6a95]

	[01] || H([019bfd782cbe11e1e6011196d21a9ea78a68121b972f9aecd2617d26598d5f6a95] || [010000000000000000000000000000000000000000000000000000000000000000] || [03])
	[01] || [a98e94a755ab276818ccefcf0b866043d12f80f9df09c087777511a48e533108]

	[01] || H([015e13631c36caa14a5a3b74da179db614a7ed778ce634c4c8a132007f9756cc1f] || [01a98e94a755ab276818ccefcf0b866043d12f80f9df09c087777511a48e533108] || [04])
	[01] || [85035b9a620d4c06ca24b9df2f9e74768a0dc8a543d9c418a4bbf41cfdbdb000]
 */

	/* Create the input hash. */
	res = KSITest_decodeHexStr("0111a700b0c8066c47ecba05ed37bc14dcadb238552d86c659342d1d7e87b8772d", buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Unable to decode input hash", res == KSI_OK);

	res = KSI_DataHash_fromImprint(ctx, buf, buf_len, &in);
	CuAssert(tc, "Unable to create input data hash", res == KSI_OK && in != NULL);

	/* Create the hash chain. */
	buildHashChain(tc, "019eaa47c788a21835616e504d2ed960afb9ec5e867643f50c223db15fff53d636", 1, 0, &chn);
	buildMetaDataHashChain(tc, metaData, 1, 0, &chn);
	buildHashChain(tc, "010000000000000000000000000000000000000000000000000000000000000000", 1, 0, &chn);
	buildHashChain(tc, "015e13631c36caa14a5a3b74da179db614a7ed778ce634c4c8a132007f9756cc1f", 0, 0, &chn);

	res = KSI_HashChain_aggregate(ctx, chn, in, 0, KSI_HASHALG_SHA2_256, NULL, &out);
	CuAssert(tc, "Unable to aggregate chain without meta data TLV.", res == KSI_OK && out != NULL);

	/* Expected out hash. */
	res = KSITest_decodeHexStr("0185035b9a620d4c06ca24b9df2f9e74768a0dc8a543d9c418a4bbf41cfdbdb000", buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Unable to decode expected output hash", res == KSI_OK);

	res = KSI_DataHash_fromImprint(ctx, buf, buf_len, &exp);
	CuAssert(tc, "Unable to create expected output data hash", res == KSI_OK && exp != NULL);
	CuAssert(tc, "Data hash mismatch", KSI_DataHash_equals(out, exp));

	KSI_MetaData_free(tmp_metaData);
	KSI_Utf8String_free(clientId);
	KSI_TLV_free(metaDataTLV);
	KSI_HashChainLinkList_free(chn);
	KSI_DataHash_free(in);
	KSI_DataHash_free(out);
	KSI_DataHash_free(exp);
}

static void testAggrChain_LegacyId_ParserFail(CuTest *tc, char *testSignatureFile) {
	int res = KSI_OK;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(testSignatureFile), &sig);
	CuAssert(tc, "Signature parsing should fail.", res == KSI_INVALID_FORMAT && sig == NULL);
}

static void testAggrChain_LegacyId_siblingContainsLegacyId_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-2014-04-30.1-legacyId-in-sibling.ksig"

	testAggrChain_LegacyId_ParserFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testAggrChain_LegacyId_invalidHeader_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-2014-04-30.1-legacyId-invalid-header.ksig"

	testAggrChain_LegacyId_ParserFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testAggrChain_LegacyId_invalidDataLenght_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-2014-04-30.1-legacyId-invalid-lenght.ksig"

	testAggrChain_LegacyId_ParserFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testAggrChain_LegacyId_invalidPadding_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-2014-04-30.1-legacyId-invalid-padding.ksig"

	testAggrChain_LegacyId_ParserFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

static void testAggrChain_LegacyId_invalidStringLenght_verifyErrorResult(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/nok-sig-2014-04-30.1-legacyId-invalid-string-lenght.ksig"

	testAggrChain_LegacyId_ParserFail(tc, TEST_SIGNATURE_FILE);

#undef TEST_SIGNATURE_FILE
}

CuSuite* KSITest_HashChain_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testCalChainBuild);
	SUITE_ADD_TEST(suite, testAggrChainBuilt);
	SUITE_ADD_TEST(suite, testAggrChainBuiltWithMetaData);
	SUITE_ADD_TEST(suite, testAggrChain_LegacyId_siblingContainsLegacyId_verifyErrorResult);
	SUITE_ADD_TEST(suite, testAggrChain_LegacyId_invalidHeader_verifyErrorResult);
	SUITE_ADD_TEST(suite, testAggrChain_LegacyId_invalidDataLenght_verifyErrorResult);
	SUITE_ADD_TEST(suite, testAggrChain_LegacyId_invalidPadding_verifyErrorResult);
	SUITE_ADD_TEST(suite, testAggrChain_LegacyId_invalidStringLenght_verifyErrorResult);

	return suite;
}
