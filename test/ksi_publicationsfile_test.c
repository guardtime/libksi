/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#include <string.h>
#include <ksi/publicationsfile.h>
#include <ksi/pkitruststore.h>
#include "all_tests.h"

extern KSI_CTX *ctx;
extern unsigned char *KSI_NET_MOCK_response;
extern unsigned KSI_NET_MOCK_response_len;

#define TEST_PUBLICATIONS_FILE "resource/tlv/publications.tlv"

static void setFileMockResponse(CuTest *tc, const char *fileName) {
	FILE *f = NULL;

	/* Read response from file. */
	f = fopen(fileName, "rb");
	CuAssert(tc, "Unable to open sample response file", f != NULL);

	KSI_NET_MOCK_response_len = (unsigned)fread(KSI_NET_MOCK_response, 1, MOCK_BUFFER_SIZE, f);
	fclose(f);
}

static void testLoadPublicationsFile(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;

	KSI_ERR_clearErrors(ctx);

	setFileMockResponse(tc, getFullResourcePath(TEST_PUBLICATIONS_FILE));

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	KSI_PublicationsFile_free(pubFile);
}

static void testVerifyPublicationsFile(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	setFileMockResponse(tc, getFullResourcePath(TEST_PUBLICATIONS_FILE));

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_PKITruststore_new(ctx, 0, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_CTX_setPKITruststore(ctx, pki);
	CuAssert(tc, "Unable to set new pki truststrore for ksi context.", res == KSI_OK);

	/* Verification should fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file shouldn't verify without mock certificate.", res != KSI_OK);

	/* Verification should succeed. */

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath("resource/tlv/mock.crt"));
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	res = KSI_PublicationsFile_verify(pubFile, ctx);
//	KSI_ERR_statusDump(ctx, stdout);
//	exit(1);

	CuAssert(tc, "Publications file should verify with mock certificate.", res == KSI_OK);

	KSI_PublicationsFile_free(pubFile);
}


static void testPublicationStringEncodingAndDecoding(CuTest *tc) {
	static const char publication[] = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";
	char *out = NULL;
	int res;
	KSI_PublicationData *pub = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_PublicationData_fromBase32(ctx, publication, &pub);
	CuAssert(tc, "Failed decoding publication string.", res == KSI_OK && pub != NULL);

	res = KSI_PublicationData_toBase32(pub, &out);

	CuAssert(tc, "Failed encoding the published data object", res == KSI_OK && out != NULL);

	CuAssert(tc, "Invalid encoded publication string does not match original.", !strncmp(publication, out, strlen(publication)));

	KSI_PublicationData_free(pub);
	KSI_free(out);
}

static void testFindPublicationByPubStr(CuTest *tc) {
	static const char publication[] = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_PublicationData *pub = NULL;
	KSI_DataHash *pubHsh = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *expHsh = NULL;
	unsigned char buf[0xff];
	unsigned len;

	KSI_ERR_clearErrors(ctx);

	res = KSI_receivePublicationsFile(ctx, &pubFile);
	CuAssert(tc, "Unable to get publications file.", res == KSI_OK && pubFile != NULL);

	res = KSI_PublicationsFile_getPublicationDataByPublicationString(pubFile, publication, &pubRec);
	CuAssert(tc, "Unable to get publication record by publication string.", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pub);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pub != NULL);

	res = KSI_PublicationData_getImprint(pub, &pubHsh);
	CuAssert(tc, "Unable to get published hash", res == KSI_OK && pubHsh != NULL);

	res = KSI_PublicationData_getTime(pub, &pubTime);
	CuAssert(tc, "Unable to get publication time.", res == KSI_OK && pubTime != NULL);

	KSITest_decodeHexStr("01a1b5238ffb05fccfa67546266a0b2d7130f6656026033b6b578c12e4fbbe231a", buf, sizeof(buf), &len);
	res = KSI_DataHash_fromImprint(ctx, buf, len, &expHsh);
	CuAssert(tc, "Unable to get data hash from imprint.", res == KSI_OK && expHsh != NULL);

	CuAssert(tc, "Publication hash mismatch.", KSI_DataHash_equals(expHsh, pubHsh));
	CuAssert(tc, "Publication time mismatch", KSI_Integer_equalsUInt(pubTime, 1397520000));

	KSI_DataHash_free(expHsh);

}

static void testFindPublicationByTime(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_PublicationData *pub = NULL;
	KSI_DataHash *pubHsh = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_DataHash *expHsh = NULL;
	KSI_LIST(KSI_Utf8String) *pubRefList = NULL;
	unsigned char buf[0xff];
	unsigned len;

	KSI_ERR_clearErrors(ctx);

	res = KSI_receivePublicationsFile(ctx, &pubFile);
	CuAssert(tc, "Unable to get publications file.", res == KSI_OK && pubFile != NULL);

	res = KSI_Integer_new(ctx, 1397520000, &pubTime);
	CuAssert(tc, "Unable to create ksi integer object.", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationsFile_getPublicationDataByTime(pubFile, pubTime, &pubRec);
	CuAssert(tc, "Unable to get publication record by publication date.", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pub);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pub != NULL);

	res = KSI_PublicationData_getImprint(pub, &pubHsh);
	CuAssert(tc, "Unable to get published hash", res == KSI_OK && pubHsh != NULL);

	KSI_Integer_free(pubTime);
	pubTime = NULL;

	res = KSI_PublicationData_getTime(pub, &pubTime);
	CuAssert(tc, "Unable to get publication time.", res == KSI_OK && pubTime != NULL);

	KSITest_decodeHexStr("01a1b5238ffb05fccfa67546266a0b2d7130f6656026033b6b578c12e4fbbe231a", buf, sizeof(buf), &len);
	res = KSI_DataHash_fromImprint(ctx, buf, len, &expHsh);
	CuAssert(tc, "Unable to get datahash from imprint", res == KSI_OK && expHsh != NULL);

	CuAssert(tc, "Publication hash mismatch.", KSI_DataHash_equals(expHsh, pubHsh));
	CuAssert(tc, "Publication time mismatch", KSI_Integer_equalsUInt(pubTime, 1397520000));

	res = KSI_PublicationRecord_getPublicationRefList(pubRec, &pubRefList);
	CuAssert(tc, "Unable to get publications ref list", res == KSI_OK && pubRefList != NULL);

	KSI_DataHash_free(expHsh);
}

static void testFindPublicationRef(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *pubTime = NULL;
	KSI_LIST(KSI_Utf8String) *pubRefList = NULL;
	size_t i;
	int isPubRefFound = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_receivePublicationsFile(ctx, &pubFile);
	CuAssert(tc, "Unable to get publications file.", res == KSI_OK && pubFile != NULL);

	res = KSI_Integer_new(ctx, 1397520000, &pubTime);
	CuAssert(tc, "Unable to create ksi integer object.", res == KSI_OK && pubTime != NULL);

	res = KSI_PublicationsFile_getPublicationDataByTime(pubFile, pubTime, &pubRec);
	CuAssert(tc, "Unable to get publication record by publication date.", res == KSI_OK && pubRec != NULL);

	KSI_Integer_free(pubTime);
	pubTime = NULL;

	res = KSI_PublicationRecord_getPublicationRefList(pubRec, &pubRefList);
	CuAssert(tc, "Unable to get publications ref list", res == KSI_OK && pubRefList != NULL);

	for (i = 0; i < KSI_Utf8StringList_length(pubRefList); i++) {
		KSI_Utf8String *pubRef = NULL;
		res = KSI_Utf8StringList_elementAt(pubRefList, i, &pubRef);
		CuAssert(tc, "Unable to get element from list", res == KSI_OK && pubRef != NULL);
		if (!strcmp("Financial Times, ISSN: 0307-1766, 2014-04-17", KSI_Utf8String_cstr(pubRef))) {
			isPubRefFound = 1;
		}
	}

	CuAssert(tc, "Financial times publication not found", isPubRefFound);
}

static void testSerializePublicationsFile(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	char *raw = NULL;
	unsigned raw_len = 0;
	FILE *f = NULL;
	int symbol = 0;
	unsigned i= 0;

	KSI_ERR_clearErrors(ctx);

	setFileMockResponse(tc, getFullResourcePath(TEST_PUBLICATIONS_FILE));

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_PublicationsFile_serialize(ctx, pubFile, &raw, &raw_len);
	CuAssert(tc, "Unable to serialize publications file", res == KSI_OK && raw != NULL && raw_len != 0);

	f = fopen(getFullResourcePath(TEST_PUBLICATIONS_FILE), "rb");
	CuAssert(tc, "Unable to open publications file", res == KSI_OK && f != NULL);

	while ((symbol = getc(f)) != EOF && i<raw_len){
		CuAssert(tc, "Serialized publications file mismatch", (char)symbol == raw[i]);
		i++;
	}

	CuAssert(tc, "Serialized publications file length  mismatch", i == raw_len);

	KSI_PublicationsFile_free(pubFile);
	KSI_free(raw);
	if (f) fclose(f);
}


CuSuite* KSITest_Publicationsfile_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testLoadPublicationsFile);
	/**
	 * Cert has expired
	 */
	SUITE_SKIP_TEST(suite, testVerifyPublicationsFile, "Taavi Valjaots", "Cert has expired.");
	SUITE_ADD_TEST(suite, testPublicationStringEncodingAndDecoding);
	SUITE_ADD_TEST(suite, testFindPublicationByPubStr);
	SUITE_ADD_TEST(suite, testFindPublicationByTime);
	SUITE_ADD_TEST(suite, testFindPublicationRef);
	SUITE_ADD_TEST(suite, testSerializePublicationsFile);

	return suite;
}

