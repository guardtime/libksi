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

static void testVerifyPublicationsFileWithOrganization(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;

	KSI_ERR_clearErrors(ctx);

	setFileMockResponse(tc, getFullResourcePath(TEST_PUBLICATIONS_FILE));

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_CTX_putPubFileCertConstraint(ctx, "2.5.4.10", "Guardtime AS");
	CuAssert(tc, "Unable to set OID 2.5.4.10", res == KSI_OK);

	/* Verification should fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify with OID='2.5.4.10' value 'Guardtime AS'.", res == KSI_OK);

	res = KSI_CTX_putPubFileCertConstraint(ctx, "2.5.4.10", "Guardtime US");
	CuAssert(tc, "Unable to set OID 2.5.4.10", res == KSI_OK);

	/* Verification should fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must not verify with OID='2.5.4.10' value 'Fake Company'.", res != KSI_OK);
	/* Verification should succeed. */

	res = KSI_CTX_putPubFileCertConstraint(ctx, "2.5.4.10", NULL);
	CuAssert(tc, "Unable to remove OID 2.5.4.10", res == KSI_OK);

	/* Verification should fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify with OID='2.5.4.10' removed from the constraints", res == KSI_OK);

	CuAssert(tc, "Publications file should verify with mock certificate.", res == KSI_OK);

	KSI_PublicationsFile_free(pubFile);
}

static void testVerifyPublicationsFileWithNoConstraints(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;

	KSI_ERR_clearErrors(ctx);

	setFileMockResponse(tc, getFullResourcePath(TEST_PUBLICATIONS_FILE));

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_CTX_putPubFileCertConstraint(ctx, "1.2.840.113549.1.9.1", NULL);
	CuAssert(tc, "Unable to delete OID 1.2.840.113549.1.9.1", res == KSI_OK);

	/* Verification should not fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify with no constraints.", res == KSI_OK);

	res = KSI_CTX_putPubFileCertConstraint(ctx, "1.2.840.113549.1.9.1", "publications@guardtime.com");
	CuAssert(tc, "Unable to set OID 1.2.840.113549.1.9.1 back to normal", res == KSI_OK);

	/* Verification should not fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify with e-mail.", res == KSI_OK);

	KSI_PublicationsFile_free(pubFile);
}

static void testVerifyPublicationsFileWithAttributeNotPresent(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;

	KSI_ERR_clearErrors(ctx);

	setFileMockResponse(tc, getFullResourcePath(TEST_PUBLICATIONS_FILE));

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_CTX_putPubFileCertConstraint(ctx, "2.5.4.9", "Local pub");
	CuAssert(tc, "Unable to delete OID 2.5.4.9", res == KSI_OK);

	/* Verification should fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify with address.", res != KSI_OK);

	res = KSI_CTX_putPubFileCertConstraint(ctx, "2.5.4.9", NULL);
	CuAssert(tc, "Unable to set OID 2.5.4.9 back to normal", res == KSI_OK);

	/* Verification should not fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify.", res == KSI_OK);

	KSI_PublicationsFile_free(pubFile);
}

static void testVerifyPublicationsFileWithRemoveNone(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;

	KSI_ERR_clearErrors(ctx);

	setFileMockResponse(tc, getFullResourcePath(TEST_PUBLICATIONS_FILE));

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_CTX_putPubFileCertConstraint(ctx, "2.5.4.9", NULL);
	CuAssert(tc, "Unable to delete nonexistent OID 2.5.4.9 (should not fail)", res == KSI_OK);

	/* Verification should not fail. */
	res = KSI_PublicationsFile_verify(pubFile, ctx);
	CuAssert(tc, "Publications file must verify with address.", res == KSI_OK);

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
	size_t len;

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
	size_t len;

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
	size_t raw_len = 0;
	FILE *f = NULL;
	int symbol = 0;
	size_t i = 0;
	size_t signedDataLengthAtLoading;
	size_t signedDataLengthAtSerialization;


	KSI_ERR_clearErrors(ctx);

	setFileMockResponse(tc, getFullResourcePath(TEST_PUBLICATIONS_FILE));

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_PublicationsFile_getSignedDataLength(pubFile, &signedDataLengthAtLoading);
	CuAssert(tc, "Unable to get signed data length.", res == KSI_OK);

	res = KSI_PublicationsFile_serialize(ctx, pubFile, &raw, &raw_len);
	CuAssert(tc, "Unable to serialize publications file", res == KSI_OK && raw != NULL && raw_len != 0);

	res = KSI_PublicationsFile_getSignedDataLength(pubFile, &signedDataLengthAtSerialization);
	CuAssert(tc, "Unable to get signed data length.", res == KSI_OK);

	f = fopen(getFullResourcePath(TEST_PUBLICATIONS_FILE), "rb");
	CuAssert(tc, "Unable to open publications file", res == KSI_OK && f != NULL);

	while ((symbol = getc(f)) != EOF && i<raw_len){
		CuAssert(tc, "Serialized publications file mismatch", (char)symbol == raw[i]);
		i++;
	}

	CuAssert(tc, "Serialized publications file length mismatch", i == raw_len);

	CuAssert(tc, "Serialized publications file length mismatch", signedDataLengthAtSerialization == signedDataLengthAtLoading);



	KSI_PublicationsFile_free(pubFile);
	KSI_free(raw);
	if (f) fclose(f);
}

static void testGetNearestPublication(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;
	KSI_PublicationData *pubDat = NULL;
	KSI_Integer *pubTm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_Integer_new(ctx, 1289779234, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getNearestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "Unable to find nearest publication", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubDat);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pubDat != NULL);

	res = KSI_PublicationData_getTime(pubDat, &pubTm);
	CuAssert(tc, "Unable to get publication time", res == KSI_OK && pubTm != NULL);

	CuAssert(tc, "Unexpected publication time", KSI_Integer_equalsUInt(pubTm, 1292371200));

	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}


static void testGetNearestPublicationOf0(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;
	KSI_PublicationData *pubDat = NULL;
	KSI_Integer *pubTm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	/* With time set to 0, the result should be the first publication record in the publications file. */
	res = KSI_Integer_new(ctx, 0, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getNearestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "Unable to find nearest publication", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubDat);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pubDat != NULL);

	res = KSI_PublicationData_getTime(pubDat, &pubTm);
	CuAssert(tc, "Unable to get publication time", res == KSI_OK && pubTm != NULL);

	CuAssert(tc, "Unexpected publication time", KSI_Integer_equalsUInt(pubTm, 1208217600));

	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}

static void testGetNearestPublicationWithPubTime(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;
	KSI_PublicationData *pubDat = NULL;
	KSI_Integer *pubTm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	/* With time set to 0, the result should be the first publication record in the publications file. */
	res = KSI_Integer_new(ctx, 1208217600, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getNearestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "Unable to find nearest publication", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubDat);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pubDat != NULL);

	res = KSI_PublicationData_getTime(pubDat, &pubTm);
	CuAssert(tc, "Unable to get publication time", res == KSI_OK && pubTm != NULL);

	CuAssert(tc, "Unexpected publication time", KSI_Integer_equalsUInt(pubTm, 1208217600));

	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}

static void testGetNearestPublicationOfFuture(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	/* With time set to 0, the result should be the first publication record in the publications file. */
	res = KSI_Integer_new(ctx, 2208217600, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getNearestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "There should not be a valid publication", res == KSI_OK && pubRec == NULL);

	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}

static void testGetLatestPublicationOf0(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;
	KSI_PublicationData *pubDat = NULL;
	KSI_Integer *pubTm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_Integer_new(ctx, 1289779234, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getLatestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "Unable to find nearest publication", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubDat);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pubDat != NULL);

	res = KSI_PublicationData_getTime(pubDat, &pubTm);
	CuAssert(tc, "Unable to get publication time", res == KSI_OK && pubTm != NULL);

	CuAssert(tc, "Unexpected publication time (this test might fail, if you have recently updated the publications file in the tests)", KSI_Integer_equalsUInt(pubTm, 1405382400));

	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}

static void testGetLatestPublicationOfLast(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;
	KSI_PublicationData *pubDat = NULL;
	KSI_Integer *pubTm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_Integer_new(ctx, 1405382400, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getLatestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "Unable to find nearest publication", res == KSI_OK && pubRec != NULL);

	res = KSI_PublicationRecord_getPublishedData(pubRec, &pubDat);
	CuAssert(tc, "Unable to get published data", res == KSI_OK && pubDat != NULL);

	res = KSI_PublicationData_getTime(pubDat, &pubTm);
	CuAssert(tc, "Unable to get publication time", res == KSI_OK && pubTm != NULL);

	CuAssert(tc, "Unexpected publication time (this test might fail, if you have recently updated the publications file in the tests)", KSI_Integer_equalsUInt(pubTm, 1405382400));

	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}

static void testGetLatestPublicationOfFuture(CuTest *tc) {
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Integer *tm = NULL;

	res = KSI_PublicationsFile_fromFile(ctx, getFullResourcePath(TEST_PUBLICATIONS_FILE), &pubFile);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && pubFile != NULL);

	res = KSI_Integer_new(ctx, 2405382400, &tm);
	CuAssert(tc, "Unable to create integer", res == KSI_OK && tm != NULL);

	res = KSI_PublicationsFile_getLatestPublication(pubFile, tm, &pubRec);
	CuAssert(tc, "This publication should not exist.", res == KSI_OK && pubRec == NULL);

	KSI_PublicationsFile_free(pubFile);
	KSI_Integer_free(tm);
}


CuSuite* KSITest_Publicationsfile_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testLoadPublicationsFile);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFile);
	SUITE_ADD_TEST(suite, testPublicationStringEncodingAndDecoding);
	SUITE_ADD_TEST(suite, testFindPublicationByPubStr);
	SUITE_ADD_TEST(suite, testFindPublicationByTime);
	SUITE_ADD_TEST(suite, testFindPublicationRef);
	SUITE_ADD_TEST(suite, testSerializePublicationsFile);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFileWithOrganization);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFileWithNoConstraints);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFileWithAttributeNotPresent);
	SUITE_ADD_TEST(suite, testVerifyPublicationsFileWithRemoveNone);
	SUITE_ADD_TEST(suite, testGetNearestPublication);
	SUITE_ADD_TEST(suite, testGetNearestPublicationOf0);
	SUITE_ADD_TEST(suite, testGetNearestPublicationWithPubTime);
	SUITE_ADD_TEST(suite, testGetNearestPublicationOfFuture);
	SUITE_ADD_TEST(suite, testGetLatestPublicationOf0);
	SUITE_ADD_TEST(suite, testGetLatestPublicationOfLast);
	SUITE_ADD_TEST(suite, testGetLatestPublicationOfFuture);

	return suite;
}

