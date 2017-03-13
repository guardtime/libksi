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

#include "cutest/CuTest.h"
#include "all_integration_tests.h"
#include <../src/ksi/ksi.h>
#include <../src/ksi/ksi.h>

extern KSI_CTX *ctx;

static void Test_DownloadPubfile(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationsFile *pubfile = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_receivePublicationsFile(ctx, &pubfile);
	CuAssert(tc, "Unable to receive publications file.", res == KSI_OK && pubfile != NULL);

	res = KSI_verifyPublicationsFile(ctx, pubfile);
	CuAssert(tc, "Unable to verify publications file.", res == KSI_OK);

	KSI_PublicationsFile_free(pubfile);

	return;
}

static void Test_DownloadPubfileInvalidConstraints(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	const KSI_CertConstraint badConstraints[] = {
		{ KSI_CERT_EMAIL, "its@not.working"},
		{ NULL, NULL }
	};
	KSI_PublicationsFile *pubfile = NULL;
	KSI_CTX *ctx = NULL;


	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_new(&ctx);
	CuAssert(tc, "Unable to create aggregation request.", res == KSI_OK);

	res = KSI_CTX_setPublicationUrl(ctx, conf.publications_file_url);
	CuAssert(tc, "Unable to set publications file url.", res == KSI_OK);

	res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, badConstraints);
	CuAssert(tc, "Unable to set publications file constraints.", res == KSI_OK);

	res = KSI_receivePublicationsFile(ctx, &pubfile);
	CuAssert(tc, "Unable to receive publications file.", res == KSI_OK && pubfile != NULL);

	res = KSI_verifyPublicationsFile(ctx, pubfile);
	CuAssert(tc, "Wrong error code. Must fail as the constraints do not match.", res == KSI_PKI_CERTIFICATE_NOT_TRUSTED);

	KSI_PublicationsFile_free(pubfile);
	KSI_CTX_free(ctx);
	return;
}

static KSI_uint64_t getLatestPubTime(CuTest* tc, KSI_PublicationsFile *pubFile) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(KSI_PublicationRecord) *pubs = NULL;
	KSI_PublicationRecord *pub = NULL;
	KSI_PublicationData *pubData = NULL;
	KSI_Integer *time = NULL;

	res = KSI_PublicationsFile_getPublications(pubFile, &pubs);
	CuAssert(tc, "Unable to get publication records.", res == KSI_OK && pubs != NULL);

	res = KSI_PublicationRecordList_elementAt(pubs, KSI_PublicationRecordList_length(pubs) - 1, &pub);
	CuAssert(tc, "Unable to get latest publication record.", res == KSI_OK && pub != NULL);

	res = KSI_PublicationRecord_getPublishedData(pub, &pubData);
	CuAssert(tc, "Unable to get publication data.", res == KSI_OK && pubData != NULL);

	res = KSI_PublicationData_getTime(pubData, &time);
	CuAssert(tc, "Unable to get publication time.", res == KSI_OK && time != NULL);

	return KSI_Integer_getUInt64(time);
}

static void Test_DownloadPubfile_ChangeClient(CuTest* tc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationsFile *pubfile = NULL;
	KSI_uint64_t prevtime;

	KSI_ERR_clearErrors(ctx);

	res = KSI_receivePublicationsFile(ctx, &pubfile);
	CuAssert(tc, "Unable to receive publications file.", res == KSI_OK && pubfile != NULL);
	prevtime = getLatestPubTime(tc, pubfile);
	KSI_PublicationsFile_free(pubfile);
	KSI_CTX_setPublicationsFile(ctx, NULL);

	res = KSI_CTX_setPublicationUrl(ctx, getFullResourcePathUri("resource/tlv/publications.tlv"));
	CuAssert(tc, "Unable to set pubfile URI.", res == KSI_OK);
	res = KSI_receivePublicationsFile(ctx, &pubfile);
	CuAssert(tc, "Unable to receive publications file.", res == KSI_OK && pubfile != NULL);
	CuAssert(tc, "Publications file last publication should be different.", prevtime != getLatestPubTime(tc, pubfile));
	prevtime = getLatestPubTime(tc, pubfile);
	KSI_PublicationsFile_free(pubfile);
	KSI_CTX_setPublicationsFile(ctx, NULL);

	res = KSI_CTX_setPublicationUrl(ctx, conf.publications_file_url);
	CuAssert(tc, "Unable to set publications file url.", res == KSI_OK);
	res = KSI_receivePublicationsFile(ctx, &pubfile);
	CuAssert(tc, "Unable to receive publications file.", res == KSI_OK && pubfile != NULL);
	CuAssert(tc, "Publications file last publication should be different.", prevtime != getLatestPubTime(tc, pubfile));
	prevtime = getLatestPubTime(tc, pubfile);
	KSI_PublicationsFile_free(pubfile);
	KSI_CTX_setPublicationsFile(ctx, NULL);

	res = KSI_CTX_setPublicationUrl(ctx, getFullResourcePathUri("resource/tlv/publications.tlv"));
	CuAssert(tc, "Unable to set pubfile URI.", res == KSI_OK);
	res = KSI_receivePublicationsFile(ctx, &pubfile);
	CuAssert(tc, "Unable to receive publications file.", res == KSI_OK && pubfile != NULL);
	CuAssert(tc, "Publications file last publication should be different.", prevtime != getLatestPubTime(tc, pubfile));
	KSI_PublicationsFile_free(pubfile);
	KSI_CTX_setPublicationsFile(ctx, NULL);
}

CuSuite* PubIntegrationTests_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, Test_DownloadPubfile);
	SUITE_ADD_TEST(suite, Test_DownloadPubfileInvalidConstraints);
	SUITE_ADD_TEST(suite, Test_DownloadPubfile_ChangeClient);

	return suite;
}


