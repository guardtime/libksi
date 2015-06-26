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
#include <ksi/pkitruststore.h>
#include "ksi/tlv.h"
#include "ksi/io.h"

#include "cutest/CuTest.h"
#include "all_tests.h"

extern KSI_CTX *ctx;
char tmp_path[1024];

static int tlvFromFile(const char *fileName, KSI_TLV **tlv) {
	int res;
	KSI_RDR *rdr = NULL;
	FILE *f = NULL;

	KSI_LOG_debug(ctx, "Open TLV file: '%s'", fileName);

	f = fopen(fileName, "rb");
	res = KSI_RDR_fromStream(ctx, f, &rdr);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TLV_fromReader(rdr, tlv);
	if (res != KSI_OK) goto cleanup;

cleanup:

	if (f != NULL) fclose(f);
	KSI_RDR_close(rdr);

	return res;
}

static void TestAddInvalidLookupFile(CuTest *tc) {
	int res;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI trustsore.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, "KSI_ThisFileDoesProbablyNotExist");
	CuAssert(tc, "Adding missing lookup file did not fail.", res != KSI_OK);

}

static void TestAddValidLookupFile(CuTest *tc) {
	int res;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI trustsore.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath("resource/tlv/mock.crt"));
	CuAssert(tc, "Adding correct lookup file did fail.", res == KSI_OK);

}



static void TestParseAndSeraializeCert(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	KSI_PKICertificate *cert = NULL;
	char *raw_crt = NULL;
	unsigned raw_crt_len;
	char *raw = NULL;
	unsigned raw_len;

	KSI_ERR_clearErrors(ctx);

	res = tlvFromFile(getFullResourcePath("resource/tlv/ok-crt.tlv"), &tlv);
	CuAssert(tc, "Unable to read tlv from file.", res == KSI_OK && tlv != NULL);

	res = KSI_PKICertificate_fromTlv(tlv, &cert);
	CuAssert(tc, "Unable to get cert from tlv.", res == KSI_OK && cert != NULL);

	res = KSI_PKICertificate_serialize(cert, &raw_crt, &raw_crt_len);
	CuAssert(tc, "Unable to serialize certificate.", res == KSI_OK && raw_crt != NULL && raw_crt_len > 0);

	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	CuAssert(tc, "Unable to get raw cert value.", res == KSI_OK && raw != NULL && raw_len > 0);

	CuAssert(tc, "Certificate and its serialized value length mismatch.", raw_len == raw_crt_len);
	CuAssert(tc, "Certificate and its serialized value mismatch.", memcmp(raw, raw_crt, raw_len) == 0);

	KSI_TLV_free(tlv);
	KSI_PKICertificate_free(cert);
	KSI_free(raw_crt);
}

CuSuite* KSITest_Truststore_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestAddInvalidLookupFile);
	SUITE_ADD_TEST(suite, TestAddValidLookupFile);
	SUITE_ADD_TEST(suite, TestParseAndSeraializeCert);

	return suite;
}
