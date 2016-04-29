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

#include "cutest/CuTest.h"
#include "all_tests.h"
#include "../src/ksi/tlv_template.h"

extern KSI_CTX *ctx;

#ifdef BUILD_DLL
__declspec( dllimport )
#endif
KSI_IMPORT_TLV_TEMPLATE(KSI_Signature)

#define TEST_SIG_BUF_SIZE 			0x1ffff
#define IS_NON_CRITICAL_FLAG_MASK 	0x40
#define IS_FORWARD_FLAG_MASK		0x20

static void TestSerializeObjectFlags(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;

	unsigned char in[TEST_SIG_BUF_SIZE];
	size_t in_len = 0;

	unsigned char *outIsNcSet = NULL;
	unsigned char *outIsFwdSet = NULL;
	size_t out_len = 0;

	FILE *f = NULL;

	KSI_Signature *sigIsNcSet = NULL;
	KSI_Signature *sigIsFwdSet = NULL;

	KSI_ERR_clearErrors(ctx);

	f = fopen(getFullResourcePath(TEST_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);


	res = KSI_Signature_parse(ctx, in, in_len, &sigIsNcSet);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sigIsNcSet != NULL);

	/* KSI_TlvTemplate_serializeObject is used because it is needed to test it specifically */
	res = KSI_TlvTemplate_serializeObject(ctx, sigIsNcSet, 0x0800, 1, 0, KSI_TLV_TEMPLATE(KSI_Signature), &outIsNcSet, &out_len);

	CuAssert(tc, "Failed to serialize signature", res == KSI_OK && out_len != 0);
	CuAssert(tc, "Failed to set isNonCritical flag", *outIsNcSet & IS_NON_CRITICAL_FLAG_MASK);


	res = KSI_Signature_parse(ctx, in, in_len, &sigIsFwdSet);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sigIsFwdSet != NULL);

	out_len = 0;
	/* KSI_TlvTemplate_serializeObject is used because it is needed to test it specifically */
	res = KSI_TlvTemplate_serializeObject(ctx, sigIsFwdSet, 0x0800, 0, 1, KSI_TLV_TEMPLATE(KSI_Signature), &outIsFwdSet, &out_len);

	CuAssert(tc, "Failed to serialize signature", res == KSI_OK && out_len != 0);
	CuAssert(tc, "Failed to set isForward flag", *outIsFwdSet & IS_FORWARD_FLAG_MASK);


	KSI_free(outIsNcSet);
	KSI_free(outIsFwdSet);
	KSI_Signature_free(sigIsNcSet);
	KSI_Signature_free(sigIsFwdSet);

#undef TEST_SIGNATURE_FILE
}

static void TestWriteBytesFlags(CuTest* tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;

	unsigned char in[TEST_SIG_BUF_SIZE];
	size_t in_len = 0;

	unsigned char out[TEST_SIG_BUF_SIZE];
	size_t out_len = 0;

	FILE *f = NULL;

	KSI_Signature *sigIsNcSet = NULL;
	KSI_Signature *sigIsFwdSet = NULL;

	unsigned char no_option = 0x00;

	KSI_ERR_clearErrors(ctx);

	f = fopen(getFullResourcePath(TEST_SIGNATURE_FILE), "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);


	res = KSI_Signature_parse(ctx, in, in_len, &sigIsNcSet);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sigIsNcSet != NULL);

	/* KSI_TlvTemplate_writeBytes is used because it is needed to test it specifically */
	res = KSI_TlvTemplate_writeBytes(ctx, sigIsNcSet, 0x0800, 1, 0, KSI_TLV_TEMPLATE(KSI_Signature), out, TEST_SIG_BUF_SIZE, &out_len, no_option);

	CuAssert(tc, "Failed to serialize signature", res == KSI_OK && out_len != 0);
	CuAssert(tc, "Failed to set isNonCritical flag", out[0] & IS_NON_CRITICAL_FLAG_MASK);


	res = KSI_Signature_parse(ctx, in, in_len, &sigIsFwdSet);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sigIsFwdSet != NULL);

	out_len = 0;
	/* KSI_TlvTemplate_writeBytes is used because it is needed to test it specifically */
	res = KSI_TlvTemplate_writeBytes(ctx, sigIsFwdSet, 0x0800, 0, 1, KSI_TLV_TEMPLATE(KSI_Signature), out, TEST_SIG_BUF_SIZE, &out_len, no_option);

	CuAssert(tc, "Failed to serialize signature", res == KSI_OK && out_len != 0);
	CuAssert(tc, "Failed to set isForward flag", out[0] & IS_FORWARD_FLAG_MASK);

	KSI_Signature_free(sigIsNcSet);
	KSI_Signature_free(sigIsFwdSet);

#undef TEST_SIGNATURE_FILE
}

CuSuite* KSITest_Flags_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestSerializeObjectFlags);
	SUITE_ADD_TEST(suite, TestWriteBytesFlags);

	return suite;
}
