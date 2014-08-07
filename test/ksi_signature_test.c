#include <string.h>
#include "all_tests.h"

extern KSI_CTX *ctx;

#define TEST_SIGNATURE_FILE "test/resource/tlv/ok-sig-2014-04-30.1.ksig"

static void testLoadSignatureFromFile(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, TEST_SIGNATURE_FILE, &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	KSI_Signature_free(sig);
}

static void testVerifySignatureNew(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, TEST_SIGNATURE_FILE, &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	/* Set the extend response. */
	KSITest_setFileMockResponse(tc, "test/resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv");

	res = KSI_verifySignature(ctx, sig);
	CuAssert(tc, "Unable to verify signature online.", res == KSI_OK);

	KSI_Signature_free(sig);

}

static void testVerifySignatureWithPublication(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, "test/resource/tlv/ok-sig-2014-04-30.1-extended.ksig", &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_verifySignature(ctx, sig);

	CuAssert(tc, "Unable to verify signature online.", res == KSI_OK);

	KSI_Signature_free(sig);

}

static void testVerifySignatureExtendedToHead(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, "test/resource/tlv/ok-sig-2014-04-30.1-head.ksig", &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	/* Set the extend response. */
	KSITest_setFileMockResponse(tc, "test/resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv");

	res = KSI_verifySignature(ctx, sig);
	CuAssert(tc, "Unable to verify signature online.", res == KSI_OK);

	KSI_Signature_free(sig);

}


static void testSignatureSigningTime(CuTest *tc) {
	int res;
	KSI_Signature *sig = NULL;
	KSI_Integer *sigTime = NULL;
	KSI_uint64_t utc = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, TEST_SIGNATURE_FILE, &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getSigningTime(sig, &sigTime);
	CuAssert(tc, "Unable to get signing time from signature", res == KSI_OK && sigTime != NULL);

	utc = KSI_Integer_getUInt64(sigTime);

	CuAssert(tc, "Unexpected signature signing time.", utc == 1398866256);

	KSI_Signature_free(sig);
}


static void testSerializeSignature(CuTest *tc) {
	int res;

	unsigned char in[0x1ffff];
	unsigned in_len = 0;

	unsigned char *out = NULL;
	unsigned out_len = 0;

	FILE *f = NULL;

	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	f = fopen(TEST_SIGNATURE_FILE, "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);

	res = KSI_Signature_parse(ctx, in, in_len, &sig);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sig != NULL);

	res = KSI_Signature_serialize(sig, &out, &out_len);
	CuAssert(tc, "Failed to serialize signature", res == KSI_OK);
	CuAssert(tc, "Serialized signature length mismatch", in_len == out_len);
	CuAssert(tc, "Serialized signature content mismatch", !memcmp(in, out, in_len));

	KSI_free(out);
	KSI_Signature_free(sig);
}

static void testVerifyDocument(CuTest *tc) {
	int res;

	unsigned char in[0x1ffff];
	unsigned in_len = 0;

	char doc[] = "LAPTOP";

	FILE *f = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	f = fopen(TEST_SIGNATURE_FILE, "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);

	res = KSI_Signature_parse(ctx, in, in_len, &sig);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sig != NULL);

	res = KSI_Signature_verifyDocument(sig, doc, strlen(doc));
	CuAssert(tc, "Failed to verify valid document", res == KSI_OK);

	res = KSI_Signature_verifyDocument(sig, doc, sizeof(doc));
	CuAssert(tc, "Verification did not fail with expected error.", res == KSI_WRONG_DOCUMENT);

	KSI_Signature_free(sig);
}

static void testVerifyDocumentHash(CuTest *tc) {
	int res;

	unsigned char in[0x1ffff];
	unsigned in_len = 0;

	char doc[] = "LAPTOP";
	KSI_DataHash *hsh = NULL;

	FILE *f = NULL;
	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	f = fopen(TEST_SIGNATURE_FILE, "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = (unsigned)fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	fclose(f);

	res = KSI_Signature_parse(ctx, in, in_len, &sig);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sig != NULL);

	/* Chech correct document. */
	res = KSI_DataHash_create(ctx, doc, strlen(doc), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Failed to create data hash", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_verifyDataHash(sig, hsh);
	CuAssert(tc, "Failed to verify valid document", res == KSI_OK);

	KSI_DataHash_free(hsh);
	hsh = NULL;

	/* Chech wrong document. */
	res = KSI_DataHash_create(ctx, doc, sizeof(doc), KSI_HASHALG_SHA2_256, &hsh);
	CuAssert(tc, "Failed to create data hash", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_verifyDataHash(sig, hsh);
	CuAssert(tc, "Verification did not fail with expected error.", res == KSI_WRONG_DOCUMENT);

	KSI_DataHash_free(hsh);
	hsh = NULL;

	/* Check correct document with wrong hash algorithm. */
	res = KSI_DataHash_create(ctx, doc, strlen(doc), KSI_HASHALG_SHA2_512, &hsh);
	CuAssert(tc, "Failed to create data hash", res == KSI_OK && hsh != NULL);

	res = KSI_Signature_verifyDataHash(sig, hsh);
	CuAssert(tc, "Verification did not fail with expected error.", res == KSI_WRONG_DOCUMENT);

	KSI_DataHash_free(hsh);


	KSI_Signature_free(sig);
}

static void testSignerIdentity(CuTest *tc) {
	int res;
	const char id_expected[] = "GT :: testA :: 36-test";
	KSI_Signature *sig = NULL;
	char *id_actual = NULL;

	res = KSI_Signature_fromFile(ctx, "test/resource/tlv/ok-sig-2014-08-01.1.ksig", &sig);
	CuAssert(tc, "Unable to load signature", res == KSI_OK && sig != NULL);

	res = KSI_Signature_getSignerIdentity(sig, &id_actual);
	CuAssert(tc, "Unable to get signer identity from signature.", res == KSI_OK && id_actual != NULL);

	CuAssert(tc, "Unexpected signer identity", !strncmp(id_expected, id_actual, strlen(id_expected)));

	KSI_Signature_free(sig);
	KSI_free(id_actual);

}

CuSuite* KSITest_Signature_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testLoadSignatureFromFile);
	SUITE_ADD_TEST(suite, testSignatureSigningTime);
	SUITE_ADD_TEST(suite, testSerializeSignature);
	SUITE_ADD_TEST(suite, testVerifyDocument);
	SUITE_ADD_TEST(suite, testVerifyDocumentHash);
	SUITE_ADD_TEST(suite, testVerifySignatureNew);
	SUITE_ADD_TEST(suite, testVerifySignatureWithPublication);
	SUITE_ADD_TEST(suite, testVerifySignatureExtendedToHead);
	SUITE_ADD_TEST(suite, testSignerIdentity);

	return suite;
}
