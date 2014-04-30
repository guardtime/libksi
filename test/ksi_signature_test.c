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

static void testSerializeSignature(CuTest *tc) {
	int res;

	unsigned char in[0x1ffff];
	int in_len = 0;

	unsigned char *out = NULL;
	int out_len = 0;

	FILE *f = NULL;

	KSI_Signature *sig = NULL;

	KSI_ERR_clearErrors(ctx);

	f = fopen(TEST_SIGNATURE_FILE, "rb");
	CuAssert(tc, "Unable to open signature file.", f != NULL);

	in_len = fread(in, 1, sizeof(in), f);
	CuAssert(tc, "Nothing read from signature file.", in_len > 0);

	res = KSI_Signature_parse(ctx, in, in_len, &sig);
	CuAssert(tc, "Failed to parse signature", res == KSI_OK && sig != NULL);

	res = KSI_Signature_serialize(sig, &out, &out_len);
	CuAssert(tc, "Failed to serialize signature", res == KSI_OK);
	CuAssertIntEquals_Msg(tc, "Serialized signature length", in_len, out_len);
	CuAssert(tc, "Serialized signature content mismatch", !memcmp(in, out, in_len));

	KSI_free(out);
	KSI_Signature_free(sig);
}


CuSuite* KSI_Signature_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testLoadSignatureFromFile);
	SUITE_ADD_TEST(suite, testSerializeSignature);

	return suite;
}
