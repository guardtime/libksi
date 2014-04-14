#include "all_tests.h"

extern KSI_CTX *ctx;

static void testDecodeHexStr(CuTest *tc) {
	const char *str = "a1 Ca fe babe  ";
	const unsigned char exp[] = {0xa1, 0xca, 0xfe, 0xba, 0xbe};
	unsigned char buf[sizeof(exp)];
	int res;
	int len;

	KSI_ERR_clearErrors(ctx);

	res = KSI_decodeHexStr(str, buf, sizeof(buf), &len);
	CuAssert(tc, "Unable to decode valid hex string", res == KSI_OK);
	CuAssertIntEquals_Msg(tc, "Decoded buf length", sizeof(exp), len);
	CuAssert(tc, "Decoded data mismatch", !memcmp(exp, buf, len));

}

static void testDecodeHexStrPartialFail(CuTest *tc) {
	const char *str = "CAFEBABE5";
	unsigned char buf[10];
	int res;
	int len;

	KSI_ERR_clearErrors(ctx);

	res = KSI_decodeHexStr(str, buf, sizeof(buf), &len);
	CuAssert(tc, "Decoder did not fail", res != KSI_OK);

}

static void testDecodeHexStrFailBuffer(CuTest *tc) {
	const char *str = " ca fe babe  ";
	unsigned char buf[1];
	int res;
	int len;

	KSI_ERR_clearErrors(ctx);

	res = KSI_decodeHexStr(str, buf, sizeof(buf), &len);
	CuAssert(tc, "Decoder did not fail.", res != KSI_OK);

}

static void testDecodeHexStrFailFormat(CuTest *tc) {
	const char *str = "1 random string";
	unsigned char buf[10];
	int res;
	int len;

	KSI_ERR_clearErrors(ctx);

	res = KSI_decodeHexStr(str, buf, sizeof(buf), &len);
	CuAssert(tc, "Decoder did not fail.", res != KSI_OK);

}

CuSuite* KSI_UTIL_GetSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testDecodeHexStr);
	SUITE_ADD_TEST(suite, testDecodeHexStrPartialFail);
	SUITE_ADD_TEST(suite, testDecodeHexStrFailBuffer);
	SUITE_ADD_TEST(suite, testDecodeHexStrFailFormat);

	return suite;
}
