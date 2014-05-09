#include <string.h>
#include "all_tests.h"

extern KSI_CTX *ctx;

#define TEST_PUBLICATIONS_FILE "test/resource/tlv/publications-1.tlv"

static void testLoadPublicationsFile(CuTest *tc) {
	int res;
	KSI_KSITrustProvider *trust = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_KSITrustProvider_fromFile(ctx,TEST_PUBLICATIONS_FILE, &trust);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && trust != NULL);

	KSI_KSITrustProvider_free(trust);
}

CuSuite* KSI_KSITrustProvider_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testLoadPublicationsFile);

	return suite;
}
