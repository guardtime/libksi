#include <string.h>
#include "all_tests.h"

extern KSI_CTX *ctx;

#define TEST_PUBLICATIONS_FILE "test/resource/tlv/publications-1.tlv"

static void testLoadPublicationsFile(CuTest *tc) {
	int res;
	KSI_KSITrustProvider *trust = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_PKITruststore_addLookupFile(ctx->pkiTruststore, "test/resource/tlv/server.crt");
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	res = KSI_KSITrustProvider_fromFile(ctx,TEST_PUBLICATIONS_FILE, &trust);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && trust != NULL);

	KSI_KSITrustProvider_free(trust);
}

static void testPublicationStringEncodingAndDecoding(CuTest *tc) {
	static const char publication[] = "AAAAAA-CTJR3I-AANBWU-RY76YF-7TH2M5-KGEZVA-WLLRGD-3GKYBG-AM5WWV-4MCLSP-XPRDDI-UFMHBA";
	char *out = NULL;
	int res;
	KSI_PublicationData *pub = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_base32ToPublishedData(ctx, publication, strlen(publication), &pub);
	CuAssert(tc, "Failed decoding publication string.", res == KSI_OK && pub != NULL);

	res = KSI_publishedDataToBase32(pub, &out);
	CuAssert(tc, "Failed encoding the published data object", res == KSI_OK && out != NULL);

	CuAssert(tc, "Invalid encoded publication string does not match original.", strncmp(publication, out, strlen(publication)));

	KSI_PublicationData_free(pub);
	KSI_free(out);
}

CuSuite* KSI_KSITrustProvider_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testLoadPublicationsFile);
	SUITE_ADD_TEST(suite, testPublicationStringEncodingAndDecoding);

	return suite;
}
