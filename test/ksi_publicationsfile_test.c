#include <string.h>
#include "all_tests.h"

extern KSI_CTX *ctx;
extern const unsigned char *KSI_NET_MOCK_request;
extern int KSI_NET_MOCK_request_len;
extern const unsigned char *KSI_NET_MOCK_response;
extern int KSI_NET_MOCK_response_len;

#define TEST_PUBLICATIONS_FILE "test/resource/tlv/publications.tlv"

static void setFileMockResponse(CuTest *tc, const char *fileName) {
	FILE *f = NULL;
	unsigned char *resp = NULL;
	int resp_size = 0xfffff;

	resp = KSI_calloc(resp_size, 1);
	CuAssert(tc, "Out of memory", resp != NULL);

	/* Read response from file. */
	f = fopen(fileName, "rb");
	CuAssert(tc, "Unable to open sample response file", f != NULL);

	KSI_NET_MOCK_response_len = fread(resp, 1, resp_size, f);
	fclose(f);

	if (KSI_NET_MOCK_response != NULL) {
		KSI_free((unsigned char *)KSI_NET_MOCK_response);
	}
	KSI_NET_MOCK_response = resp;
}

static void testLoadPublicationsFile(CuTest *tc) {
	int res;
	KSI_PublicationsFile *trust = NULL;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI truststore from context.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, "test/resource/tlv/mock.crt");
	CuAssert(tc, "Unable to read certificate", res == KSI_OK);

	setFileMockResponse(tc, TEST_PUBLICATIONS_FILE);

	res = KSI_PublicationsFile_fromFile(ctx, TEST_PUBLICATIONS_FILE, &trust);
	KSI_ERR_statusDump(ctx, stdout);
	CuAssert(tc, "Unable to read publications file", res == KSI_OK && trust != NULL);

	KSI_PublicationsFile_free(trust);
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

CuSuite* KSITest_Publicationsfile_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testLoadPublicationsFile);
	SUITE_ADD_TEST(suite, testPublicationStringEncodingAndDecoding);

	return suite;
}
