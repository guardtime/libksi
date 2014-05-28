#include <string.h>
#include "all_tests.h"

extern KSI_CTX *ctx;
extern const unsigned char *KSI_NET_MOCK_request;
extern int KSI_NET_MOCK_request_len;
extern const unsigned char *KSI_NET_MOCK_response;
extern int KSI_NET_MOCK_response_len;

#define TEST_SIGNATURE_FILE "test/resource/tlv/ok-sig-2014-04-30.1.ksig"

static unsigned char someImprint[] ={
		0x01, 0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
		0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d};

static unsigned char expectedSignRequest[] = {
		0x82, 0x00, 0x00, 0x27, 0x82, 0x01, 0x00, 0x23, 0x03, 0x21, 0x01, 0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06,
		0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc, 0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6,
		0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d};

static unsigned char expectedExtendRequest[] = {
		0x83, 0x00, 0x00, 0x10, 0x83, 0x01, 0x00, 0x0c, 0x02, 0x04, 0x53, 0x61, 0x01, 0x50, 0x03, 0x04, 0x53, 0x74, 0x03, 0x80
};

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

static void TestSendAggregateRequest(CuTest* tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_NetProvider *pr = NULL;

	KSI_ERR_clearErrors(ctx);


	res = KSI_NET_MOCK_new(ctx, &pr);
	CuAssert(tc, "Unable to create mock network provider.", res == KSI_OK);

	res = KSI_setNetworkProvider(ctx, pr);
	CuAssert(tc, "Unable to set network provider.", res == KSI_OK);

	res = KSI_DataHash_fromImprint(ctx, someImprint, sizeof(someImprint), &hsh);
	CuAssert(tc, "Unable to create data hash object from raw imprint", res == KSI_OK && hsh != NULL);

	setFileMockResponse(tc, "test/resource/tlv/ok_aggr_response-1.tlv");

	res = KSI_Signature_sign(ctx, hsh, &sig);
	KSI_ERR_statusDump(ctx, stdout);
	CuAssert(tc, "Unable to sign the hash", res == KSI_OK && sig != NULL);
	CuAssert(tc, "Unexpected send request", KSI_NET_MOCK_request_len == sizeof(expectedSignRequest) && !memcmp(expectedSignRequest, KSI_NET_MOCK_request, KSI_NET_MOCK_request_len));

	KSI_free((unsigned char *)KSI_NET_MOCK_response);
	KSI_NET_MOCK_response = NULL;

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
}

static void TestSendExtendRequest(CuTest* tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_NetProvider *pr = NULL;
	KSI_Signature *ext = NULL;
	unsigned char *serialized = NULL;
	int serialized_len = 0;
	unsigned char *expected[0x1ffff];
	int expected_len = 0;
	FILE *f = NULL;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI Truststore", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, "test/resource/tlv/mock.crt");
	CuAssert(tc, "Unable to add test certificate to truststore.", res == KSI_OK);

	res = KSI_NET_MOCK_new(ctx, &pr);
	CuAssert(tc, "Unable to create mock network provider.", res == KSI_OK);

	res = KSI_setNetworkProvider(ctx, pr);
	CuAssert(tc, "Unable to set network provider.", res == KSI_OK);

	res = KSI_Signature_fromFile(ctx, TEST_SIGNATURE_FILE, &sig);
	CuAssert(tc, "Unable to load signature from file.", res == KSI_OK && sig != NULL);

	setFileMockResponse(tc, "test/resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv");

	res = KSI_extendSignature(ctx, sig, &ext);
	KSI_ERR_statusDump(ctx, stdout);

	CuAssert(tc, "Unable to extend the signature", res == KSI_OK && ext != NULL);
	CuAssert(tc, "Unexpected send request", KSI_NET_MOCK_request_len == sizeof(expectedExtendRequest) && !memcmp(expectedExtendRequest, KSI_NET_MOCK_request, KSI_NET_MOCK_request_len));

	res = KSI_Signature_serialize(ext, &serialized, &serialized_len);
	CuAssert(tc, "Unable to serialize extended signature", res == KSI_OK && serialized != NULL && serialized_len > 0);

	/* Read in the expected result */
	f = fopen("test/resource/tlv/ok-sig-2014-04-30.1-extended.ksig", "rb");
	CuAssert(tc, "Unable to read expected result file", f != NULL);
	expected_len = fread(expected, 1, sizeof(expected), f);
	fclose(f);

	CuAssertIntEquals_Msg(tc, "Expected result length", expected_len, serialized_len);
	CuAssert(tc, "Unexpected extended signature.", !memcmp(expected, serialized, expected_len));

	KSI_free((unsigned char *)KSI_NET_MOCK_response);
	KSI_free(serialized);
	KSI_NET_MOCK_response = NULL;

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	KSI_Signature_free(ext);

}

CuSuite* KSI_NET_GetSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestSendAggregateRequest);
	SUITE_ADD_TEST(suite, TestSendExtendRequest);

	return suite;
}

