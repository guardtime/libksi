#include <string.h>
#include "all_tests.h"

extern KSI_CTX *ctx;
extern unsigned char *KSI_NET_MOCK_request;
extern int KSI_NET_MOCK_request_len;
extern const unsigned char *KSI_NET_MOCK_response;
extern int KSI_NET_MOCK_response_len;


static unsigned char someImprint[] ={
		0x01, 0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06, 0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc,
		0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6, 0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d};

static unsigned char expectedSendRequest[] = {
		0x82, 0x00, 0x00, 0x27, 0x82, 0x01, 0x00, 0x23, 0x03, 0x21, 0x01, 0x11, 0xa7, 0x00, 0xb0, 0xc8, 0x06,
		0x6c, 0x47, 0xec, 0xba, 0x05, 0xed, 0x37, 0xbc, 0x14, 0xdc, 0xad, 0xb2, 0x38, 0x55, 0x2d, 0x86, 0xc6,
		0x59, 0x34, 0x2d, 0x1d, 0x7e, 0x87, 0xb8, 0x77, 0x2d};

static void TestSendRequest(CuTest* tc) {
	int res;
	KSI_DataHash *hsh = NULL;
	KSI_Signature *sig = NULL;
	KSI_NetProvider *pr = NULL;
	FILE *f = NULL;
	unsigned char *resp = NULL;
	int resp_size = 0xfffff;

	KSI_ERR_clearErrors(ctx);

	resp = KSI_calloc(resp_size, 1);
	CuAssert(tc, "Out of memory", resp != NULL);

	res = KSI_NET_MOCK_new(ctx, &pr);
	CuAssert(tc, "Unable to create mock network provider.", res == KSI_OK);

	res = KSI_CTX_setNetworkProvider(ctx, pr);
	CuAssert(tc, "Unable to set network provider.", res == KSI_OK);

	res = KSI_DataHash_fromImprint(ctx, someImprint, sizeof(someImprint), &hsh);
	CuAssert(tc, "Unable to create data hash object from raw imprint", res == KSI_OK && hsh != NULL);

	/* Read valid response */
	f = fopen("test/resource/tlv/ok_aggr_response-1.tlv", "rb");
	CuAssert(tc, "Unable to open sample response file", f != NULL);

	KSI_NET_MOCK_response_len = fread(resp, 1, resp_size, f);
	fclose(f);

	KSI_NET_MOCK_response = resp;


	res = KSI_Signature_sign(hsh, &sig);
	CuAssert(tc, "Unable to sign the hash", res == KSI_OK && sig != NULL);
	CuAssert(tc, "Unexpected send request", KSI_NET_MOCK_request_len == sizeof(expectedSendRequest) && !memcmp(expectedSendRequest, KSI_NET_MOCK_request, KSI_NET_MOCK_request_len));

	KSI_NET_MOCK_response = NULL;
	KSI_free(resp);

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
}

CuSuite* KSI_NET_GetSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestSendRequest);

	return suite;
}

