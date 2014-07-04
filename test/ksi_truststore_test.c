#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cutest/CuTest.h"
#include "all_tests.h"

extern KSI_CTX *ctx;

static void TestAddInvalidLookupFile(CuTest *tc) {
	int res;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI trustsore.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, "KSI_ThisFileDoesProbablyNotExist");
	CuAssert(tc, "Adding missing lookup file did not fail.", res != KSI_OK);

}

static void TestAddValidLookupFile(CuTest *tc) {
	int res;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI trustsore.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, "test/resource/tlv/mock.crt");
	CuAssert(tc, "Adding correct lookup file did fail.", res == KSI_OK);

}


static void TestAddInvalidLookupDir(CuTest *tc) {
	int res;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI trustsore.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupDir(pki, "KSI_ThisDirDoesProbablyNotExist");
	CuAssert(tc, "Adding missing lookup directory did not fail.", res != KSI_OK);

}

CuSuite* KSITest_Truststore_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestAddInvalidLookupFile);
//	SUITE_ADD_TEST(suite, TestAddInvalidLookupDir);
	SUITE_ADD_TEST(suite, TestAddValidLookupFile);

	return suite;
}
