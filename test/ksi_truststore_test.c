/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ksi/pkitruststore.h>

#include "cutest/CuTest.h"
#include "all_tests.h"

extern KSI_CTX *ctx;
char tmp_path[1024];

static void TestAddInvalidLookupFile(CuTest *tc) {
	int res;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI trustsore.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, "KSI_ThisFileDoesProbablyNotExist");
	CuAssert(tc, "Adding missing lookup file did not fail.", res != KSI_OK);

}

static void TestAddValidLookupFile(CuTest *tc) {
	int res;
	KSI_PKITruststore *pki = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_CTX_getPKITruststore(ctx, &pki);
	CuAssert(tc, "Unable to get PKI trustsore.", res == KSI_OK && pki != NULL);

	res = KSI_PKITruststore_addLookupFile(pki, getFullResourcePath("resource/tlv/mock.crt"));
	CuAssert(tc, "Adding correct lookup file did fail.", res == KSI_OK);

}


CuSuite* KSITest_Truststore_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestAddInvalidLookupFile);
	SUITE_ADD_TEST(suite, TestAddValidLookupFile);

	return suite;
}
