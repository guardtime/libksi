#include <stdio.h>
#include <string.h>

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"

void TestTlvInitOwnMem(CuTest* tc) {
	KSI_CTX *ctx = NULL;
	KSI_TLV *tlv = NULL;
	int res;

	KSI_CTX_new(&ctx);

	res = KSI_TLV_new(ctx, NULL, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV buffer is null.", tlv->buffer != NULL);

	CuAssert(tc, "TLV encoding is wrong.", tlv->encoding == KSI_TLV_ENC_RAW);

	CuAssert(tc, "TLV raw does not point to buffer.", tlv->encode.rawVal.ptr != tlv->buffer);

	KSI_TLV_free(tlv);
	KSI_CTX_free(ctx);
}

CuSuite* KSI_TLV_GetSuite(void)
{
	CuSuite* suite = CuSuiteNew();

//	SUITE_ADD_TEST(suite, TestRdrFileBadFileName);

	return suite;
}
