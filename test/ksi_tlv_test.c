#include <stdio.h>
#include <string.h>

#include "all_tests.h"

extern KSI_CTX *ctx;

static void testTlvInitOwnMem(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, 0x11, 1, 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV not marked as lenient", KSI_TLV_isNonCritical(tlv));
	CuAssert(tc, "TLV not marked to be forwarded", KSI_TLV_isForward(tlv));

	KSI_TLV_free(tlv);
}

static void testTlvLenientFlag(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x11, 1, 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV not marked as lenient", KSI_TLV_isNonCritical(tlv));

	KSI_TLV_free(tlv);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x11, 0, 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV marked as lenient", !KSI_TLV_isNonCritical(tlv));

	KSI_TLV_free(tlv);
}

static void testTlvForwardFlag(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x11, 1, 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV not marked to be forwarded", KSI_TLV_isForward(tlv));

	KSI_TLV_free(tlv);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x11, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV marked to be forwarded", !KSI_TLV_isForward(tlv));

	KSI_TLV_free(tlv);
}

static void testTlvSetRaw(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	unsigned char tmp[0xff] = { 0xaa, 0xbb, 0xcc, 0xdd };
	const unsigned char *val = NULL;
	unsigned val_len = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x12, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	res = KSI_TLV_setRawValue(tlv, tmp, sizeof(tmp));
	CuAssert(tc, "Failed to set raw value", res == KSI_OK);

	res = KSI_TLV_getRawValue(tlv, &val, &val_len);
	CuAssert(tc, "Failed to get raw value", res == KSI_OK);

	CuAssert(tc, "Raw value mismatch", val_len == sizeof(tmp) && !memcmp(val, tmp, val_len));

	KSI_TLV_free(tlv);
}

static void testTlv8FromReader(CuTest* tc) {
	int res;
	/* TLV type = 7, length = 21 */
	unsigned char raw[] = "\x07\x15THIS IS A TLV CONTENT";
	const unsigned char *val = NULL;
	unsigned val_len = 0;


	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, &rdr);
	CuAssert(tc, "Failed to create reader.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	res = KSI_TLV_getRawValue(tlv, &val, &val_len);
	CuAssert(tc, "Unable to get raw value", res == KSI_OK);

	CuAssert(tc, "TLV length mismatch", 21 == val_len);
	CuAssert(tc, "TLV type mismatch", 7 == KSI_TLV_getTag(tlv));

	CuAssert(tc, "TLV content differs", !memcmp(val, raw + 2, val_len));

	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void testTlv8getRawValueSharedMem(CuTest* tc) {
	int res;
	/* TLV type = 7, length = 21 */
	unsigned char raw[] = "\x07\x15THIS IS A TLV CONTENT";
	const unsigned char *tmp = NULL;
	unsigned tmp_len = sizeof(tmp);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	KSI_ERR_clearErrors(ctx);

	KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, &rdr);
	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	res = KSI_TLV_getRawValue(tlv, &tmp, &tmp_len);
	CuAssert(tc, "Failed to retrieve raw value.", res == KSI_OK);

	CuAssert(tc, "TLV payload length mismatch", 21 == tmp_len);

	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void testTlv16FromReader(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21 */
	unsigned char raw[] = "\x82\xaa\x00\x15THIS IS A TLV CONTENT";
	const unsigned char *val = NULL;
	unsigned val_len = 0;

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, &rdr);

	CuAssert(tc, "Failed to create reader.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	res = KSI_TLV_getRawValue(tlv, &val, &val_len);
	CuAssert(tc, "Unable to get raw value", res == KSI_OK);

	CuAssert(tc, "TLV length mismatch", 21 == val_len);
	CuAssert(tc, "TLV type mismatch", 0x2aa == KSI_TLV_getTag(tlv));

	CuAssert(tc, "TLV content differs", !memcmp(val, raw + 4, val_len));

	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void testTlvGetUint64(CuTest* tc) {
	int res;
	/* TLV type = 1a, length = 8 */
	unsigned char raw[] = {0x1a, 0x08, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xfa, 0xce};

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;
	KSI_Integer *integer = NULL;

	KSI_ERR_clearErrors(ctx);
	KSI_RDR_fromMem(ctx, raw, sizeof(raw), &rdr);
	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	res = KSI_Integer_fromTlv(tlv, &integer);
	CuAssert(tc, "Parsing uint64 failed.", res == KSI_OK);

	CuAssert(tc, "Parsed value is not correct.", KSI_Integer_getUInt64(integer) == 0xcafebabecafeface);

	KSI_TLV_free(tlv);
	KSI_Integer_free(integer);
	KSI_RDR_close(rdr);
}

static void testTlvGetUint64Overflow(CuTest* tc) {
	int res;
	/* TLV type = 1a, length = 8 */
	unsigned char raw[] = {0x1a, 0x09, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xfa, 0xce, 0xee};

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;
	KSI_Integer *integer = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw), &rdr);
	CuAssert(tc, "Failed to create reader from memory buffer.", res == KSI_OK && rdr != NULL);


	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	res = KSI_Integer_fromTlv(tlv, &integer);
	CuAssert(tc, "Parsing uint64 with overflow should not succeed.", res != KSI_OK);

	KSI_Integer_free(integer);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void testTlvGetStringValue(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21 */
	unsigned char raw[] = "\x82\xaa\x00\x0blore ipsum\0";
	KSI_Utf8String *utf = NULL;
	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, &rdr);
	CuAssert(tc, "Unable to create reader.", res == KSI_OK && rdr != NULL);
	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Unable to create TLV from reader.", res == KSI_OK && tlv != NULL);

	res = KSI_Utf8String_fromTlv(tlv, &utf);
	CuAssert(tc, "Failed to get string value from tlv.", res == KSI_OK && utf != NULL);

	CuAssert(tc, "Returned string is not what was expected", !strcmp("lore ipsum", KSI_Utf8String_cstr(utf)));

	KSI_Utf8String_free(utf);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void testTlvGetNextNested(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21 */
	unsigned char raw[] = "\x01\x20" "\x07\x16" "THIS IS A TLV CONTENT\0" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;
	KSI_TLV *nested = NULL;
	unsigned i = 0;
	KSI_LIST(KSI_TLV) *list = NULL;
	KSI_Utf8String *utf = NULL;
	KSI_Integer *integer = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, &rdr);
	CuAssert(tc, "Unable to create reader.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Unable to read TLV.", res == KSI_OK && tlv != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_TLV);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getNestedList(tlv, &list);
	CuAssert(tc, "Unable to get nested list from TLV.", res == KSI_OK && list != NULL);

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Unable to read nested TLV", res == KSI_OK && nested != NULL);

	res = KSI_Utf8String_fromTlv(nested, &utf);
	CuAssert(tc, "Unable to read string from nested TLV", res == KSI_OK && utf != NULL);
	CuAssert(tc, "Unexpected string from nested TLV.", !strcmp("THIS IS A TLV CONTENT", KSI_Utf8String_cstr(utf)));

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Unable to read nested TLV", res == KSI_OK && nested != NULL);

	res = KSI_Integer_fromTlv(nested, &integer);
	CuAssert(tc, "Unable to read uint from nested TLV", res == KSI_OK);
	CuAssert(tc, "Unexpected uint value from nested TLV", 0xcafffffffffe == KSI_Integer_getUInt64(integer));

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Reading nested TLV did not fail after reading last TLV.", res == KSI_BUFFER_OVERFLOW);

	KSI_Integer_free(integer);
	KSI_Utf8String_free(utf);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);

}

static void testTlvGetNextNestedSharedMemory(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21 */
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	char *str = NULL;


	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;
	KSI_TLV *nested = NULL;
	KSI_LIST(KSI_TLV) *list = NULL;
	unsigned i = 0;

	KSI_ERR_clearErrors(ctx);
	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, &rdr);
	CuAssert(tc, "Unable to create reader.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Unable to read TLV.", res == KSI_OK && tlv != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_TLV);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getNestedList(tlv, &list);
	CuAssert(tc, "Unable to get nested list from TLV.", res == KSI_OK && list != NULL);

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Unable to read nested TLV", res == KSI_OK && nested != NULL);

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Unable to read nested TLV", res == KSI_OK && nested != NULL);

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Reading nested TLV did not fail after reading last TLV.", res == KSI_BUFFER_OVERFLOW);


	KSI_free(str);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void testTlvSerializeString(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21 */
	unsigned char raw[] = "\x82\xaa\x00\x0blore ipsum";
	unsigned buf_len;
	unsigned char buf[0xffff];
	KSI_Utf8String *utf = NULL;

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw), &rdr);
	CuAssert(tc, "Unable to create reader.", res == KSI_OK && rdr != NULL);
	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Unable to create TLV from reader.", res == KSI_OK && tlv != NULL);

	res = KSI_Utf8String_fromTlv(tlv, &utf);
	CuAssert(tc, "Failed to get string value from tlv.", res == KSI_OK && utf != NULL);

	res = KSI_TLV_serialize_ex(tlv, buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Failed to serialize string TLV", res == KSI_OK);
	CuAssert(tc, "Size of serialized TLV mismatch", sizeof(raw) == buf_len);

	CuAssert(tc, "Serialized TLV does not match original", !memcmp(raw, buf, buf_len));

	KSI_Utf8String_free(utf);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void testTlvSerializeUint(CuTest* tc) {
	int res;
	/* TLV type = 1a, length = 8 */
	unsigned char raw[] = {0x1a, 0x08, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xfa, 0xce};
	unsigned buf_len;
	unsigned char buf[0xffff];

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;
	KSI_Integer *integer = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw), &rdr);
	CuAssert(tc, "Failed to create reader from memory buffer.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	res = KSI_Integer_fromTlv(tlv, &integer);
	CuAssert(tc, "Parsing uint64 with overflow should not succeed.", res == KSI_OK);

	res = KSI_TLV_serialize_ex(tlv, buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Failed to serialize string value of tlv.", res == KSI_OK);
	CuAssert(tc, "Size of serialized TLV mismatch", sizeof(raw) == buf_len);

	CuAssert(tc, "Serialized value does not match", !memcmp(raw, buf, buf_len));

	KSI_Integer_free(integer);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void testTlvSerializeNested(CuTest* tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	char *str = NULL;
	unsigned buf_len;
	unsigned char buf[0xffff];


	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;
	KSI_TLV *nested = NULL;
	KSI_LIST(KSI_TLV) *list = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, &rdr);
	CuAssert(tc, "Unable to create reader.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Unable to read TLV.", res == KSI_OK && tlv != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_TLV);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getNestedList(tlv, &list);
	CuAssert(tc, "Unable to get nested list from TLV.", res == KSI_OK && list != NULL);

	res = KSI_TLVList_elementAt(list, 0, &nested);
	CuAssert(tc, "Unable to read nested TLV", res == KSI_OK && nested != NULL);

	res = KSI_TLV_serialize_ex(tlv, buf, sizeof(buf), &buf_len);

	CuAssert(tc, "Failed to serialize nested values of tlv.", res == KSI_OK);
	CuAssert(tc, "Size of serialized TLV mismatch", sizeof(raw) - 1 == buf_len);

	CuAssert(tc, "Serialized value does not match original", !KSITest_memcmp(raw, buf, buf_len));

	KSI_free(str);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);

}

static void testTlvParseBlobFailWithExtraData(CuTest* tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x07\x06QWERTYU";

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_parseBlob2(ctx, raw, sizeof(raw) - 1, 0, &tlv);
	CuAssert(tc, "Blob with extra data was parsed into TLV", res != KSI_OK && tlv == NULL);

	KSI_TLV_free(tlv);
}

static void testBadUtf8(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	unsigned char tmp[] = { 0xff, 0xff, 0xff, 0xff };
	KSI_Utf8String *utf = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x12, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	res = KSI_TLV_setRawValue(tlv, tmp, sizeof(tmp));
	CuAssert(tc, "Failed to set raw value", res == KSI_OK);

	res = KSI_Utf8String_fromTlv(tlv, &utf);
	CuAssert(tc, "Blob 0xffffffff should not be a valid UTF-8 string", res != KSI_OK && utf == NULL);

	KSI_Utf8String_free(utf);
	KSI_TLV_free(tlv);
}

static void testBadUtf8WithZeros(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	unsigned char tmp[] = "some\0text";
	KSI_Utf8String *utf = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x12, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	res = KSI_TLV_setRawValue(tlv, tmp, sizeof(tmp));
	CuAssert(tc, "Failed to set raw value", res == KSI_OK);

	res = KSI_Utf8String_fromTlv(tlv, &utf);
	CuAssert(tc, "Blob containing a null character should not be a valid UTF-8 string", res != KSI_OK && utf == NULL);

	KSI_Utf8String_free(utf);
	KSI_TLV_free(tlv);
}


CuSuite* KSITest_TLV_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testTlvInitOwnMem);
	SUITE_ADD_TEST(suite, testTlvSetRaw);
	SUITE_ADD_TEST(suite, testTlv8FromReader);
	SUITE_ADD_TEST(suite, testTlv8getRawValueSharedMem);
	SUITE_ADD_TEST(suite, testTlv16FromReader);
	SUITE_ADD_TEST(suite, testTlvGetUint64);
	SUITE_ADD_TEST(suite, testTlvGetUint64Overflow);
	SUITE_ADD_TEST(suite, testTlvGetStringValue);
	SUITE_ADD_TEST(suite, testTlvGetNextNested);
	SUITE_ADD_TEST(suite, testTlvGetNextNestedSharedMemory);
	SUITE_ADD_TEST(suite, testTlvSerializeString);
	SUITE_ADD_TEST(suite, testTlvSerializeUint);
	SUITE_ADD_TEST(suite, testTlvSerializeNested);
	SUITE_ADD_TEST(suite, testTlvLenientFlag);
	SUITE_ADD_TEST(suite, testTlvForwardFlag);
	SUITE_ADD_TEST(suite, testTlvParseBlobFailWithExtraData);
	SUITE_ADD_TEST(suite, testBadUtf8);
	SUITE_ADD_TEST(suite, testBadUtf8WithZeros);

	return suite;
}
