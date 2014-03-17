#include <stdio.h>
#include <string.h>

#include "all_tests.h"

extern KSI_CTX *ctx;

static void TestTlvInitOwnMem(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, 0x11, 1, 1, NULL, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV not marked as lenient", tlv->isLenient);
	CuAssert(tc, "TLV not marked to be forwarded", tlv->isForwardable);

	CuAssert(tc, "TLV buffer is null.", tlv->buffer != NULL);

	CuAssert(tc, "TLV encoding is wrong.", tlv->payloadType == KSI_TLV_PAYLOAD_RAW);

	CuAssert(tc, "TLV raw does not point to buffer.", tlv->payload.rawVal.ptr == tlv->buffer);

	KSI_TLV_free(tlv);
}

static void TestTlvLenientFlag(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x11, 1, 1, NULL, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV not marked as lenient", tlv->isLenient);

	KSI_TLV_free(tlv);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x11, 0, 1, NULL, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV marked as lenient", !tlv->isLenient);

	KSI_TLV_free(tlv);
}

static void TestTlvForwardFlag(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x11, 1, 1, NULL, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV not marked to be forwarded", tlv->isForwardable);

	KSI_TLV_free(tlv);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x11, 0, 0, NULL, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV marked to be forwarded", !tlv->isForwardable);

	KSI_TLV_free(tlv);
}

static void TestTlvInitExtMem(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	unsigned char tmp[0xff];

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx,KSI_TLV_PAYLOAD_RAW, 0x12, 0, 0, tmp, sizeof(tmp), 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV buffer is not null.", tlv->buffer == NULL);

	CuAssert(tc, "TLV encoding is wrong.", tlv->payloadType == KSI_TLV_PAYLOAD_RAW);

	CuAssert(tc, "TLV raw does not point to external memory.", tlv->payload.rawVal.ptr == tmp);

	KSI_TLV_free(tlv);
}

static void TestTlv8FromReader(CuTest* tc) {
	int res;
	/* TLV type = 7, length = 21 */
	char raw[] = "\x07\x15THIS IS A TLV CONTENT";

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, 1, &rdr);
	CuAssert(tc, "Failed to create reader.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	CuAssertIntEquals_Msg(tc, "TLV length", 21, tlv->payload.rawVal.length);
	CuAssertIntEquals_Msg(tc, "TLV type", 7, tlv->tag);

	CuAssert(tc, "TLV content differs", !memcmp(tlv->payload.rawVal.ptr, raw + 2, tlv->payload.rawVal.length));

	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void TestTlv8getRawValueCopy(CuTest* tc) {
	int res;
	/* TLV type = 7, length = 21 */
	unsigned char raw[] = "\x07\x15THIS IS A TLV CONTENT";
	unsigned char *tmp = NULL;
	int tmp_len = sizeof(tmp);

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, 1, &rdr);
	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	res = KSI_TLV_getRawValue(tlv, &tmp, &tmp_len, 1);
	CuAssert(tc, "Failed to retrieve raw value.", res == KSI_OK);

	CuAssertIntEquals_Msg(tc, "TLV payload length", 21, tmp_len);

	/* Make sure the pointer does not point to the original. */
	CuAssert(tc, "Data pointer points to original value.", tmp != tlv->payload.rawVal.ptr);


	CuAssert(tc, "TLV content differs", !memcmp(tmp, raw + 2, tmp_len));

	/* Change the value. */
	++*tmp;

	CuAssert(tc, "Original value changed.", memcmp(tmp, tlv->payload.rawVal.ptr, tmp_len));

	KSI_free(tmp);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void TestTlv8getRawValueSharedMem(CuTest* tc) {
	int res;
	/* TLV type = 7, length = 21 */
	unsigned char raw[] = "\x07\x15THIS IS A TLV CONTENT";
	unsigned char *tmp = NULL;
	int tmp_len = sizeof(tmp);

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, 1, &rdr);
	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	res = KSI_TLV_getRawValue(tlv, &tmp, &tmp_len, 0);
	CuAssert(tc, "Failed to retrieve raw value.", res == KSI_OK);

	CuAssertIntEquals_Msg(tc, "TLV payload length", 21, tmp_len);

	/* Make sure the pointer *does* point to the original. */
	CuAssert(tc, "Data pointer points to original value.", tmp == tlv->payload.rawVal.ptr);

	/* Change the value. */
	++*tmp;

	CuAssert(tc, "Original value did not changed.", !memcmp(tmp, tlv->payload.rawVal.ptr, tmp_len));

	KSI_nofree(tmp);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void TestTlv16FromReader(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21 */
	char raw[] = "\x82\xaa\x00\x15THIS IS A TLV CONTENT";

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, 1, &rdr);

	CuAssert(tc, "Failed to create reader.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	CuAssertIntEquals_Msg(tc, "TLV length", 21, tlv->payload.rawVal.length);
	CuAssertIntEquals_Msg(tc, "TLV type", 0x2aa, tlv->tag);

	CuAssert(tc, "TLV content differs", !memcmp(tlv->payload.rawVal.ptr, raw + 4, tlv->payload.rawVal.length));

	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void TestTlvGetUint64(CuTest* tc) {
	int res;
	/* TLV type = 1a, length = 8 */
	unsigned char raw[] = {0x1a, 0x08, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xfa, 0xce};
	uint64_t value;

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	KSI_RDR_fromMem(ctx, raw, sizeof(raw), 1, &rdr);
	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_INT);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getUInt64Value(tlv, &value);
	CuAssert(tc, "Parsing uint64 failed.", res == KSI_OK);

	CuAssert(tc, "Parsed value is not correct.", value == 0xcafebabecafeface);

	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void TestTlvGetUint64Overflow(CuTest* tc) {
	int res;
	/* TLV type = 1a, length = 8 */
	unsigned char raw[] = {0x1a, 0x09, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xfa, 0xce, 0xee};
	uint64_t value;

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw), 1, &rdr);
	CuAssert(tc, "Failed to create reader from memory buffer.", res == KSI_OK && rdr != NULL);


	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	res = KSI_TLV_getUInt64Value(tlv, &value);
	CuAssert(tc, "Parsing uint64 with overflow should not succeed.", res != KSI_OK);

	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void TestTlvGetStringValue(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21 */
	char raw[] = "\x82\xaa\x00\x0alore ipsum";
	char *str = NULL;

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	CuAssert(tc, "Unable to create context", res == KSI_OK && ctx != NULL);

	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, 1, &rdr);
	CuAssert(tc, "Unable to create reader.", res == KSI_OK && rdr != NULL);
	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Unable to create TLV from reader.", res == KSI_OK && tlv != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_STR);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getStringValue(tlv, &str, 0);
	CuAssert(tc, "Failed to get string value from tlv.", res == KSI_OK && str != NULL);
	CuAssert(tc, "TLV payload type not string.", tlv->payloadType == KSI_TLV_PAYLOAD_STR);

	CuAssert(tc, "Returned value does not point to original value.", str == tlv->payload.rawVal.ptr);

	CuAssert(tc, "Returned string is not what was expected", !strcmp("lore ipsum", str));

	KSI_nofree(str);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void TestTlvGetStringValueCopy(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21 */
	char raw[] = "\x82\xaa\x00\x0alore ipsum";
	char *str = NULL;

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, 1, &rdr);
	CuAssert(tc, "Unable to create reader.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Unable to create TLV from reader.", res == KSI_OK && tlv != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_STR);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getStringValue(tlv, &str, 1);
	CuAssert(tc, "Failed to get string value from tlv.", res == KSI_OK && str != NULL);

	CuAssert(tc, "Returned value *does* point to original value.", str != (char *)tlv->payload.rawVal.ptr);

	CuAssert(tc, "Returned string is not what was expected", !strcmp("lore ipsum", str));

	KSI_free(str);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void TestTlvGetNextNested(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21 */
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	char *str = NULL;

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;
	KSI_TLV *nested = NULL;
	uint64_t uint;

	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, 1, &rdr);
	CuAssert(tc, "Unable to create reader.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Unable to read TLV.", res == KSI_OK && tlv != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_TLV);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getNextNestedTLV(tlv, &nested);
	CuAssert(tc, "Unable to read nested TLV", res == KSI_OK && nested != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(nested, KSI_TLV_PAYLOAD_STR);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getStringValue(nested, &str, 1);
	CuAssert(tc, "Unable to read string from nested TLV", res == KSI_OK && str != NULL);
	CuAssert(tc, "Unexpected string from nested TLV.", !strcmp("THIS IS A TLV CONTENT", str));

	res = KSI_TLV_getNextNestedTLV(tlv, &nested);
	CuAssert(tc, "Unable to read nested TLV", res == KSI_OK && nested != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(nested, KSI_TLV_PAYLOAD_INT);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getUInt64Value(nested, &uint);
	CuAssert(tc, "Unable to read uint from nested TLV", res == KSI_OK);
	CuAssert(tc, "Unexpected uint value from nested TLV", 0xcafffffffffe == uint);

	res = KSI_TLV_getNextNestedTLV(tlv, &nested);
	CuAssert(tc, "Reading nested TLV failed after reading last TLV.", res == KSI_OK);
	CuAssert(tc, "Nested element should have been NULL", nested == NULL);

	KSI_free(str);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);

}

static void TestTlvGetNextNestedSharedMemory(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21 */
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	char *str = NULL;

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;
	KSI_TLV *nested = NULL;
	uint64_t uint;

	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, 1, &rdr);
	CuAssert(tc, "Unable to create reader.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Unable to read TLV.", res == KSI_OK && tlv != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_TLV);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getNextNestedTLV(tlv, &nested);
	CuAssert(tc, "Unable to read nested TLV", res == KSI_OK && nested != NULL);
	CuAssert(tc, "Nested TLV buffer is not NULL", nested->buffer == NULL);
	CuAssert(tc, "Nested TLV memory area out of parent buffer.",
			nested->payload.rawVal.ptr > tlv->buffer && nested->payload.rawVal.ptr <= tlv->buffer + tlv->buffer_size );

	res = KSI_TLV_getNextNestedTLV(tlv, &nested);
	CuAssert(tc, "Unable to read nested TLV", res == KSI_OK && nested != NULL);
	CuAssert(tc, "Nested TLV buffer is not NULL", nested->buffer == NULL);
	CuAssert(tc, "Nested TLV memory area out of parent buffer.",
			nested->payload.rawVal.ptr > tlv->buffer && nested->payload.rawVal.ptr <= tlv->buffer + tlv->buffer_size );

	res = KSI_TLV_getNextNestedTLV(tlv, &nested);
	CuAssert(tc, "Reading nested TLV failed after reading last TLV.", res == KSI_OK);
	CuAssert(tc, "Nested element should have been NULL", nested == NULL);


	KSI_free(str);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void TestTlvSerializeString(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21 */
	char raw[] = "\x82\xaa\x00\x0alore ipsum";
	char *str = NULL;
	int buf_len;
	unsigned char buf[0xffff];

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	CuAssert(tc, "Unable to create context", res == KSI_OK && ctx != NULL);

	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, 1, &rdr);
	CuAssert(tc, "Unable to create reader.", res == KSI_OK && rdr != NULL);
	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Unable to create TLV from reader.", res == KSI_OK && tlv != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_STR);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getStringValue(tlv, &str, 0);
	CuAssert(tc, "Failed to get string value from tlv.", res == KSI_OK && str != NULL);

	res = KSI_TLV_serialize_ex(tlv, buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Failed to serialize string TLV", res == KSI_OK);
	CuAssertIntEquals_Msg(tc, "Size of serialized TLV", sizeof(raw) - 1, buf_len);

	CuAssert(tc, "Serialized TLV does not match original", !memcmp(raw, buf, buf_len));

	KSI_nofree(str);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void TestTlvSerializeUint(CuTest* tc) {
	int res;
	/* TLV type = 1a, length = 8 */
	unsigned char raw[] = {0x1a, 0x08, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xfa, 0xce};
	uint64_t value;
	int buf_len;
	unsigned char buf[0xffff];

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;

	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw), 1, &rdr);
	CuAssert(tc, "Failed to create reader from memory buffer.", res == KSI_OK && rdr != NULL);


	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Failed to create TLV from reader.", res == KSI_OK && tlv != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_INT);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getUInt64Value(tlv, &value);
	CuAssert(tc, "Parsing uint64 with overflow should not succeed.", res == KSI_OK);

	res = KSI_TLV_serialize_ex(tlv, buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Failed to serialize string value of tlv.", res == KSI_OK);
	CuAssertIntEquals_Msg(tc, "Size of serialized TLV", sizeof(raw), buf_len);

	CuAssert(tc, "Serialized value does not match", !debug_memcmp(raw, buf, buf_len));

	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);
}

static void TestTlvSerializeNested(CuTest* tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	char *str = NULL;
	int buf_len;
	unsigned char buf[0xffff];

	KSI_ERR_clearErrors(ctx);

	KSI_RDR *rdr = NULL;
	KSI_TLV *tlv = NULL;
	KSI_TLV *nested = NULL;
	uint64_t uint;

	res = KSI_RDR_fromMem(ctx, raw, sizeof(raw) - 1, 1, &rdr);
	CuAssert(tc, "Unable to create reader.", res == KSI_OK && rdr != NULL);

	res = KSI_TLV_fromReader(rdr, &tlv);
	CuAssert(tc, "Unable to read TLV.", res == KSI_OK && tlv != NULL);

	/* Cast payload type */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_TLV);
	CuAssert(tc, "TLV cast failed", res == KSI_OK);

	res = KSI_TLV_getNextNestedTLV(tlv, &nested);
	CuAssert(tc, "Unable to read nested TLV", res == KSI_OK && nested != NULL);
	CuAssert(tc, "Nested TLV buffer is not NULL", nested->buffer == NULL);

	res = KSI_TLV_serialize_ex(tlv, buf, sizeof(buf), &buf_len);

	CuAssert(tc, "Failed to serialize nested values of tlv.", res == KSI_OK);
	CuAssertIntEquals_Msg(tc, "Size of serialized TLV", sizeof(raw) - 1, buf_len);

	CuAssert(tc, "Serialized value does not match original", !debug_memcmp(raw, buf, buf_len));

	KSI_free(str);
	KSI_TLV_free(tlv);
	KSI_RDR_close(rdr);

}

static void TestTlvRequireCast(CuTest* tc) {
	int res;

	KSI_TLV *tlv = NULL;
	KSI_TLV *nested = NULL;

	unsigned char *ptr = NULL;
	int len;
	uint64_t uintval;

	unsigned char raw[] = "\x07\x06QWERTY";

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Unable to create TLV", res == KSI_OK && tlv != NULL);

	/* Should not fail */
	res = KSI_TLV_getRawValue(tlv, &ptr, &len, 0);
	CuAssert(tc, "Failed to get raw value without a cast", res == KSI_OK && ptr != NULL);
	ptr = NULL;

	/* Should fail. */
	res = KSI_TLV_getStringValue(tlv, (char **)&ptr, 0);
	CuAssert(tc, "Got string value without a cast", res != KSI_OK);
	ptr = NULL;

	/* Should fail. */
	res = KSI_TLV_getUInt64Value(tlv, &uintval);
	CuAssert(tc, "Got uint value without a cast", res != KSI_OK);
	ptr = NULL;

	/* Should fail. */
	res = KSI_TLV_getNextNestedTLV(tlv, &nested);
	CuAssert(tc, "Got nested TLV without a cast", res != KSI_OK);
	ptr = NULL;


	/* Cast as string */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_STR);
	CuAssert(tc, "Failed to cast TLV to nested string.", res == KSI_OK);

	/* After cast, this should not fail */
	res = KSI_TLV_getStringValue(tlv, &ptr, 0);
	CuAssert(tc, "Failed to get string value after a cast to string", res == KSI_OK);
	ptr = NULL;

	/* Should fail */
	res = KSI_TLV_getRawValue(tlv, &ptr, &len, 0);
	CuAssert(tc, "Got raw value after a cast to string", res != KSI_OK);
	ptr = NULL;

	KSI_TLV_free(tlv);
	KSI_nofree(nested);
}

static void TestTlvParseBlobFailWithExtraData(CuTest* tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x07\x06QWERTYU";

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Blob with extra data was parsed into TLV", res != KSI_OK && tlv == NULL);

	KSI_TLV_free(tlv);
}


static void TestTlvFromUint(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;
	uint64_t val;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_fromUint(ctx, 0x13, 0, 0, 0xabcde, &tlv);
	CuAssert(tc, "Unable to create TLV from uint value.", res == KSI_OK && tlv != NULL);

	CuAssertIntEquals_Msg(tc, "Uint length", 3, tlv->payload.uintVal.length);

	res = KSI_TLV_getUInt64Value(tlv, &val);
	CuAssert(tc, "Wrong value from TLV", val == 0xabcde);

	/* Cast to raw and back */
	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_RAW);
	CuAssert(tc, "Unable to cast from uint to raw", res == KSI_OK);

	CuAssertIntEquals_Msg(tc, "Raw tlv payload lenght", 3, tlv->payload.rawVal.length);

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_INT);
	CuAssert(tc, "Unable to cast from raw to uint", res == KSI_OK);
	CuAssertIntEquals_Msg(tc, "Uint length (after casts)", 3, tlv->payload.uintVal.length);
	res = KSI_TLV_getUInt64Value(tlv, &val);
	CuAssert(tc, "Wrong value from TLV (after casts)", val == 0xabcde);

	KSI_TLV_free(tlv);
}

static void TestTlvComposeNested(CuTest* tc) {
	KSI_TLV *outer = NULL;
	KSI_TLV *nested = NULL;
	unsigned char raw[] = {0x01, 0x06, 0x61, 0x04, 0xca, 0xfe, 0xba, 0xbe};
	int buf_len;
	unsigned char buf[0xffff];
	int res;

	KSI_ERR_clearErrors(ctx);

	/* Create an empty outer TLV */
	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, 0x1, 0, 0, NULL, 0, 0, &outer);
	CuAssert(tc, "Unable to create TLV", res == KSI_OK && outer != NULL);

	res = KSI_TLV_cast(outer, KSI_TLV_PAYLOAD_TLV);
	CuAssert(tc, "Unable to cast outer TLV payload type to 'nested'", res == KSI_OK);

	/* Create nested TLV and append to the outer TLV*/
	res = KSI_TLV_fromUint(ctx, 0x01, 1, 1, 0xcafebabe, &nested);
	CuAssert(tc, "Unable to create nested TLV from uint", res == KSI_OK && nested != NULL);

	res = KSI_TLV_appendNestedTLV(outer, NULL, nested);
	CuAssert(tc, "Unable to append nested TLV.", res == KSI_OK);

	res = KSI_TLV_serialize_ex(outer, buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Unable to serialize outer TLV.", res == KSI_OK);
	CuAssertIntEquals_Msg(tc, "Size of serialized data", sizeof(raw), buf_len);
	CuAssert(tc, "Unexpected serialized data", !memcmp(raw, buf, buf_len));

	KSI_nofree(nested);
	KSI_TLV_free(outer);

}

static void TestTlvComposeNestedMore(CuTest* tc) {
	KSI_TLV *outer = NULL;
	KSI_TLV *nested = NULL;
	unsigned char raw[] = {0x01, 0x0a, 0x61, 0x04, 0xca, 0xfe, 0xba, 0xbe, 0x61, 0x02, 0x47, 0x54 };
	int buf_len;
	unsigned char buf[0xffff];
	int res;

	KSI_ERR_clearErrors(ctx);

	/* Create an empty outer TLV */
	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, 0x1, 0, 0, NULL, 0, 0, &outer);
	CuAssert(tc, "Unable to create TLV", res == KSI_OK && outer != NULL);

	res = KSI_TLV_cast(outer, KSI_TLV_PAYLOAD_TLV);
	CuAssert(tc, "Unable to cast outer TLV payload type to 'nested'", res == KSI_OK);

	/* Create nested TLV and append to the outer TLV*/
	res = KSI_TLV_fromUint(ctx, 0x01, 1, 1, 0xcafebabe, &nested);
	CuAssert(tc, "Unable to create nested TLV from uint", res == KSI_OK && nested != NULL);

	res = KSI_TLV_appendNestedTLV(outer, NULL, nested);
	CuAssert(tc, "Unable to append first nested TLV.", res == KSI_OK);

	/* Create nested TLV and append to the outer TLV*/
	res = KSI_TLV_fromString(ctx, 0x01, 1, 1, "GT", &nested);
	CuAssert(tc, "Unable to create nested TLV from uint", res == KSI_OK && nested != NULL);

	res = KSI_TLV_appendNestedTLV(outer, NULL, nested);
	CuAssert(tc, "Unable to append first nested TLV.", res == KSI_OK);

	res = KSI_TLV_serialize_ex(outer, buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Unable to serialize outer TLV.", res == KSI_OK);
	CuAssertIntEquals_Msg(tc, "Size of serialized data", sizeof(raw), buf_len);
	CuAssert(tc, "Unexpected serialized data", !debug_memcmp(raw, buf, buf_len));

	KSI_nofree(nested);
	KSI_TLV_free(outer);

}

CuSuite* KSI_TLV_GetSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestTlvInitOwnMem);
	SUITE_ADD_TEST(suite, TestTlvInitExtMem);
	SUITE_ADD_TEST(suite, TestTlv8FromReader);
	SUITE_ADD_TEST(suite, TestTlv8getRawValueCopy);
	SUITE_ADD_TEST(suite, TestTlv8getRawValueSharedMem);
	SUITE_ADD_TEST(suite, TestTlv16FromReader);
	SUITE_ADD_TEST(suite, TestTlvGetUint64);
	SUITE_ADD_TEST(suite, TestTlvGetUint64Overflow);
	SUITE_ADD_TEST(suite, TestTlvGetStringValue);
	SUITE_ADD_TEST(suite, TestTlvGetStringValueCopy);
	SUITE_ADD_TEST(suite, TestTlvGetNextNested);
	SUITE_ADD_TEST(suite, TestTlvGetNextNestedSharedMemory);
	SUITE_ADD_TEST(suite, TestTlvSerializeString);
	SUITE_ADD_TEST(suite, TestTlvSerializeUint);
	SUITE_ADD_TEST(suite, TestTlvSerializeNested);
	SUITE_ADD_TEST(suite, TestTlvRequireCast);
	SUITE_ADD_TEST(suite, TestTlvLenientFlag);
	SUITE_ADD_TEST(suite, TestTlvForwardFlag);
	SUITE_ADD_TEST(suite, TestTlvFromUint);
	SUITE_ADD_TEST(suite, TestTlvComposeNested);
	SUITE_ADD_TEST(suite, TestTlvComposeNestedMore);
	SUITE_ADD_TEST(suite, TestTlvParseBlobFailWithExtraData);

	return suite;
}
