/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

#include <stdio.h>
#include <string.h>

#include <ksi/hashchain.h>
#include <ksi/io.h>
#include <ksi/tlv.h>
#include <ksi/tlv_element.h>
#include <ksi/tlv_template.h>

#include "all_tests.h"

#include "../src/ksi/impl/signature_impl.h"

extern KSI_CTX *ctx;

static void testTlvInitOwnMem(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx, 0x11, 1, 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV not marked as lenien.", KSI_TLV_isNonCritical(tlv));
	CuAssert(tc, "TLV not marked to be forwarded.", KSI_TLV_isForward(tlv));

	KSI_TLV_free(tlv);
}

static void testTlvLenientFlag(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx, 0x11, 1, 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV not marked as lenient.", KSI_TLV_isNonCritical(tlv));

	KSI_TLV_free(tlv);

	res = KSI_TLV_new(ctx, 0x11, 0, 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV marked as lenient.", !KSI_TLV_isNonCritical(tlv));

	KSI_TLV_free(tlv);
}

static void testTlvForwardFlag(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx, 0x11, 1, 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV not marked to be forwarded.", KSI_TLV_isForward(tlv));

	KSI_TLV_free(tlv);

	res = KSI_TLV_new(ctx, 0x11, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	CuAssert(tc, "TLV marked to be forwarded.", !KSI_TLV_isForward(tlv));

	KSI_TLV_free(tlv);
}

static void testTlvSetRaw(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	unsigned char tmp[0xff] = { 0xaa, 0xbb, 0xcc, 0xdd };
	const unsigned char *val = NULL;
	size_t val_len = 0;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx, 0x12, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	res = KSI_TLV_setRawValue(tlv, tmp, sizeof(tmp));
	CuAssert(tc, "Failed to set raw value.", res == KSI_OK);

	res = KSI_TLV_getRawValue(tlv, &val, &val_len);
	CuAssert(tc, "Failed to get raw value.", res == KSI_OK);

	CuAssert(tc, "Raw value mismatch.", val_len == sizeof(tmp) && !memcmp(val, tmp, val_len));

	KSI_TLV_free(tlv);
}

static void testTlvSetRawAsNull(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	unsigned char *tmp = NULL;
	const unsigned char *val = NULL;
	size_t val_len = 0;
	unsigned char tmp_not_null[2] = {0x01, 0x02};

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx, 0x12, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	res = KSI_TLV_setRawValue(tlv, tmp, 0);
	CuAssert(tc, "Failed to set raw value.", res == KSI_OK);

	res = KSI_TLV_getRawValue(tlv, &val, &val_len);
	CuAssert(tc, "Failed to get raw value.", res == KSI_OK);
	CuAssert(tc, "Raw value mismatch.", val_len == 0 && val == NULL);


	res = KSI_TLV_setRawValue(tlv, tmp_not_null, 0);
	CuAssert(tc, "Failed to set raw value.", res == KSI_OK);

	res = KSI_TLV_getRawValue(tlv, &val, &val_len);
	CuAssert(tc, "Failed to get raw value.", res == KSI_OK);
	CuAssert(tc, "Raw value mismatch.", val_len == 0 && val == NULL);


	res = KSI_TLV_setRawValue(tlv, tmp, 2);
	CuAssert(tc, "Set NULL value with length greater than 0 must fail.", res == KSI_INVALID_ARGUMENT);


	KSI_TLV_free(tlv);
}

static void testParseTlv8(CuTest* tc) {
	int res;
	/* TLV type = 7, length = 21. */
	unsigned char raw[] = "\x07\x15THIS IS A TLV CONTENT";
	KSI_FTLV ftlv;

	res = KSI_FTLV_memRead(raw, sizeof(raw) - 1, &ftlv);
	CuAssert(tc, "Failed to parse TLV8.", res == KSI_OK);

	CuAssert(tc, "TLV length mismatch.", 21 == ftlv.dat_len);
	CuAssert(tc, "TLV type mismatch.", 7 == ftlv.tag);

	CuAssert(tc, "Unexpected header length.", ftlv.hdr_len == 2);
}

static void testParseTlv16(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21. */
	unsigned char raw[] = "\x82\xaa\x00\x15THIS IS A TLV CONTENT";
	KSI_FTLV ftlv;

	KSI_ERR_clearErrors(ctx);

	res = KSI_FTLV_memRead(raw, sizeof(raw) - 1, &ftlv);
	CuAssert(tc, "Failed to parse TLV16.", res == KSI_OK);

	CuAssert(tc, "TLV length mismatch.", 21 == ftlv.dat_len);
	CuAssert(tc, "TLV type mismatch.", 0x2aa == ftlv.tag);

	CuAssert(tc, "Unexpected header length.", 4 == ftlv.hdr_len);
}

static void testTlvGetUint64(CuTest* tc) {
	int res;
	/* TLV type = 1a, length = 8. */
	unsigned char raw[] = {0x1a, 0x08, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xfa, 0xce};

	KSI_TLV *tlv = NULL;
	KSI_Integer *integer = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw), &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_Integer_fromTlv(tlv, &integer);
	CuAssert(tc, "Parsing uint64 failed.", res == KSI_OK);

	CuAssert(tc, "Parsed value is not correct.", KSI_Integer_getUInt64(integer) == 0xcafebabecafefacell);

	KSI_TLV_free(tlv);
	KSI_Integer_free(integer);
}

static void testTlvGetUint64Overflow(CuTest* tc) {
	int res;
	/* TLV type = 1a, length = 8. */
	unsigned char raw[] = {0x1a, 0x09, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xfa, 0xce, 0xee};

	KSI_TLV *tlv = NULL;
	KSI_Integer *integer = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw), &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_Integer_fromTlv(tlv, &integer);
	CuAssert(tc, "Parsing uint64 with overflow should not succeed.", res != KSI_OK);

	KSI_Integer_free(integer);
	KSI_TLV_free(tlv);
}

static void testTlvGetStringValue(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21. */
	unsigned char raw[] = "\x82\xaa\x00\x0blore ipsum\0";
	KSI_Utf8String *utf = NULL;
	KSI_TLV *tlv = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_Utf8String_fromTlv(tlv, &utf);
	CuAssert(tc, "Failed to get string value from tlv.", res == KSI_OK && utf != NULL);

	CuAssert(tc, "Returned string is not what was expected.", !strcmp("lore ipsum", KSI_Utf8String_cstr(utf)));

	KSI_Utf8String_free(utf);
	KSI_TLV_free(tlv);
}

static void testTlvGetNextNested(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21. */
	unsigned char raw[] = "\x01\x20" "\x07\x16" "THIS IS A TLV CONTENT\0" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";

	KSI_TLV *tlv = NULL;
	KSI_TLV *nested = NULL;
	unsigned i = 0;
	KSI_LIST(KSI_TLV) *list = NULL;
	KSI_Utf8String *utf = NULL;
	KSI_Integer *integer = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_TLV_getNestedList(tlv, &list);
	CuAssert(tc, "Unable to get nested list from TLV.", res == KSI_OK && list != NULL);

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Unable to read nested TLV.", res == KSI_OK && nested != NULL);

	res = KSI_Utf8String_fromTlv(nested, &utf);
	CuAssert(tc, "Unable to read string from nested TLV.", res == KSI_OK && utf != NULL);
	CuAssert(tc, "Unexpected string from nested TLV.", !strcmp("THIS IS A TLV CONTENT", KSI_Utf8String_cstr(utf)));

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Unable to read nested TLV.", res == KSI_OK && nested != NULL);

	res = KSI_Integer_fromTlv(nested, &integer);
	CuAssert(tc, "Unable to read uint from nested TLV.", res == KSI_OK);
	CuAssert(tc, "Unexpected uint value from nested TLV.", 0xcafffffffffell == KSI_Integer_getUInt64(integer));

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Reading nested TLV did not fail after reading last TLV.", res == KSI_BUFFER_OVERFLOW);

	KSI_Integer_free(integer);
	KSI_Utf8String_free(utf);
	KSI_TLV_free(tlv);

}

static void testTlvGetNextNestedSharedMemory(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21. */
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	char *str = NULL;

	KSI_TLV *tlv = NULL;
	KSI_TLV *nested = NULL;
	KSI_LIST(KSI_TLV) *list = NULL;
	unsigned i = 0;

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_TLV_getNestedList(tlv, &list);
	CuAssert(tc, "Unable to get nested list from TLV.", res == KSI_OK && list != NULL);

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Unable to read nested TLV.", res == KSI_OK && nested != NULL);

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Unable to read nested TLV.", res == KSI_OK && nested != NULL);

	res = KSI_TLVList_elementAt(list, i++, &nested);
	CuAssert(tc, "Reading nested TLV did not fail after reading last TLV.", res == KSI_BUFFER_OVERFLOW);


	KSI_free(str);
	KSI_TLV_free(tlv);
}

static void testTlvSerializeString(CuTest* tc) {
	int res;
	/* TLV16 type = 0x2aa, length = 21. */
	unsigned char raw[] = "\x82\xaa\x00\x0blore ipsum\0";
	size_t buf_len;
	unsigned char buf[0xffff];
	KSI_Utf8String *utf = NULL;

	KSI_TLV *tlv = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_Utf8String_fromTlv(tlv, &utf);
	CuAssert(tc, "Failed to get string value from TLV.", res == KSI_OK && utf != NULL);

	res = KSI_TLV_serialize_ex(tlv, buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Failed to serialize string TLV.", res == KSI_OK);
	CuAssert(tc, "Size of serialized TLV mismatch.", sizeof(raw) - 1 == buf_len);

	CuAssert(tc, "Serialized TLV does not match original.", !memcmp(raw, buf, buf_len));

	KSI_Utf8String_free(utf);
	KSI_TLV_free(tlv);
}

static void testTlvSerializeUint(CuTest* tc) {
	int res;
	/* TLV type = 1a, length = 8. */
	unsigned char raw[] = {0x1a, 0x08, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe, 0xfa, 0xce};
	size_t buf_len;
	unsigned char buf[0xffff];

	KSI_TLV *tlv = NULL;
	KSI_Integer *integer = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw), &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_Integer_fromTlv(tlv, &integer);
	CuAssert(tc, "Parsing uint64 with overflow should not succeed.", res == KSI_OK);

	res = KSI_TLV_serialize_ex(tlv, buf, sizeof(buf), &buf_len);
	CuAssert(tc, "Failed to serialize string value of tlv.", res == KSI_OK);
	CuAssert(tc, "Size of serialized TLV mismatch.", sizeof(raw) == buf_len);

	CuAssert(tc, "Serialized value does not match.", !memcmp(raw, buf, buf_len));

	KSI_Integer_free(integer);
	KSI_TLV_free(tlv);
}

static void testTlvSerializeNested(CuTest* tc) {
	int res;
	unsigned char raw[] = "\x01\x1f" "\x07\x15" "THIS IS A TLV CONTENT" "\x7\x06" "\xca\xff\xff\xff\xff\xfe";
	char *str = NULL;
	size_t buf_len;
	unsigned char buf[0xffff];


	KSI_TLV *tlv = NULL;
	KSI_TLV *nested = NULL;
	KSI_LIST(KSI_TLV) *list = NULL;

	KSI_ERR_clearErrors(ctx);
	res = KSI_TLV_parseBlob(ctx, raw, sizeof(raw) - 1, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_TLV_getNestedList(tlv, &list);
	CuAssert(tc, "Unable to get nested list from TLV.", res == KSI_OK && list != NULL);

	res = KSI_TLVList_elementAt(list, 0, &nested);
	CuAssert(tc, "Unable to read nested TLV.", res == KSI_OK && nested != NULL);

	res = KSI_TLV_serialize_ex(tlv, buf, sizeof(buf), &buf_len);

	CuAssert(tc, "Failed to serialize nested values of tlv.", res == KSI_OK);
	CuAssert(tc, "Size of serialized TLV mismatch.", sizeof(raw) - 1 == buf_len);

	CuAssert(tc, "Serialized value does not match original.", !KSITest_memcmp(raw, buf, buf_len));

	KSI_free(str);
	KSI_TLV_free(tlv);

}

KSI_IMPORT_TLV_TEMPLATE(KSI_Signature);

static void testTlvSerializeMandatoryListObjectEmpty(CuTest *tc) {
#define TEST_SIGNATURE_FILE "resource/tlv/ok-sig-2014-04-30.1.ksig"

	int res;
	KSI_Signature *sig = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;
	KSI_AggregationHashChain *aggr = NULL;
	KSI_HashChainLinkList *chain = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_Signature_fromFile(ctx, getFullResourcePath(TEST_SIGNATURE_FILE), &sig);
	CuAssert(tc, "Unable to read signature from file.", res == KSI_OK && sig != NULL);

	res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, 0, &aggr);
	CuAssert(tc, "Unable to aggregation hash chain at 0.", res == KSI_OK && aggr != NULL);

	res = KSI_AggregationHashChain_getChain(aggr, &chain);
	CuAssert(tc, "Unable to hash chain link list.", res == KSI_OK && chain != NULL);

	while (KSI_HashChainLinkList_length(chain) != 0) {
		KSI_HashChainLinkList_remove(chain, 0, NULL);
	}
	CuAssert(tc, "List contains elements.", KSI_HashChainLinkList_length(chain) == 0);

	res = KSI_TlvTemplate_serializeObject(ctx, sig, 0x0800, 0, 0, KSI_TLV_TEMPLATE(KSI_Signature), &raw, &raw_len);
	CuAssert(tc, "Signature serialization should fail.", res == KSI_INVALID_FORMAT && raw_len == 0);

	KSI_free(raw);
	KSI_Signature_free(sig);

#undef TEST_SIGNATURE_FILE
}

static void testTlvParseBlobFailWithExtraData(CuTest* tc) {
	int res;
	KSI_TLV *tlv = NULL;
	unsigned char raw[] = "\x07\x06QWERTYU";

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_parseBlob2(ctx, raw, sizeof(raw) - 1, 0, &tlv);
	CuAssert(tc, "Blob with extra data was parsed into TLV.", res != KSI_OK && tlv == NULL);

	KSI_TLV_free(tlv);
}

static void testBadUtf8(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	unsigned char tmp[] = { 0xff, 0xff, 0xff, 0xff };
	KSI_Utf8String *utf = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx, 0x12, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	res = KSI_TLV_setRawValue(tlv, tmp, sizeof(tmp));
	CuAssert(tc, "Failed to set raw value.", res == KSI_OK);

	res = KSI_Utf8String_fromTlv(tlv, &utf);
	CuAssert(tc, "Blob 0xffffffff should not be a valid UTF-8 string.", res != KSI_OK && utf == NULL);

	KSI_Utf8String_free(utf);
	KSI_TLV_free(tlv);
}

static void testBadUtf8WithZeros(CuTest* tc) {
	KSI_TLV *tlv = NULL;
	int res;

	unsigned char tmp[] = "some\0text";
	KSI_Utf8String *utf = NULL;

	KSI_ERR_clearErrors(ctx);

	res = KSI_TLV_new(ctx, 0x12, 0, 0, &tlv);
	CuAssert(tc, "Failed to create TLV.", res == KSI_OK);
	CuAssert(tc, "Created TLV is NULL.", tlv != NULL);

	res = KSI_TLV_setRawValue(tlv, tmp, sizeof(tmp));
	CuAssert(tc, "Failed to set raw value.", res == KSI_OK);

	res = KSI_Utf8String_fromTlv(tlv, &utf);
	CuAssert(tc, "Blob containing a null character should not be a valid UTF-8 string.", res != KSI_OK && utf == NULL);

	KSI_Utf8String_free(utf);
	KSI_TLV_free(tlv);
}

static void testTlvElementIntegers(CuTest *tc) {
	int res;
	KSI_Integer *in = NULL;
	KSI_Integer *out = NULL;
	KSI_TlvElement *el = NULL;
	struct {
		int tag;
		KSI_uint64_t val;
	} inputs[] = {{0x1fff, 0xcafebabe}, {0x1, 0}, {0x20, 0xffffffffffffffffull}, {0x0, 0x0} };
	size_t i  = 0;

	/* Create the outer tlv element. */
	res = KSI_TlvElement_new(&el);
	CuAssert(tc, "Unable to create plain TlvElement.", res == KSI_OK && el != NULL);

	while (inputs[i].tag != 0x0 && inputs[i].val != 0x0) {
		/* Create the sample value. */
		res = KSI_Integer_new(ctx, inputs[i].val, &in);
		CuAssert(tc, "Unable to create integer value.", res == KSI_OK && in != NULL);

		/* Set the integer value as a sub element. */
		res = KSI_TlvElement_setInteger(el, inputs[i].tag, in);
		CuAssert(tc, "Unable to set an integer as a sub element.", res == KSI_OK);

		/* Extract the integer value. */
		res = KSI_TlvElement_getInteger(el, ctx, inputs[i].tag, &out);
		CuAssert(tc, "Unable to extract an integer from sub elements.", res == KSI_OK);

		CuAssert(tc, "Extracted value does not equal to the input value.", KSI_Integer_equals(in, out));
		CuAssert(tc, "Extracted value does not equal to the expected value.", KSI_Integer_equalsUInt(out, inputs[i].val));

		KSI_Integer_free(in);
		KSI_Integer_free(out);

		i++;
	}

	KSI_TlvElement_free(el);
}

void testTlvElementNested(CuTest *tc) {
	int res;
	unsigned char buf[0xffff + 4];
	size_t len;
	/* # Expected result of this test.
		TLV[1f00]:
			TLV[08]:
				TLV[01]: abcd
				TLV[02]: 1234
			TLV[1600]:
				TLV[03]: 1a2b
				TLV[04]: 11aa
	 */
	unsigned char exp[] = {0x9f, 0x00, 0x00, 0x16, 0x08, 0x08, 0x01, 0x02, 0xab, 0xcd, 0x02, 0x02, 0x12, 0x34, 0x96, 0x00, 0x00, 0x08, 0x03, 0x02, 0x1a, 0x2b, 0x04, 0x02, 0x11, 0xaa};


	KSI_TlvElement *outer = NULL;
	KSI_TlvElement *inner8 = NULL;
	KSI_TlvElement *inner16 = NULL;
	KSI_Integer *sub1 = NULL;
	KSI_Integer *sub2 = NULL;
	KSI_Integer *sub3 = NULL;
	KSI_Integer *sub4 = NULL;


	/* Create the outer (PDU) element. */
	res = KSI_TlvElement_new(&outer);
	CuAssert(tc, "Unable to create TlvElement.", res == KSI_OK && outer != NULL);
	outer->ftlv.tag = 0x1f00;

	/* Create the first nested element. */
	res = KSI_TlvElement_new(&inner8);
	CuAssert(tc, "Unable to create TlvElement.", res == KSI_OK && inner8 != NULL);
	inner8->ftlv.tag = 0x08;

	/* Create the second nested element. */
	res = KSI_TlvElement_new(&inner16);
	CuAssert(tc, "Unable to create TlvElement.", res == KSI_OK && inner16 != NULL);
	inner16->ftlv.tag = 0x1600;

	/* Create randomish elements. */
	res = KSI_Integer_new(ctx, 0xabcd, &sub1);
	CuAssert(tc, "Unable to create KSI_Integer.", res == KSI_OK && sub1 != NULL);

	res = KSI_Integer_new(ctx, 0x1234, &sub2);
	CuAssert(tc, "Unable to create KSI_Integer.", res == KSI_OK && sub2 != NULL);

	res = KSI_Integer_new(ctx, 0x1a2b, &sub3);
	CuAssert(tc, "Unable to create KSI_Integer.", res == KSI_OK && sub3 != NULL);

	res = KSI_Integer_new(ctx, 0x11aa, &sub4);
	CuAssert(tc, "Unable to create KSI_Integer.", res == KSI_OK && sub4 != NULL);

	/* Add the nested elements to the outer element. */
	res = KSI_TlvElement_appendElement(outer, inner8);
	CuAssert(tc, "Unable to append nested element.", res == KSI_OK);
	res = KSI_TlvElement_appendElement(outer, inner16);
	CuAssert(tc, "Unable to append nested element.", res == KSI_OK);

	/* Add nested integer values to the first nested element. */
	res = KSI_TlvElement_setInteger(inner8, 0x01, sub1);
	CuAssert(tc, "Unable to set nested integer.", res == KSI_OK);
	res = KSI_TlvElement_setInteger(inner8, 0x02, sub2);
	CuAssert(tc, "Unable to set nested integer.", res == KSI_OK);

	/* Add nested integer values to the second nested element. */
	res = KSI_TlvElement_setInteger(inner16, 0x03, sub3);
	CuAssert(tc, "Unable to set nested integer.", res == KSI_OK);
	res = KSI_TlvElement_setInteger(inner16, 0x04, sub4);
	CuAssert(tc, "Unable to set nested integer.", res == KSI_OK);

	/* Serialize the structure. */
	res = KSI_TlvElement_serialize(outer, buf, sizeof(buf), &len, 0);

	CuAssert(tc, "Unexpected serialized length.", len == sizeof(exp));
	CuAssert(tc, "Unexpected serialized value.", !KSITest_memcmp(buf, exp, sizeof(exp)));


	KSI_TlvElement_free(outer);
	KSI_TlvElement_free(inner8);
	KSI_TlvElement_free(inner16);
	KSI_Integer_free(sub1);
	KSI_Integer_free(sub2);
	KSI_Integer_free(sub3);
	KSI_Integer_free(sub4);
}

void testTlvElementDetachment(CuTest *tc) {
	int res;
	KSI_TlvElement *tlv = NULL;
	/* # TLV to be parsed and detached.
		TLV[1f00]:
			TLV[08]:
				TLV[01]: abcd
				TLV[02]: 1234
			TLV[1600]:
				TLV[03]: 1a2b
				TLV[04]: 11aa
	 */
	unsigned char buf[] = {0x9f, 0x00, 0x00, 0x16, 0x08, 0x08, 0x01, 0x02, 0xab, 0xcd, 0x02, 0x02, 0x12, 0x34, 0x96, 0x00, 0x00, 0x08, 0x03, 0x02, 0x1a, 0x2b, 0x04, 0x02, 0x11, 0xaa};

	res = KSI_TlvElement_parse(buf, sizeof(buf), &tlv);
	CuAssert(tc, "Unable to parse TLV.", res == KSI_OK && tlv != NULL);
	CuAssert(tc, "TLV not expected to own its buffer.", tlv->ptr == buf && tlv->ptr_own == 0);

	res = KSI_TlvElement_detach(tlv);
	CuAssert(tc, "Unable to detach TLV from its outer resources.", res == KSI_OK);
	CuAssert(tc, "TLV expected to own its buffer.", tlv->ptr != buf && tlv->ptr_own == 1);
	CuAssert(tc, "TLV buffer not properly detached.", tlv->ftlv.hdr_len + tlv->ftlv.dat_len == sizeof(buf) && !memcmp(buf, tlv->ptr, sizeof(buf)));

	KSI_TlvElement_free(tlv);
}

void testTlvElementRemove(CuTest *tc) {
	int res;
	size_t len = 0;
	KSI_TlvElement *subTlv = NULL;
	KSI_TlvElement *tlv = NULL;
	/* # TLV to be parsed.
		TLV[1f00]:
			TLV[08]:
				TLV[01]: abcd
				TLV[02]: 1234
			TLV[1600]:
				TLV[03]: 1a2b
				TLV[04]: 11aa
	 */
	unsigned char tmp[0xffff + 4];
	unsigned char buf[] = {0x9f, 0x00, 0x00, 0x16, 0x08, 0x08, 0x01, 0x02, 0xab, 0xcd, 0x02, 0x02, 0x12, 0x34, 0x96, 0x00, 0x00, 0x08, 0x03, 0x02, 0x1a, 0x2b, 0x04, 0x02, 0x11, 0xaa};
	unsigned char exp1[] = {0x9f, 0x00, 0x00, 0x0a, 0x08, 0x08, 0x01, 0x02, 0xab, 0xcd, 0x02, 0x02, 0x12, 0x34};
	unsigned char exp2[] = {0x9f, 0x00, 0x00, 0x00};
	unsigned char exp3[] = {0x08, 0x08, 0x01, 0x02, 0xab, 0xcd, 0x02, 0x02, 0x12, 0x34};
	unsigned char exp4[] = {0x08, 0x04, 0x02, 0x02, 0x12, 0x34};

	res = KSI_TlvElement_parse(buf, sizeof(buf), &tlv);
	CuAssert(tc, "Unable to parse TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_TlvElement_removeElement(tlv, 0x1600, NULL);
	CuAssert(tc, "Unable to remove child TLV from parent TLV.", res == KSI_OK);

	/* Serialize the remaining TLV. */
	res = KSI_TlvElement_serialize(tlv, tmp, sizeof(tmp), &len, 0);
	CuAssert(tc, "Unable to serialize TLV.", res == KSI_OK);
	CuAssert(tc, "Unexpected TLV contents.", len == sizeof(exp1) && !memcmp(tmp, exp1, sizeof(exp1)));

	res = KSI_TlvElement_removeElement(tlv, 0x08, &subTlv);
	CuAssert(tc, "Unable to remove child TLV from parent TLV.", res == KSI_OK && subTlv != NULL);

	/* Serialize the remaining TLV. */
	res = KSI_TlvElement_serialize(tlv, tmp, sizeof(tmp), &len, 0);
	CuAssert(tc, "Unable to serialize TLV.", res == KSI_OK);
	CuAssert(tc, "Unexpected TLV contents.", len == sizeof(exp2) && !memcmp(tmp, exp2, sizeof(exp2)));

	/* Serialize the removed child TLV. */
	res = KSI_TlvElement_serialize(subTlv, tmp, sizeof(tmp), &len, 0);
	CuAssert(tc, "Unable to serialize TLV.", res == KSI_OK);
	CuAssert(tc, "Unexpected TLV contents.", len == sizeof(exp3) && !memcmp(tmp, exp3, sizeof(exp3)));

	res = KSI_TlvElement_removeElement(subTlv, 0x01, NULL);
	CuAssert(tc, "Unable to remove child TLV from parent TLV.", res == KSI_OK);

	/* Serialize the remaining TLV. */
	res = KSI_TlvElement_serialize(subTlv, tmp, sizeof(tmp), &len, 0);
	CuAssert(tc, "Unable to serialize TLV.", res == KSI_OK);
	CuAssert(tc, "Unexpected TLV contents.", len == sizeof(exp4) && !memcmp(tmp, exp4, sizeof(exp4)));

	KSI_TlvElement_free(subTlv);
	KSI_TlvElement_free(tlv);
}

void testTlvElementRemoveNotExisting(CuTest *tc) {
	int res;
	size_t len = 0;
	KSI_TlvElement *tlv = NULL;
	/* # TLV to be parsed.
		TLV[1f00]:
			TLV[08]:
				TLV[01]: abcd
				TLV[02]: 1234
			TLV[1600]:
				TLV[03]: 1a2b
				TLV[04]: 11aa
	 */
	unsigned char tmp[0xffff + 4];
	unsigned char buf[] = {0x9f, 0x00, 0x00, 0x16, 0x08, 0x08, 0x01, 0x02, 0xab, 0xcd, 0x02, 0x02, 0x12, 0x34, 0x96, 0x00, 0x00, 0x08, 0x03, 0x02, 0x1a, 0x2b, 0x04, 0x02, 0x11, 0xaa};

	res = KSI_TlvElement_parse(buf, sizeof(buf), &tlv);
	CuAssert(tc, "Unable to parse TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_TlvElement_removeElement(tlv, 0x1601, NULL);
	CuAssert(tc, "Removal of not existing child TLV must not be possible.", res == KSI_INVALID_STATE);

	/* Serialize the remaining TLV. */
	res = KSI_TlvElement_serialize(tlv, tmp, sizeof(tmp), &len, 0);
	CuAssert(tc, "Unable to serialize TLV.", res == KSI_OK);
	CuAssert(tc, "Unexpected TLV contents.", len == sizeof(buf) && !memcmp(tmp, buf, sizeof(buf)));

	KSI_TlvElement_free(tlv);
}

void testTlvElementRemoveMultipleSameId(CuTest *tc) {
	int res;
	size_t len = 0;
	KSI_TlvElement *tlv = NULL;
	/* # TLV to be parsed.
		TLV[1f00]:
			TLV[08]:
				TLV[01]: abcd
				TLV[02]: 1234
			TLV[08]:
				TLV[03]: 1a2b
				TLV[04]: 11aa
	 */
	unsigned char tmp[0xffff + 4];
	unsigned char buf[] = {0x9f, 0x00, 0x00, 0x15, 0x08, 0x08, 0x01, 0x02, 0xab, 0xcd, 0x02, 0x02, 0x12, 0x34, 0x08, 0x00, 0x08, 0x03, 0x02, 0x1a, 0x2b, 0x04, 0x02, 0x11, 0xaa};

	res = KSI_TlvElement_parse(buf, sizeof(buf), &tlv);
	CuAssert(tc, "Unable to parse TLV.", res == KSI_OK && tlv != NULL);

	res = KSI_TlvElement_removeElement(tlv, 0x08, NULL);
	CuAssert(tc, "Removal must fail if there is more than one element with same id.", res == KSI_INVALID_STATE);

	/* Serialize the remaining TLV. */
	res = KSI_TlvElement_serialize(tlv, tmp, sizeof(tmp), &len, 0);
	CuAssert(tc, "Unable to serialize TLV.", res == KSI_OK);
	CuAssert(tc, "Unexpected TLV contents.", len == sizeof(buf) && !memcmp(tmp, buf, sizeof(buf)));

	KSI_TlvElement_free(tlv);
}

CuSuite* KSITest_TLV_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testTlvInitOwnMem);
	SUITE_ADD_TEST(suite, testTlvSetRaw);
	SUITE_ADD_TEST(suite, testTlvSetRawAsNull);
	SUITE_ADD_TEST(suite, testParseTlv8);
	SUITE_ADD_TEST(suite, testParseTlv16);
	SUITE_ADD_TEST(suite, testTlvGetUint64);
	SUITE_ADD_TEST(suite, testTlvGetUint64Overflow);
	SUITE_ADD_TEST(suite, testTlvGetStringValue);
	SUITE_ADD_TEST(suite, testTlvGetNextNested);
	SUITE_ADD_TEST(suite, testTlvGetNextNestedSharedMemory);
	SUITE_ADD_TEST(suite, testTlvSerializeString);
	SUITE_ADD_TEST(suite, testTlvSerializeUint);
	SUITE_ADD_TEST(suite, testTlvSerializeNested);
	SUITE_ADD_TEST(suite, testTlvSerializeMandatoryListObjectEmpty);
	SUITE_ADD_TEST(suite, testTlvLenientFlag);
	SUITE_ADD_TEST(suite, testTlvForwardFlag);
	SUITE_ADD_TEST(suite, testTlvParseBlobFailWithExtraData);
	SUITE_ADD_TEST(suite, testBadUtf8);
	SUITE_ADD_TEST(suite, testBadUtf8WithZeros);
	SUITE_ADD_TEST(suite, testTlvElementIntegers);
	SUITE_ADD_TEST(suite, testTlvElementNested);
	SUITE_ADD_TEST(suite, testTlvElementDetachment);
	SUITE_ADD_TEST(suite, testTlvElementRemove);
	SUITE_ADD_TEST(suite, testTlvElementRemoveNotExisting);
	SUITE_ADD_TEST(suite, testTlvElementRemoveMultipleSameId);

	return suite;
}
