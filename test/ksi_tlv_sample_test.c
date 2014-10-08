#include <string.h>

#include "all_tests.h"


static char *ok_sample[] = {
		"test/resource/tlv/ok_int-1.tlv",
		"test/resource/tlv/ok_int-2.tlv",
		"test/resource/tlv/ok_int-3.tlv",
		"test/resource/tlv/ok_int-4.tlv",
		"test/resource/tlv/ok_int-5.tlv",
		"test/resource/tlv/ok_int-6.tlv",
		"test/resource/tlv/ok_int-7.tlv",
		"test/resource/tlv/ok_int-8.tlv",
		"test/resource/tlv/ok_int-9.tlv",
		"test/resource/tlv/ok_nested-1.tlv",
		"test/resource/tlv/ok_nested-2.tlv",
		"test/resource/tlv/ok_nested-3.tlv",
		"test/resource/tlv/ok_nested-4.tlv",
		"test/resource/tlv/ok_nested-5.tlv",
		"test/resource/tlv/ok_nested-6.tlv",
		"test/resource/tlv/ok_nested-7.tlv",
		"test/resource/tlv/ok_nested-8.tlv",
		"test/resource/tlv/ok_nested-9.tlv",
		"test/resource/tlv/ok_str-1.tlv",
		"test/resource/tlv/ok_str-2.tlv",
		"test/resource/tlv/ok_str-3.tlv",
		"test/resource/tlv/ok_str-4.tlv",
		"test/resource/tlv/ok_str-5.tlv",
		"test/resource/tlv/ok_str-6.tlv",
		"test/resource/tlv/ok_str-7.tlv",
		NULL
};

static char *nok_sample[] = {
		"test/resource/tlv/nok_int-1.tlv",
		"test/resource/tlv/nok_int-2.tlv",
		"test/resource/tlv/nok_int-3.tlv",
		"test/resource/tlv/nok_int-4.tlv",
		"test/resource/tlv/nok_str-1.tlv",
		NULL
};

extern KSI_CTX *ctx;

static int tlvFromFile(char *fileName, KSI_TLV **tlv) {
	int res;
	KSI_RDR *rdr = NULL;

	KSI_LOG_debug(ctx, "Open TLV file: '%s'", fileName);

	res = KSI_RDR_fromFile(ctx, fileName, "rb", &rdr);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TLV_fromReader(rdr, tlv);
	if (res != KSI_OK) goto cleanup;

cleanup:

	KSI_RDR_close(rdr);

	return res;
}

static int parseStructure(KSI_TLV *tlv, int indent) {
	int res;
	uint64_t uint;
	const char *buf;
	KSI_TLV *nested = NULL;
	KSI_LIST(KSI_TLV) *list = NULL;
	size_t i;

	switch (KSI_TLV_getTag(tlv)) {
		case 0x01:
			/* Cast as numeric TLV */
			res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_INT);
			if (res != KSI_OK) goto cleanup;

			/* Parse number */
			res = KSI_TLV_getUInt64Value(tlv, &uint);
			if (res != KSI_OK) goto cleanup;
			break;
		case 0x02:
			/* Cast as string TLV */
			res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_STR);
			if (res != KSI_OK) goto cleanup;
			/* Parse string */
			res = KSI_TLV_getStringValue(tlv, &buf);
			if (res != KSI_OK) goto cleanup;
			break;
		case 0x03:
		case 0x1003:
			/* Cast as nested TLV */
			res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_TLV);
			if (res != KSI_OK) goto cleanup;

			res = KSI_TLV_getNestedList(tlv, &list);
			if (res != KSI_OK) goto cleanup;

			/* Parse nested */
			for (i = 0; i < KSI_TLVList_length(list); i++) {
				res = KSI_TLVList_elementAt(list, i, &nested);
				if (res != KSI_OK) goto cleanup;

				if (nested == NULL) break;

				res = parseStructure(nested, indent);
				if (res != KSI_OK) goto cleanup;
			}
			break;
		default:
			res = KSI_INVALID_FORMAT;
			goto cleanup;
	}

cleanup:

	return res;
}

static void TestOkFiles(CuTest* tc) {
	int res;
	int i = 0;

	KSI_TLV *tlv = NULL;

	KSI_ERR_clearErrors(ctx);

	while (ok_sample[i] != NULL) {
		CuAssert(tc, "Unable to read valid TLV", tlvFromFile(ok_sample[i++], &tlv) == KSI_OK);

		res = parseStructure(tlv, 0);

		CuAssert(tc, "Unable to parse valid TLV", res == KSI_OK);

		KSI_TLV_free(tlv);
		tlv = NULL;

		break;
	}
}

static void TestNokFiles(CuTest* tc) {
	int res;
	int i = 0;

	KSI_TLV *tlv = NULL;

	KSI_ERR_clearErrors(ctx);

	while (nok_sample[i] != NULL) {
		res = tlvFromFile(nok_sample[i++], &tlv);

		if (res == KSI_OK) {
			res = parseStructure(tlv, 0);
		}

		CuAssert(tc, "Parser did not fail with invalid TLV", res != KSI_OK);

		KSI_TLV_free(tlv);
		tlv = NULL;
	}
}

static void TestSerialize(CuTest* tc) {
	int res;
	KSI_TLV *tlv = NULL;

	unsigned char in[0xffff + 4];
	unsigned char out[0xffff + 4];
	char errstr[1024];

	unsigned out_len;
	size_t in_len;

	FILE *f = NULL;
	int i = 0;

	KSI_ERR_clearErrors(ctx);

	while (ok_sample[i] != NULL) {
		KSI_LOG_debug(ctx, "TestSerialize: opening file '%s'", ok_sample[i]);
		f = fopen(ok_sample[i], "rb");
		CuAssert(tc, "Unable to open test file.", f != NULL);

		in_len = fread(in, 1, sizeof(in), f);

		fclose(f);
		f = NULL;

		res = KSI_TLV_parseBlob2(ctx, in, in_len, 0, &tlv);
		CuAssert(tc, "Unable to parse TLV", res == KSI_OK);

		res = parseStructure(tlv, 0);
		CuAssert(tc, "Unable to parse TLV structure", res == KSI_OK);

		/* Re assemble TLV */
		KSI_TLV_serialize_ex(tlv, out, sizeof(out), &out_len);

		CuAssert(tc, "Serialized TLV size mismatch", in_len == out_len);
		sprintf(errstr, "Serialised TLV content does not match original: %s", ok_sample[i]);
		CuAssert(tc, errstr, !memcmp(in, out, in_len));

		KSI_TLV_free(tlv);
		tlv = NULL;
		i++;
	}
}

static void TestClone(CuTest *tc) {
	int res;
	KSI_TLV *tlv = NULL;
	KSI_TLV *clone = NULL;

	unsigned char in[0xffff + 4];
	unsigned char out1[0xffff + 4];
	char errstr[1024];

	unsigned out_len;
	size_t in_len;

	FILE *f = NULL;
	int i = 0;

	KSI_ERR_clearErrors(ctx);

	while (ok_sample[i] != NULL) {
		f = fopen(ok_sample[i], "rb");
		CuAssert(tc, "Unable to open test file.", f != NULL);

		in_len = fread(in, 1, sizeof(in), f);

		fclose(f);
		f = NULL;

		res = KSI_TLV_parseBlob2(ctx, in, in_len, 0, &tlv);
		CuAssert(tc, "Unable to parse TLV", res == KSI_OK);

		res = parseStructure(tlv, 0);
		CuAssert(tc, "Unable to parse TLV structure", res == KSI_OK);

		res = KSI_TLV_clone(tlv, &clone);
		CuAssert(tc, "Unsable to clone TLV", res == KSI_OK && clone != NULL);

		/* Re assemble TLV */
		res = KSI_TLV_serialize_ex(clone, out1, sizeof(out1), &out_len);
		CuAssert(tc, "Unable to serialize TLV", res == KSI_OK);

		CuAssert(tc, "Serialized TLV size mismatch", in_len == out_len);
		sprintf(errstr, "Serialised TLV content does not match original: %s", ok_sample[i]);
		CuAssert(tc, errstr, !memcmp(in, out1, in_len));

		KSI_TLV_free(clone);
		clone = NULL;

		KSI_TLV_free(tlv);
		tlv = NULL;
		i++;
	}
}

static void testObjectSerialization(CuTest *tc, const char *sample, int (*parse)(KSI_CTX *, unsigned char *, unsigned, void **), int (*serialize)(void *, unsigned char **, unsigned *), void (*objFree)(void *)) {
	int res;
	void *pdu = NULL;
	unsigned char in[0xffff + 4];
	unsigned in_len;
	unsigned char *out = NULL;
	unsigned out_len;
	FILE *f = NULL;

	f = fopen(sample, "rb");
	CuAssert(tc, "Unable to open pdu file.", f != NULL);

	in_len = fread(in, 1, sizeof(in), f);
	fclose(f);
	CuAssert(tc, "Unable to read pdu.", in_len > 0);

	res = parse(ctx, in, in_len, &pdu);
	CuAssert(tc, "Unable to parse 1st pdu.", res == KSI_OK && pdu != NULL);

	res = serialize(pdu, &out, &out_len);
	CuAssert(tc, "Unable to serialize 1st pdu", res == KSI_OK && out != NULL && out_len > 0);

	CuAssert(tc, "Serialized pdu length mismatch.", in_len == out_len);
	CuAssert(tc, "Serialised pdu content mismatch.", !KSITest_memcmp(in, out, in_len));

	KSI_free(out);
	objFree(pdu);
}

static void aggregationPduTest(CuTest *tc) {
	testObjectSerialization(tc, "test/resource/tlv/ok-sig-2014-07-01.1-aggr_response_ordered.tlv",
			(int (*)(KSI_CTX *, unsigned char *, unsigned, void **))KSI_AggregationPdu_parse,
			(int (*)(void *, unsigned char **, unsigned *))KSI_AggregationPdu_serialize,
			( void (*)(void *))KSI_AggregationPdu_free);
}

static void extendPduTest(CuTest *tc) {
	testObjectSerialization(tc, "test/resource/tlv/ok-sig-2014-04-30.1-extend_response.tlv",
			(int (*)(KSI_CTX *, unsigned char *, unsigned, void **))KSI_ExtendPdu_parse,
			(int (*)(void *, unsigned char **, unsigned *))KSI_ExtendPdu_serialize,
			( void (*)(void *))KSI_ExtendPdu_free);
}


CuSuite* KSITest_TLV_Sample_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestOkFiles);
	SUITE_ADD_TEST(suite, TestNokFiles);
	SUITE_ADD_TEST(suite, TestSerialize);
	SUITE_ADD_TEST(suite, TestClone);
	SUITE_ADD_TEST(suite, aggregationPduTest);
	SUITE_ADD_TEST(suite, extendPduTest);

	return suite;
}
