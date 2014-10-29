#include <string.h>

#include "internal.h"

struct KSI_OctetString_st {
	KSI_CTX *ctx;
	unsigned char *data;
	unsigned int data_len;
};

struct KSI_Integer_st {
	int staticAlloc;
	int refCount;
	KSI_uint64_t value;
};

/**
 * KSI_OctetString
 */
void KSI_OctetString_free(KSI_OctetString *t) {
	if(t != NULL) {
		KSI_free(t->data);
		KSI_free(t);
	}
}

struct KSI_Utf8String_st {
	KSI_CTX *ctx;
	char *value;
	size_t len;
	int refCount;
};

/**
 *  A static pool for immutable #KSI_Integer object values in range 0..f
 */
static KSI_Integer integerPool[] = {
		{1, 0, 0x00}, {1, 0, 0x01}, {1, 0, 0x02}, {1, 0, 0x03},
		{1, 0, 0x04}, {1, 0, 0x05}, {1, 0, 0x06}, {1, 0, 0x07},
		{1, 0, 0x08}, {1, 0, 0x09}, {1, 0, 0x0a}, {1, 0, 0x0b},
		{1, 0, 0x0c}, {1, 0, 0x0d}, {1, 0, 0x0e}, {1, 0, 0x0f}
};

KSI_IMPLEMENT_LIST(KSI_Integer, KSI_Integer_free);
KSI_IMPLEMENT_LIST(KSI_Utf8String, KSI_Utf8String_free);
KSI_IMPLEMENT_LIST(KSI_Utf8StringNZ, KSI_Utf8String_free);
KSI_IMPLEMENT_LIST(KSI_OctetString, KSI_OctetString_free);

int KSI_OctetString_new(KSI_CTX *ctx, const unsigned char *data, unsigned int data_len, KSI_OctetString **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_OctetString *tmp = NULL;

	tmp = KSI_new(KSI_OctetString);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->data = NULL;
	tmp->data_len = data_len;

	tmp->data = KSI_calloc(data_len, 1);
	if (tmp->data == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	memcpy(tmp->data, data, data_len);

	*t = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_OctetString_free(tmp);
	return res;
}

int KSI_OctetString_extract(const KSI_OctetString *t, const unsigned char **data, unsigned int *data_len) {
	int res = KSI_UNKNOWN_ERROR;

	if(t == NULL || data == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	*data = t->data;
	*data_len = t->data_len;

	res = KSI_OK;

cleanup:

	 return res;
}

int KSI_OctetString_equals(const KSI_OctetString *left, const KSI_OctetString *right) {
	return left != NULL && right != NULL && left->data_len == right->data_len && !memcmp(left->data, right->data, left->data_len);
}

int KSI_OctetString_fromTlv(KSI_TLV *tlv, KSI_OctetString **oct) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	const unsigned char *raw = NULL;
	unsigned int raw_len = 0;
	KSI_OctetString *tmp = NULL;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, oct != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_RAW);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_OctetString_new(ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*oct = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(ctx);
	KSI_nofree(raw);
	KSI_OctetString_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_OctetString_toTlv(KSI_CTX *ctx, KSI_OctetString *oct, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;

	KSI_PRE(&err, oct != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_setRawValue(tmp, oct->data, oct->data_len);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

int verifyUtf8(const unsigned char *str, unsigned len) {
	int res = KSI_UNKNOWN_ERROR;
    size_t i = 0;
    size_t j = 0;
    size_t charContinuationLen = 0;

    while (i < len) {
        j = i;
        if (i + 1 != len && str[i] == 0) {
        	/* The string contains a '\0' byte where not allowed. */
        	res = KSI_INVALID_FORMAT;
        	goto cleanup;
        } else if (str[i] <= 0x7f)
            charContinuationLen = 0;
        else if (str[i] >= 0xc0 /*11000000*/ && str[i] <= 0xdf /*11011111*/)
            charContinuationLen = 1;
        else if (str[i] >= 0xe0 /*11100000*/ && str[i] <= 0xef /*11101111*/)
            charContinuationLen = 2;
        else if (str[i] >= 0xf0 /*11110000*/ && str[i] <= 0xf4 /* Cause of RFC 3629 */)
            charContinuationLen = 3;
        else {
        	res = KSI_INVALID_FORMAT;
        	goto cleanup;
        }
        if (i + charContinuationLen >= len) {
        	res = KSI_BUFFER_OVERFLOW;
        	goto cleanup;
        }

        ++i;

        while (i < len && charContinuationLen > 0
               && str[i] >= 0x80 /*10000000*/ && str[i] <= 0xbf /*10111111*/) {
            ++i;
            --charContinuationLen;
        }
        if (charContinuationLen != 0) {
        	res = KSI_INVALID_FORMAT;
        	goto cleanup;
        }
    }

    res = KSI_OK;

cleanup:

    return res;
}
/**
 * Utf8String
 */
void KSI_Utf8String_free(KSI_Utf8String *t) {
	if (t != NULL && --t->refCount == 0) {
		KSI_free(t->value);
		KSI_free(t);
	}
}

int KSI_Utf8String_new(KSI_CTX *ctx, const unsigned char *str, unsigned len, KSI_Utf8String **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Utf8String *tmp = NULL;
	char *val = NULL;
	unsigned actualLen = len;

	tmp = KSI_new(KSI_Utf8String);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->value = NULL;
	tmp->refCount = 1;
	
	/* Verify that is is a null-terminated string. */
	if (actualLen == 0 || str[actualLen - 1] != '\0') {
		++actualLen;
	}

	/* Verify correctness of utf-8 */
	res = verifyUtf8(str, actualLen);
	if (res != KSI_OK) goto cleanup;

	val = KSI_malloc(actualLen);
	memcpy(val, str, len);
	val[actualLen - 1] = '\0';

	tmp->value = val;
	tmp->len = actualLen;

	val = NULL;

	*t = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:

	KSI_free(val);
	KSI_Utf8String_free(tmp);
	return res;
}

size_t KSI_Utf8String_size(const KSI_Utf8String *t) {
	return t != NULL ? t->len : 0;
}

const char *KSI_Utf8String_cstr(const KSI_Utf8String *t) {
	return t == NULL ? NULL : t->value;
}

int KSI_Utf8String_fromTlv(KSI_TLV *tlv, KSI_Utf8String **u8str) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	const unsigned char *cstr = NULL;
	KSI_Utf8String *tmp = NULL;
	unsigned len;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, u8str != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_getRawValue(tlv, &cstr, &len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_Utf8String_new(ctx, cstr, len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*u8str = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(ctx);
	KSI_nofree(cstr);
	KSI_Utf8String_free(tmp);

	return KSI_RETURN(&err);
}
int KSI_Utf8String_toTlv(KSI_CTX *ctx, KSI_Utf8String *u8str, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;

	KSI_PRE(&err, u8str != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_setRawValue(tmp, u8str->value, u8str->len);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_Utf8StringNZ_fromTlv(KSI_TLV *tlv, KSI_Utf8String **u8str) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	const unsigned char *cstr = NULL;
	KSI_Utf8String *tmp = NULL;
	unsigned len;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, u8str != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	res = KSI_Utf8String_fromTlv(tlv, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	if (tmp->len == 0 || (tmp->len == 1 && tmp->value[0] == 0)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Empty string value not allowed.");
		goto cleanup;
	}

	*u8str = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(ctx);
	KSI_nofree(cstr);
	KSI_Utf8String_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_Utf8StringNZ_toTlv(KSI_CTX *ctx, KSI_Utf8String *u8str, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;

	KSI_PRE(&err, u8str != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (u8str->len == 0 || (u8str->len == 1 && u8str->value[0] == 0)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Empty string value not allowed.");
		goto cleanup;
	}

	res = KSI_Utf8String_toTlv(ctx, u8str, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}


int KSI_Utf8String_clone(KSI_Utf8String *u8str, KSI_Utf8String **clone){
	KSI_ERR err;
	
	KSI_PRE(&err, u8str != NULL) goto cleanup;
	KSI_PRE(&err, clone != NULL) goto cleanup;
	KSI_BEGIN(u8str->ctx, &err);
	
	((KSI_Utf8String*)u8str)->refCount++;
	
	*clone = u8str;
	
	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}


void KSI_Integer_free(KSI_Integer *kint) {
	if (kint != NULL && !kint->staticAlloc && --kint->refCount == 0) {
		KSI_free(kint);
	}
}

int KSI_Integer_clone(KSI_Integer *val, KSI_Integer **clone) {
	int res = KSI_UNKNOWN_ERROR;

	if (val == NULL || clone == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Update ref count only when not statically allocated object. */
	if (!val->staticAlloc) {
		val->refCount++;
	}

	*clone = val;

	res = KSI_OK;

cleanup:

	return res;
}

char *KSI_Integer_toDateString(const KSI_Integer *kint, char *buf, unsigned buf_len) {
	char *ret = NULL;
	time_t pubTm;
	struct tm tm;

	pubTm = (time_t)kint->value;

	gmtime_r(&pubTm, &tm);

	strftime(buf, buf_len, "%Y-%m-%d %H:%M:%S UTC", &tm);

	ret = buf;

	return ret;
}

int KSI_Integer_getSize(const KSI_Integer *kint, unsigned *size) {
	int res = KSI_UNKNOWN_ERROR;
	if (kint == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	*size = KSI_UINT64_MINSIZE(kint->value);

	res = KSI_OK;

cleanup:

	return res;
}

KSI_uint64_t KSI_Integer_getUInt64(const KSI_Integer *kint) {
	return kint != NULL ? kint->value : 0;
}

int KSI_Integer_equals(const KSI_Integer *a, const KSI_Integer *b) {
	return a != NULL && b != NULL && (a == b || a->value == b->value);
}

int KSI_Integer_equalsUInt(const KSI_Integer *o, KSI_uint64_t i) {
	return o != NULL && o->value == i;
}

int KSI_Integer_compare(const KSI_Integer *a, const KSI_Integer *b) {
	if (a == b) return 0;
	if (a == NULL && b != NULL) return -1;
	if (a != NULL && b == NULL) return 1;
	if (a->value > b->value)
		return 1;
	else if (a->value < b->value)
		return -1;
	else
		return 0;
}

int KSI_Integer_new(KSI_CTX *ctx, KSI_uint64_t value, KSI_Integer **ksiInteger) {
	KSI_ERR err;
	KSI_Integer *tmp = NULL;
	static size_t poolSize = sizeof(integerPool) / sizeof(KSI_Integer);

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, ksiInteger != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (value < poolSize) {
		tmp = integerPool + value;
	} else {
		tmp = KSI_new(KSI_Integer);
		if (tmp == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		tmp->staticAlloc = 0;
		tmp->value = value;
		tmp->refCount = 1;
	}

	*ksiInteger = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Integer_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_Integer_fromTlv(KSI_TLV *tlv, KSI_Integer **ksiInteger) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	KSI_Integer *tmp = NULL;
	const unsigned char *raw = NULL;
	unsigned len;
	unsigned i;
	KSI_uint64_t val = 0;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, ksiInteger != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_getRawValue(tlv, &raw, &len);
	KSI_CATCH(&err, res) goto cleanup;

	if (len > 8) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Integer larger than 64bit");
		goto cleanup;
	}

	for (i = 0; i < len; i++) {
		val = val << 8 | raw[i];
	}

	res = KSI_Integer_new(ctx, val, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

 	*ksiInteger = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(ctx);
	KSI_Integer_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_Integer_toTlv(KSI_CTX *ctx, KSI_Integer *integer, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;
	unsigned char raw[8];
	unsigned len = 0;
	KSI_uint64_t val = integer->value;

	KSI_PRE(&err, integer != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	while (val != 0) {
		raw[7 - len++] = val & 0xff;
		val >>= 8;
	}

	if (len > 0) {
		res = KSI_TLV_setRawValue(tmp, raw + 8 - len, len);
		KSI_CATCH(&err, res) goto cleanup;
	}

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}
