/*
 * Copyright 2013-2015 Guardtime, Inc.
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

#include <assert.h>
#include <string.h>

#include "internal.h"
#include "tlv.h"

struct KSI_OctetString_st {
	KSI_CTX *ctx;
	size_t refCount;
	unsigned char *data;
	size_t data_len;
};

struct KSI_Integer_st {
	int staticAlloc;
	size_t refCount;
	KSI_uint64_t value;
};

struct KSI_Utf8String_st {
	KSI_CTX *ctx;
	size_t refCount;
	char *value;
	size_t len;
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

/**
 * KSI_OctetString
 */
void KSI_OctetString_free(KSI_OctetString *o) {
	if (o != NULL && --o->refCount == 0) {
		KSI_free(o->data);
		KSI_free(o);
	}
}

int KSI_OctetString_new(KSI_CTX *ctx, const unsigned char *data, size_t data_len, KSI_OctetString **o) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_OctetString *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || (data == NULL && data_len != 0) || o == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_OctetString);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->data = NULL;
	tmp->data_len = data_len;
	tmp->refCount = 1;

	if (data_len > 0) {
		tmp->data = KSI_malloc(data_len);
		if (tmp->data == NULL) {
			KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		memcpy(tmp->data, data, data_len);
	}

	*o = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_OctetString_free(tmp);
	return res;
}

int KSI_OctetString_ref(KSI_OctetString *o) {
	if (o != NULL) {
		++o->refCount;
	}
	return KSI_OK;
}

int KSI_OctetString_extract(const KSI_OctetString *o, const unsigned char **data, size_t *data_len) {
	int res = KSI_UNKNOWN_ERROR;

	if (o == NULL || data == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	*data = o->data;
	*data_len = o->data_len;

	res = KSI_OK;

cleanup:

	 return res;
}

int KSI_OctetString_equals(const KSI_OctetString *left, const KSI_OctetString *right) {
	return left != NULL && right != NULL &&
			((left == right) || (left->data_len == right->data_len && !memcmp(left->data, right->data, left->data_len)));
}

int KSI_OctetString_fromTlv(KSI_TLV *tlv, KSI_OctetString **o) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	const unsigned char *raw = NULL;
	size_t raw_len = 0;
	KSI_OctetString *tmp = NULL;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_ERR_clearErrors(ctx);
	if (tlv == NULL || o == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_RAW);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OctetString_new(ctx, raw, raw_len, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(ctx);
	KSI_nofree(raw);
	KSI_OctetString_free(tmp);

	return res;
}

int KSI_OctetString_toTlv(KSI_CTX *ctx, KSI_OctetString *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || o == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_setRawValue(tmp, o->data, o->data_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tmp);

	return res;
}

static int verifyUtf8(const unsigned char *str, size_t len) {
	int res = KSI_UNKNOWN_ERROR;
    size_t i = 0;
    size_t charContinuationLen = 0;

    while (i < len) {
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
void KSI_Utf8String_free(KSI_Utf8String *o) {
	if (o != NULL && --o->refCount == 0) {
		KSI_free(o->value);
		KSI_free(o);
	}
}

int KSI_Utf8String_new(KSI_CTX *ctx, const char *str, size_t len, KSI_Utf8String **o) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Utf8String *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || str == NULL || o == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_Utf8String);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->value = NULL;
	tmp->refCount = 1;
	
	/* Verify that it is a null-terminated string. */
	if (len == 0 || str[len - 1] != '\0') {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "String value is not null-terminated.");
		goto cleanup;
	}

	/* Verify correctness of utf-8 */
	res = verifyUtf8((const unsigned char *)str, len);
	if (res != KSI_OK) goto cleanup;

	tmp->value = KSI_malloc(len);
	if (tmp->value == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	memcpy(tmp->value, str, len);

	tmp->len = len;

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Utf8String_free(tmp);

	return res;
}

int KSI_Utf8String_ref(KSI_Utf8String *o) {
	if (o != NULL) {
		++o->refCount;
	}
	return KSI_OK;
}

size_t KSI_Utf8String_size(const KSI_Utf8String *o) {
	return o != NULL ? o->len : 0;
}

const char *KSI_Utf8String_cstr(const KSI_Utf8String *o) {
	return o == NULL ? NULL : o->value;
}

int KSI_Utf8String_fromTlv(KSI_TLV *tlv, KSI_Utf8String **o) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	const char *cstr = NULL;
	KSI_Utf8String *tmp = NULL;
	size_t len;

	ctx = KSI_TLV_getCtx(tlv);

	KSI_ERR_clearErrors(ctx);
	if (tlv == NULL || o == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_getRawValue(tlv, (const unsigned char **)&cstr, &len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Utf8String_new(ctx, cstr, len, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(ctx);
	KSI_nofree(cstr);
	KSI_Utf8String_free(tmp);

	return res;
}

int KSI_Utf8String_toTlv(KSI_CTX *ctx, KSI_Utf8String *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || o == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (o->len > 0xffff){
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "UTF8 string too long for TLV conversion.");
		goto cleanup;
	}
	
	res = KSI_TLV_setRawValue(tmp, o->value, (unsigned)o->len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tmp);

	return res;
}

int KSI_Utf8StringNZ_fromTlv(KSI_TLV *tlv, KSI_Utf8String **o) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	const unsigned char *cstr = NULL;
	KSI_Utf8String *tmp = NULL;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_ERR_clearErrors(ctx);
	if (tlv == NULL || o == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_Utf8String_fromTlv(tlv, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (tmp->len == 0 || (tmp->len == 1 && tmp->value[0] == 0)) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Empty string value not allowed.");
		goto cleanup;
	}

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(ctx);
	KSI_nofree(cstr);
	KSI_Utf8String_free(tmp);

	return res;
}

int KSI_Utf8StringNZ_toTlv(KSI_CTX *ctx, KSI_Utf8String *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || o == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (o->len == 0 || (o->len == 1 && o->value[0] == 0)) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Empty string value not allowed.");
		goto cleanup;
	}

	res = KSI_Utf8String_toTlv(ctx, o, tag, isNonCritical, isForward, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tmp);

	return res;
}

void KSI_Integer_free(KSI_Integer *o) {
	if (o != NULL && !o->staticAlloc && --o->refCount == 0) {
		KSI_free(o);
	}
}

int KSI_Integer_ref(KSI_Integer *o) {
	if (o != NULL && !o->staticAlloc) {
		++o->refCount;
	}
	return KSI_OK;
}

char *KSI_Integer_toDateString(const KSI_Integer *o, char *buf, size_t buf_len) {
	char *ret = NULL;
	time_t pubTm;
	struct tm tm;

	pubTm = (time_t)o->value;

	gmtime_r(&pubTm, &tm);

	strftime(buf, buf_len, "%Y-%m-%d %H:%M:%S UTC", &tm);

	ret = buf;

	return ret;
}

KSI_uint64_t KSI_Integer_getUInt64(const KSI_Integer *o) {
	return o != NULL ? o->value : 0;
}

int KSI_Integer_equals(const KSI_Integer *a, const KSI_Integer *b) {
	return a != NULL && b != NULL && (a == b || a->value == b->value);
}

int KSI_Integer_equalsUInt(const KSI_Integer *o, KSI_uint64_t i) {
	return o != NULL && o->value == i;
}

int KSI_Integer_compare(const KSI_Integer *a, const KSI_Integer *b) {
	if (a == b || (a == NULL && b == NULL)) return 0;
	if (a == NULL && b != NULL) return -1;
	if (a != NULL && b == NULL) return 1;
	if (a->value > b->value)
		return 1;
	else if (a->value < b->value)
		return -1;
	else
		return 0;
}

int KSI_Integer_new(KSI_CTX *ctx, KSI_uint64_t value, KSI_Integer **o) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *tmp = NULL;
	static size_t poolSize = sizeof(integerPool) / sizeof(KSI_Integer);

	KSI_ERR_clearErrors(ctx);
	if (o == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (value < poolSize) {
		tmp = integerPool + value;
	} else {
		tmp = KSI_new(KSI_Integer);
		if (tmp == NULL) {
			KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		tmp->staticAlloc = 0;
		tmp->value = value;
		tmp->refCount = 1;
	}

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Integer_free(tmp);

	return res;
}

int KSI_Integer_fromTlv(KSI_TLV *tlv, KSI_Integer **o) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_Integer *tmp = NULL;
	const unsigned char *raw = NULL;
	size_t len;
	size_t i;
	KSI_uint64_t val = 0;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_ERR_clearErrors(ctx);
	if (tlv == NULL || o == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_getRawValue(tlv, &raw, &len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (len > 8) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Integer larger than 64bit");
		goto cleanup;
	}

	/* Encode the up-to 64bit unsigned integer. */
	for (i = 0; i < len; i++) {
		val = val << 8 | raw[i];
	}

	/* Make sure the integer was coded properly. */
	if (len != KSI_UINT64_MINSIZE(val)) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Integer not properly formated.");
		goto cleanup;
	}

	res = KSI_Integer_new(ctx, val, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

 	*o = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(ctx);
	KSI_Integer_free(tmp);

	return res;
}

int KSI_Integer_toTlv(KSI_CTX *ctx, KSI_Integer *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tmp = NULL;
	unsigned char raw[8];
	unsigned len = 0;
	KSI_uint64_t val;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || o == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	val = o->value;

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Encode the integer value. */
	while (val != 0) {
		raw[7 - len++] = val & 0xff;
		val >>= 8;
	}

	/* If the length is greater than 0 (val > 0), add the raw value. */
	if (len > 0) {
		res = KSI_TLV_setRawValue(tmp, raw + 8 - len, len);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tmp);

	return res;
}
