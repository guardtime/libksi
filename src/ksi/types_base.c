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

#include <assert.h>
#include <string.h>

#include "internal.h"
#include "tlv.h"

struct KSI_OctetString_st {
	KSI_CTX *ctx;
	size_t ref;
	unsigned char *data;
	size_t data_len;
};

struct KSI_Integer_st {
	size_t ref;
	KSI_uint64_t value;
};

struct KSI_Utf8String_st {
	KSI_CTX *ctx;
	size_t ref;
	char *value;
	size_t len;
};

/**
 *  A static pool for immutable #KSI_Integer object values in range 0..ff
 */
static KSI_Integer integerPool[] = {
		{0, 0x00}, {0, 0x01}, {0, 0x02}, {0, 0x03}, {0, 0x04}, {0, 0x05}, {0, 0x06}, {0, 0x07},
		{0, 0x08}, {0, 0x09}, {0, 0x0a}, {0, 0x0b},	{0, 0x0c}, {0, 0x0d}, {0, 0x0e}, {0, 0x0f},
		{0, 0x10}, {0, 0x11}, {0, 0x12}, {0, 0x13},	{0, 0x14}, {0, 0x15}, {0, 0x16}, {0, 0x17},
		{0, 0x18}, {0, 0x19}, {0, 0x1a}, {0, 0x1b},	{0, 0x1c}, {0, 0x1d}, {0, 0x1e}, {0, 0x1f},
		{0, 0x20}, {0, 0x21}, {0, 0x22}, {0, 0x23},	{0, 0x24}, {0, 0x25}, {0, 0x26}, {0, 0x27},
		{0, 0x28}, {0, 0x29}, {0, 0x2a}, {0, 0x2b},	{0, 0x2c}, {0, 0x2d}, {0, 0x2e}, {0, 0x2f},
		{0, 0x30}, {0, 0x31}, {0, 0x32}, {0, 0x33},	{0, 0x34}, {0, 0x35}, {0, 0x36}, {0, 0x37},
		{0, 0x38}, {0, 0x39}, {0, 0x3a}, {0, 0x3b},	{0, 0x3c}, {0, 0x3d}, {0, 0x3e}, {0, 0x3f},
		{0, 0x40}, {0, 0x41}, {0, 0x42}, {0, 0x43},	{0, 0x44}, {0, 0x45}, {0, 0x46}, {0, 0x47},
		{0, 0x48}, {0, 0x49}, {0, 0x4a}, {0, 0x4b},	{0, 0x4c}, {0, 0x4d}, {0, 0x4e}, {0, 0x4f},
		{0, 0x50}, {0, 0x51}, {0, 0x52}, {0, 0x53},	{0, 0x54}, {0, 0x55}, {0, 0x56}, {0, 0x57},
		{0, 0x58}, {0, 0x59}, {0, 0x5a}, {0, 0x5b},	{0, 0x5c}, {0, 0x5d}, {0, 0x5e}, {0, 0x5f},
		{0, 0x60}, {0, 0x61}, {0, 0x62}, {0, 0x63},	{0, 0x64}, {0, 0x65}, {0, 0x66}, {0, 0x67},
		{0, 0x68}, {0, 0x69}, {0, 0x6a}, {0, 0x6b},	{0, 0x6c}, {0, 0x6d}, {0, 0x6e}, {0, 0x6f},
		{0, 0x70}, {0, 0x71}, {0, 0x72}, {0, 0x73},	{0, 0x74}, {0, 0x75}, {0, 0x76}, {0, 0x77},
		{0, 0x78}, {0, 0x79}, {0, 0x7a}, {0, 0x7b},	{0, 0x7c}, {0, 0x7d}, {0, 0x7e}, {0, 0x7f},
		{0, 0x80}, {0, 0x81}, {0, 0x82}, {0, 0x83},	{0, 0x84}, {0, 0x85}, {0, 0x86}, {0, 0x87},
		{0, 0x88}, {0, 0x89}, {0, 0x8a}, {0, 0x8b},	{0, 0x8c}, {0, 0x8d}, {0, 0x8e}, {0, 0x8f},
		{0, 0x90}, {0, 0x91}, {0, 0x92}, {0, 0x93},	{0, 0x94}, {0, 0x95}, {0, 0x96}, {0, 0x97},
		{0, 0x98}, {0, 0x99}, {0, 0x9a}, {0, 0x9b},	{0, 0x9c}, {0, 0x9d}, {0, 0x9e}, {0, 0x9f},
		{0, 0xa0}, {0, 0xa1}, {0, 0xa2}, {0, 0xa3},	{0, 0xa4}, {0, 0xa5}, {0, 0xa6}, {0, 0xa7},
		{0, 0xa8}, {0, 0xa9}, {0, 0xaa}, {0, 0xab},	{0, 0xac}, {0, 0xad}, {0, 0xae}, {0, 0xaf},
		{0, 0xb0}, {0, 0xb1}, {0, 0xb2}, {0, 0xb3},	{0, 0xb4}, {0, 0xb5}, {0, 0xb6}, {0, 0xb7},
		{0, 0xb8}, {0, 0xb9}, {0, 0xba}, {0, 0xbb},	{0, 0xbc}, {0, 0xbd}, {0, 0xbe}, {0, 0xbf},
		{0, 0xc0}, {0, 0xc1}, {0, 0xc2}, {0, 0xc3},	{0, 0xc4}, {0, 0xc5}, {0, 0xc6}, {0, 0xc7},
		{0, 0xc8}, {0, 0xc9}, {0, 0xca}, {0, 0xcb},	{0, 0xcc}, {0, 0xcd}, {0, 0xce}, {0, 0xcf},
		{0, 0xd0}, {0, 0xd1}, {0, 0xd2}, {0, 0xd3},	{0, 0xd4}, {0, 0xd5}, {0, 0xd6}, {0, 0xd7},
		{0, 0xd8}, {0, 0xd9}, {0, 0xda}, {0, 0xdb},	{0, 0xdc}, {0, 0xdd}, {0, 0xde}, {0, 0xdf},
		{0, 0xe0}, {0, 0xe1}, {0, 0xe2}, {0, 0xe3},	{0, 0xe4}, {0, 0xe5}, {0, 0xe6}, {0, 0xe7},
		{0, 0xe8}, {0, 0xe9}, {0, 0xea}, {0, 0xeb},	{0, 0xec}, {0, 0xed}, {0, 0xee}, {0, 0xef},
		{0, 0xf0}, {0, 0xf1}, {0, 0xf2}, {0, 0xf3},	{0, 0xf4}, {0, 0xf5}, {0, 0xf6}, {0, 0xf7},
		{0, 0xf8}, {0, 0xf9}, {0, 0xfa}, {0, 0xfb},	{0, 0xfc}, {0, 0xfd}, {0, 0xfe}, {0, 0xff}
};
static const size_t integerPoolSize = sizeof(integerPool) / sizeof(KSI_Integer);


KSI_IMPLEMENT_LIST(KSI_Integer, KSI_Integer_free);
KSI_IMPLEMENT_LIST(KSI_Utf8String, KSI_Utf8String_free);
KSI_IMPLEMENT_LIST(KSI_Utf8StringNZ, KSI_Utf8String_free);
KSI_IMPLEMENT_LIST(KSI_OctetString, KSI_OctetString_free);

/**
 * KSI_OctetString
 */
void KSI_OctetString_free(KSI_OctetString *o) {
	if (o != NULL && --o->ref == 0) {
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
	tmp->ref = 1;

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

KSI_IMPLEMENT_REF(KSI_OctetString);

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

int KSI_OctetString_toTlv(KSI_CTX *ctx, const KSI_OctetString *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || o == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_new(ctx, tag, isNonCritical, isForward, &tmp);
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

char* KSI_OctetString_toString(const KSI_OctetString *id, char separator, char *buf, size_t buf_len) {
	int res = 0;
	const unsigned char *raw = NULL;
	size_t raw_len;
	size_t written = 0;
	size_t i = 0;


	if (id == NULL || buf == NULL || buf_len == 0) {
		return NULL;
	}

	res = KSI_OctetString_extract(id, &raw, &raw_len);
	if(res != KSI_OK || raw == NULL) return NULL;

	for (i = 0; i < raw_len; i++) {
		if(buf_len - written <= 0) return NULL;
		if(separator == '\0' || i == raw_len - 1)
			written += KSI_snprintf(buf + written, buf_len - written, "%02x", raw[i]);
		else
			written += KSI_snprintf(buf + written, buf_len - written, "%02x%c", raw[i], separator);
		if (written == 0) return NULL;
	}

	return buf;
}

#define LEGACY_ID_STR_LEN_POS 2
#define LEGACY_ID_STR_POS 3

int KSI_OctetString_LegacyId_getUtf8String(const KSI_OctetString *id, KSI_Utf8String **str) {
	int res = KSI_UNKNOWN_ERROR;
	const unsigned char *raw = NULL;
	size_t raw_len;
	KSI_Utf8String *tmp = NULL;

	if (id == NULL || str == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(id->ctx);

	res = KSI_OctetString_extract(id, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(id->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Utf8String_new(id->ctx, (char *)(raw + LEGACY_ID_STR_POS), raw[LEGACY_ID_STR_LEN_POS] + 1, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(id->ctx, res, NULL);
		goto cleanup;
	}
	*str = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:
	KSI_Utf8String_free(tmp);

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
	if (o != NULL && --o->ref == 0) {
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
	tmp->ref = 1;

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

KSI_IMPLEMENT_REF(KSI_Utf8String);

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

int KSI_Utf8String_toTlv(KSI_CTX *ctx, const KSI_Utf8String *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || o == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_new(ctx, tag, isNonCritical, isForward, &tmp);
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
	KSI_Utf8String_free(tmp);

	return res;
}

int KSI_Utf8StringNZ_toTlv(KSI_CTX *ctx, const KSI_Utf8String *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
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
	if (o != NULL && o->value >= integerPoolSize && --o->ref == 0) {
		KSI_free(o);
	}
}

KSI_IMPLEMENT_REF(KSI_Integer);

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

	KSI_ERR_clearErrors(ctx);
	if (o == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (value < integerPoolSize) {
		tmp = integerPool + value;
	} else {
		tmp = KSI_new(KSI_Integer);
		if (tmp == NULL) {
			KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}
		tmp->value = value;
		tmp->ref = 1;
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

int KSI_Integer_toTlv(KSI_CTX *ctx, const KSI_Integer *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
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

	res = KSI_TLV_new(ctx, tag, isNonCritical, isForward, &tmp);
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
