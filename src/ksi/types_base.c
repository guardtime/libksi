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


/**
 * Utf8String
 */

void KSI_Utf8String_free(KSI_Utf8String *t) {
	if (t != NULL && --t->refCount == 0) {
		KSI_free(t->value);
		KSI_free(t);
	}
}

int KSI_Utf8String_new(KSI_CTX *ctx, const char *str, KSI_Utf8String **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Utf8String *tmp = NULL;
	char *val = NULL;
	size_t len = 0;

	tmp = KSI_new(KSI_Utf8String);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->value = NULL;
	tmp->refCount = 1;
	
	len = strlen(str) + 1;

	val = KSI_calloc(len, 1);
	memcpy(val, str, len);

	tmp->value = val;
	tmp->len = len;

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
	const char *cstr = NULL;
	KSI_Utf8String *tmp = NULL;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, u8str != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_STR);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_getStringValue(tlv, &cstr);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_Utf8String_new(ctx, cstr, &tmp);
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

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_STR, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_setStringValue(tmp, u8str->value);
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

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, ksiInteger != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_INT);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_getInteger(tlv, &tmp);
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

	KSI_PRE(&err, integer != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_INT, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_setUintValue(tmp, integer->value);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}
