#include <string.h>


#include "internal.h"

#define KSI_TLV_MASK_TLV16 0x80u
#define KSI_TLV_MASK_LENIENT 0x40u
#define KSI_TLV_MASK_FORWARD 0x20u

#define KSI_TLV_MASK_TLV8_TYPE 0x1fu

#define KSI_BUFFER_SIZE 0xffff + 1

struct KSI_TLV_st {
	/* Context. */
	KSI_CTX *ctx;

	/* Flags */
	int isNonCritical;
	int isForwardable;

	/* TLV tag. */
	unsigned tag;

	/* Max size of the buffer. Default is 0xffff bytes. */
	unsigned buffer_size;

	/* Internal storage. */
	unsigned char *buffer;

	/* Internal storage of nested TLV's */
	KSI_LIST(KSI_TLV) *nested;

	/* How the payload is encoded internally. */
	int payloadType;

	unsigned char *datap;
	unsigned datap_len;

	size_t relativeOffset;
	size_t absoluteOffset;

};

/**
 *
 */
static int createOwnBuffer(KSI_TLV *tlv, int copy) {
	KSI_ERR err;
	unsigned char *buf = NULL;
	unsigned buf_size = KSI_BUFFER_SIZE;
	unsigned buf_len = 0;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->buffer != NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "TLV buffer already allocated.");
		goto cleanup;
	}

	buf = KSI_calloc(buf_size, 1);
	if (buf == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if (copy && tlv->datap != NULL) {
		buf_len = tlv->datap_len;

		memcpy(buf, tlv->datap, buf_len);
	}

	tlv->buffer = buf;
	buf = NULL;

	tlv->datap = tlv->buffer;
	tlv->datap_len = buf_len;

	tlv->buffer_size = buf_size;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(buf);

	return KSI_RETURN(&err);
}

/**
 *
 */
static size_t appendBlob(KSI_TLV *tlv, unsigned char *data, unsigned data_length) {
	size_t size = 0;
	int res;

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		goto cleanup;
	}

	if (tlv->buffer == NULL) {
		res = createOwnBuffer(tlv, 1);
		if (res != KSI_OK) goto cleanup;
	}

	if (tlv->datap_len + data_length > tlv->buffer_size) {
		goto cleanup;
	}

	memcpy(tlv->datap + tlv->datap_len , data, data_length);

	size = tlv->datap_len += data_length;

cleanup:

	return size;
}


/**
 *
 */
static int readTlv(KSI_RDR *rdr, KSI_TLV **tlv, int copy) {
	int res;
	KSI_ERR err;
	unsigned char hdr[4];
	size_t readCount;
	KSI_TLV *tmp = NULL;
	unsigned length = 0;
	int isLenient = 0;
	int isForward = 0;
	unsigned tag;
	unsigned char buffer[0xffff];
	unsigned char *ptr = NULL;
	char errstr[1024];
	size_t tlvOffset = 0;

	KSI_PRE(&err, rdr != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(KSI_RDR_getCtx(rdr), &err);

	/* Store the relative offset. */
	res = KSI_RDR_getOffset(rdr, &tlvOffset);
	KSI_CATCH(&err, res) goto cleanup;

	/* Read first two bytes */
	res = KSI_RDR_read_ex(rdr, hdr, 2, &readCount);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	if (readCount == 0 && KSI_RDR_isEOF(rdr)) {
		/* Reached end of stream. */
		KSI_SUCCESS(&err);
		goto cleanup;
	}
	if (readCount != 2) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	isLenient = *hdr & KSI_TLV_MASK_LENIENT;
	isForward = *hdr & KSI_TLV_MASK_FORWARD;

	/* Is it a TLV8 or TLV16 */
	if (*hdr & KSI_TLV_MASK_TLV16) {
		/* TLV16 */
		/* Read additional 2 bytes of header */
		res = KSI_RDR_read_ex(rdr, hdr + 2, 2, &readCount);
		if (res != KSI_OK) {
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}
		if (readCount != 2) {
			KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
			goto cleanup;
		}

		tag = ((*hdr & KSI_TLV_MASK_TLV8_TYPE) << 8 ) | *(hdr + 1);
		length = (unsigned)(*(hdr + 2) << 8) | *(hdr + 3);
	} else {
		/* TLV8 */
		tag = *hdr & KSI_TLV_MASK_TLV8_TYPE;
		length = *(hdr + 1);
	}

	/* Get the payload. */
	ptr = NULL;
	if (!copy) {
		/* At this point we will reuse the allocated memory. */
		res = KSI_RDR_read_ptr(rdr, &ptr, length, &readCount);
		KSI_CATCH(&err, res) goto cleanup;
	}

	if (ptr == NULL) {
		/* Read and make a copy of the payload. */
		res = KSI_RDR_read_ex(rdr, buffer, length, &readCount);
		KSI_CATCH(&err, res) goto cleanup;
	}

	if (readCount != length) {
		snprintf(errstr, sizeof(errstr), "Expected to read %u bytes, but got %llu", length, (long long unsigned)readCount);
		KSI_FAIL(&err, KSI_INVALID_FORMAT, errstr);
		goto cleanup;
	}

	/* Create new TLV object. */
	res = KSI_TLV_new(KSI_RDR_getCtx(rdr), KSI_TLV_PAYLOAD_RAW, tag, isLenient, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	if (ptr == NULL) {
		/* Append raw data. */
		if (appendBlob(tmp, buffer, length) != length) {
			KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Unable to complete TLV object.");
			goto cleanup;
		}
	} else {
		tmp->datap = ptr;
		tmp->datap_len = (unsigned)readCount;
	}

	tmp->relativeOffset = tlvOffset;
	tmp->absoluteOffset = tlvOffset;
	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(ptr);
	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}


/**
 *
 */
static int encodeAsRaw(KSI_TLV *tlv) {
	KSI_ERR err;
	int res;
	unsigned payloadLength;
	unsigned char *buf = NULL;
	unsigned buf_size = 0;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType == KSI_TLV_PAYLOAD_RAW) {
		KSI_SUCCESS(&err);
		goto cleanup;
	}

	if (tlv->buffer == NULL) {
		buf_size = 0xffff + 1;
		buf = KSI_calloc(buf_size, 1);
		if (buf == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}
	} else {
		buf = tlv->buffer;
		buf_size = tlv->buffer_size;
	}

	payloadLength = buf_size;
	res = KSI_TLV_serializePayload(tlv, buf, &payloadLength);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	tlv->payloadType = KSI_TLV_PAYLOAD_RAW;
	tlv->buffer = buf;
	tlv->buffer_size = buf_size;

	tlv->datap = buf;
	tlv->datap_len = payloadLength;

	KSI_TLVList_freeAll(tlv->nested);
	tlv->nested = NULL;

	buf = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(buf);

	return KSI_RETURN(&err);
}

/**
 *
 */
static int encodeAsString(KSI_TLV *tlv) {
	int res;
	KSI_ERR err;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType == KSI_TLV_PAYLOAD_STR) {
		KSI_SUCCESS(&err);
		goto cleanup;
	}

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	/* Determine if the current string ends with a zero. */
	if (tlv->datap[tlv->datap_len - 1] != '\0') {
		/* Make the buffer a null-terminated string, but do not change the actual size. */
		if (tlv->buffer == NULL) {
			/* Create local copy. */
			res = createOwnBuffer(tlv, tlv->datap != NULL);
			if (res != KSI_OK) {
				KSI_FAIL(&err, res, NULL);
				goto cleanup;
			}
		}

		if (tlv->datap_len >= tlv->buffer_size) {
			KSI_FAIL(&err, KSI_UNKNOWN_ERROR, NULL);
			goto cleanup;
		}
		*(tlv->datap + tlv->datap_len) = '\0';
	}
	tlv->payloadType = KSI_TLV_PAYLOAD_STR;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}
/**
 *
 */
static int encodeAsUInt64(KSI_TLV *tlv) {
	KSI_ERR err;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	/* Exit when already correct type. */
	if (tlv->payloadType == KSI_TLV_PAYLOAD_INT) {
		KSI_SUCCESS(&err);
		goto cleanup;
	}

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	/* Verify size of data - fail if overflow. */
	if (tlv->datap_len > sizeof(uint64_t)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "TLV size not in range for integer value.");
		goto cleanup;
	}

	tlv->payloadType = KSI_TLV_PAYLOAD_INT;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int encodeAsNestedTlvs(KSI_TLV *tlv) {
	int res;
	KSI_ERR err;
	KSI_RDR *rdr = NULL;
	KSI_TLV *tmp = NULL;
	KSI_LIST(KSI_TLV) *tlvList = NULL;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType == KSI_TLV_PAYLOAD_TLV) {
		KSI_SUCCESS(&err);
		goto cleanup;
	}

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	res = KSI_RDR_fromSharedMem(tlv->ctx, tlv->datap, tlv->datap_len, &rdr);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLVList_new(tlv->ctx, &tlvList);
	KSI_CATCH(&err, res) goto cleanup;

	/* Try parsing all of the nested TLV's. */
	while (1) {
		res = readTlv(rdr, &tmp, 0);
		KSI_CATCH(&err, res) goto cleanup;

		/* Check if end of reader. */
		if (tmp == NULL) break;

		/* Update the absolute offset of the child TLV object. */
		tmp->absoluteOffset += tlv->absoluteOffset;

		res = KSI_TLVList_append(tlvList, tmp);
		KSI_CATCH(&err, res) goto cleanup;

		tmp = NULL;
	}

	tlv->payloadType = KSI_TLV_PAYLOAD_TLV;
	tlv->nested = tlvList;
	tlvList = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RDR_close(rdr);
	KSI_TLV_free(tmp);
	KSI_TLVList_freeAll(tlvList);

	return KSI_RETURN(&err);
}

int KSI_TLV_setUintValue(KSI_TLV *tlv, KSI_uint64_t val) {
	KSI_ERR err;
	int res;
	unsigned len;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	len = KSI_UINT64_MINSIZE(val);
	if (tlv->buffer == NULL) {
		res = createOwnBuffer(tlv, 0);
		KSI_CATCH(&err, res) goto cleanup;
	}

	tlv->datap = tlv->buffer;
	tlv->datap_len = len;

	for (; len > 0; len--) {
		tlv->datap[len - 1] = (unsigned char)(val & 0xff);
		val >>= 8;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_TLV_setRawValue(KSI_TLV *tlv, const void *data, unsigned data_len) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, data != NULL) goto cleanup;
	KSI_PRE(&err, data_len > 0) goto cleanup;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "TLV not a raw type");
		goto cleanup;
	}

	if (data_len > KSI_BUFFER_SIZE) {
		KSI_FAIL(&err, KSI_BUFFER_OVERFLOW, NULL);
		goto cleanup;
	}

	if (tlv->buffer == NULL) {
		res = createOwnBuffer(tlv, 0);
		KSI_CATCH(&err, res) goto cleanup;
	}

	tlv->datap = tlv->buffer;
	tlv->datap_len = data_len;

	memcpy(tlv->datap, data, data_len);

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_TLV_setStringValue(KSI_TLV *tlv, const char *str) {
	KSI_ERR err;
	int res;
	size_t str_len;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, str != NULL) goto cleanup;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType != KSI_TLV_PAYLOAD_STR) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "TLV not a raw type");
		goto cleanup;
	}

	str_len = strlen(str);
	if (str_len > KSI_BUFFER_SIZE) {
		KSI_FAIL(&err, KSI_BUFFER_OVERFLOW, NULL);
		goto cleanup;
	}

	if (tlv->buffer == NULL) {
		res = createOwnBuffer(tlv, 0);
		KSI_CATCH(&err, res) goto cleanup;
	}

	tlv->datap = tlv->buffer;
	tlv->datap_len = (unsigned)str_len + 1;

	memcpy(tlv->datap, str, tlv->datap_len);

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_new(KSI_CTX *ctx, int payloadType, unsigned tag, int isLenient, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	KSI_TLV *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_TLV);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	/* Initialize context. */
	tmp->ctx = ctx;
	tmp->tag = tag;
	/* Make sure the values are *only* 1 or 0. */
	tmp->isNonCritical = isLenient ? 1 : 0;
	tmp->isForwardable = isForward ? 1 : 0;

	tmp->nested = NULL;

	tmp->buffer_size = 0;
	tmp->buffer = NULL;

	tmp->payloadType = payloadType;
	tmp->datap_len = 0;
	tmp->datap = NULL;

	tmp->relativeOffset = 0;
	tmp->absoluteOffset = 0;

	/* Update the out parameter. */
	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmp);
	return KSI_RETURN(&err);
}

/**
 *
 */
void KSI_TLV_free(KSI_TLV *tlv) {
	if (tlv != NULL) {
		KSI_free(tlv->buffer);
		/* Free nested data */

		KSI_TLVList_freeAll(tlv->nested);
		KSI_free(tlv);
	}
}

int KSI_TLV_fromReader(KSI_RDR *rdr, KSI_TLV **tlv) {
	/* Read the TLV and make a copy of the memory. */
	return readTlv(rdr, tlv, 1);
}


/**
 *
 */
int KSI_TLV_getRawValue(KSI_TLV *tlv, const unsigned char **buf, unsigned *len) {
	KSI_ERR err;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, buf != NULL) goto cleanup;
	KSI_PRE(&err, len != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	/* Check payload type. */
	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	*buf = tlv->datap;
	*len = tlv->datap_len;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_TLV_getInteger(KSI_TLV *tlv, KSI_Integer **value) {
	KSI_ERR err;
	KSI_Integer *tmp = NULL;
	KSI_uint64_t val = 0;
	int res;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, value != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	/* Check payload type. */
	if (tlv->payloadType != KSI_TLV_PAYLOAD_INT) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	res = KSI_TLV_getUInt64Value(tlv, &val);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_Integer_new(tlv->ctx, val, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*value = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp);

	return KSI_RETURN(&err);
}


/**
 *
 */
int KSI_TLV_getUInt64Value(KSI_TLV *tlv, KSI_uint64_t *val) {
	KSI_ERR err;
	KSI_uint64_t tmp = 0;
	unsigned i;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, val != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	/* Check payload type. */
	if (tlv->payloadType != KSI_TLV_PAYLOAD_INT) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	for (i = 0; i < tlv->datap_len; i++) {
		tmp = tmp << 8 | tlv->datap[i];
	}

	*val = tmp;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_getStringValue(KSI_TLV *tlv, const char **buf) {
	KSI_ERR err;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, buf != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	/* Check payload type. */
	if (tlv->payloadType != KSI_TLV_PAYLOAD_STR) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	*buf = (const char *) tlv->datap;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_TLV_getNestedList(KSI_TLV *tlv, KSI_LIST(KSI_TLV) **list) {
	KSI_ERR err;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, list != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	/* Check payload type. */
	if (tlv->payloadType != KSI_TLV_PAYLOAD_TLV) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	*list = tlv->nested;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_parseBlob(KSI_CTX *ctx, const unsigned char *data, size_t data_length, KSI_TLV **tlv) {
	KSI_ERR err;
	KSI_RDR *rdr = NULL;
	KSI_TLV *tmp = NULL;

	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, data != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_RDR_fromSharedMem(ctx, (unsigned char *)data, data_length, &rdr);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_fromReader(rdr, &tmp);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	/* Make sure, the blob does not contain extra data. */
	res = KSI_RDR_verifyEnd(rdr);
	KSI_CATCH(&err, res) goto cleanup;


	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RDR_close(rdr);
	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_cast(KSI_TLV *tlv, int payloadType) {
	KSI_ERR err;

	int res;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType == payloadType) {
		KSI_SUCCESS(&err);
		goto cleanup;
	}

	switch(payloadType) {
		case KSI_TLV_PAYLOAD_RAW:
			res = encodeAsRaw(tlv);
			break;
		case KSI_TLV_PAYLOAD_STR:
			res = encodeAsString(tlv);
			break;
		case KSI_TLV_PAYLOAD_INT:
			res = encodeAsUInt64(tlv);
			break;
		case KSI_TLV_PAYLOAD_TLV:
			res = encodeAsNestedTlvs(tlv);
			break;
		default:
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Unknown TLV payload encoding.");
			goto cleanup;
	}

	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_fromUint(KSI_CTX *ctx, unsigned tag, int isLenient, int isForward, KSI_uint64_t uint, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_INT, tag, isLenient, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_setUintValue(tmp, uint);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_fromString(KSI_CTX *ctx, unsigned tag, int isLenient, int isForward, char *str, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, str != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_STR, tag, isLenient, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_setStringValue(tmp, str);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_isLenient(KSI_TLV *tlv) {
	return tlv->isNonCritical;
}

/**
 *
 */
int KSI_TLV_isForward(KSI_TLV *tlv) {
	return tlv->isForwardable;
}

/**
 *
 */
unsigned KSI_TLV_getTag(KSI_TLV *tlv) {
	return tlv->tag;
}

int KSI_TLV_getPayloadType(KSI_TLV *tlv) {
	return tlv->payloadType;
}

int KSI_TLV_removeNestedTlv(KSI_TLV *target, KSI_TLV *tlv) {
	KSI_ERR err;
	int res;
	size_t pos;

	KSI_PRE(&err, target != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;

	KSI_BEGIN(target->ctx, &err);

	res = KSI_TLVList_indexOf(target->nested, tlv, &pos);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLVList_remove(target->nested, pos);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_TLV_replaceNestedTlv(KSI_TLV *parentTlv, KSI_TLV *oldTlv, KSI_TLV *newTlv) {
	KSI_ERR err;
	size_t pos;
	int res;

	KSI_PRE(&err, parentTlv != NULL) goto cleanup;
	KSI_PRE(&err, oldTlv != NULL) goto cleanup;
	KSI_PRE(&err, newTlv != NULL) goto cleanup;

	KSI_BEGIN(parentTlv->ctx, &err);

	if (parentTlv->payloadType != KSI_TLV_PAYLOAD_TLV) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	res = KSI_TLVList_indexOf(parentTlv->nested, oldTlv, &pos);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLVList_replaceAt(parentTlv->nested, pos, newTlv);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}


/**
 *
 */
int KSI_TLV_appendNestedTlv(KSI_TLV *target, KSI_TLV *after, KSI_TLV *tlv) {
	KSI_ERR err;
	size_t pos;
	int res;
	KSI_LIST(KSI_TLV) *list = NULL;

	KSI_PRE(&err, target != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;

	KSI_BEGIN(target->ctx, &err);

	if (target->payloadType != KSI_TLV_PAYLOAD_TLV) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	if (target->nested == NULL) {
		res = KSI_TLVList_new(target->ctx, &list);
		KSI_CATCH(&err, res) goto cleanup;

		target->nested = list;
		list = NULL;
	}

	if (after != NULL) {
		res = KSI_TLVList_indexOf(target->nested, tlv, &pos);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_TLVList_insertAt(target->nested, pos, tlv);
	} else {
		res = KSI_TLVList_append(target->nested, tlv);
	}

	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLVList_freeAll(list);
	return KSI_RETURN(&err);
}

static int serializeTlv(const KSI_TLV *tlv, unsigned char *buf, unsigned *buf_free, int serializeHeader);

static int serializeRaw(const KSI_TLV *tlv, unsigned char *buf, unsigned *len) {
	KSI_ERR err;
	unsigned payloadLength;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, buf != NULL) goto cleanup;
	KSI_PRE(&err, len != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW && tlv->payloadType != KSI_TLV_PAYLOAD_STR && tlv->payloadType != KSI_TLV_PAYLOAD_INT) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	payloadLength = tlv->datap_len;

	if (*len < payloadLength) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	memcpy(buf + *len - payloadLength, tlv->datap, payloadLength);

	*len-=payloadLength;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int serializeTlvList(const KSI_LIST(KSI_TLV) *tlvListNode, unsigned char *buf, unsigned *buf_free) {
	KSI_ERR err;
	int res;
	unsigned bf = *buf_free;
	KSI_TLV *tlv = NULL;

	KSI_PRE(&err, tlvListNode != NULL) goto cleanup;
	KSI_BEGIN(KSI_TLVList_getCtx(tlvListNode), &err);

	/* Cast required, as the iterator is advanced by one. */
	res = KSI_TLVList_next((KSI_LIST(KSI_TLV) *)tlvListNode, &tlv);
	KSI_CATCH(&err, res) goto cleanup;

	if (tlv != NULL) {
		res = serializeTlvList(tlvListNode, buf, &bf);
		if (res != KSI_OK) {
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}

		res = serializeTlv(tlv, buf, &bf, 1);
		if (res != KSI_OK) {
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}

		*buf_free = bf;
	}
	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int serializeNested(const KSI_TLV *tlv, unsigned char *buf, unsigned *buf_free) {
	KSI_ERR err;
	int res;
	unsigned bf = *buf_free;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, buf != NULL) goto cleanup;
	KSI_PRE(&err, buf_free != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType != KSI_TLV_PAYLOAD_TLV) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (tlv->nested != NULL) {
		res = KSI_TLVList_iter(tlv->nested);
		KSI_CATCH(&err, res) goto cleanup;

		res = serializeTlvList(tlv->nested, buf, &bf);
		if (res != KSI_OK) {
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}
	}

	*buf_free = bf;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int serializePayload(const KSI_TLV *tlv, unsigned char *buf, unsigned *buf_free) {
	KSI_ERR err;
	int res;
	unsigned bf = *buf_free;

	KSI_BEGIN(tlv->ctx, &err);

	switch (tlv->payloadType) {
		case KSI_TLV_PAYLOAD_RAW:
		case KSI_TLV_PAYLOAD_STR:
		case KSI_TLV_PAYLOAD_INT:
			res = serializeRaw(tlv, buf, &bf);
			break;
		case KSI_TLV_PAYLOAD_TLV:
			res = serializeNested(tlv, buf, &bf);
			break;
		default:
			KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Dont know how to serialize unknown payload type.");
			goto cleanup;
	}
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	*buf_free = bf;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int serializeTlv(const KSI_TLV *tlv, unsigned char *buf, unsigned *buf_free, int serializeHeader) {
	KSI_ERR err;
	int res;
	unsigned bf = *buf_free;
	unsigned payloadLength;
	unsigned char *ptr = NULL;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, buf != NULL) goto cleanup;
	KSI_PRE(&err, buf_free != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	res = serializePayload(tlv, buf, &bf);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	payloadLength = *buf_free - bf;
	ptr = buf + bf - 1;

	if (serializeHeader) {
		/* Write header */
		if (payloadLength > 0xff || tlv->tag > KSI_TLV_MASK_TLV8_TYPE) {
			/* Encode as TLV16 */
			if (bf < 4) {
				KSI_FAIL(&err, KSI_BUFFER_OVERFLOW, NULL);
				goto cleanup;
			}
			bf -= 4;
			*ptr-- = 0xff & payloadLength;
			*ptr-- = 0xff & payloadLength >> 8;
			*ptr-- = tlv->tag & 0xff;
			*ptr-- = (unsigned char) (KSI_TLV_MASK_TLV16 | (tlv->isNonCritical ? KSI_TLV_MASK_LENIENT : 0) | (tlv->isForwardable ? KSI_TLV_MASK_FORWARD : 0) | (tlv->tag >> 8));

		} else {
			/* Encode as TLV8 */
			if (bf < 2) {
				KSI_FAIL(&err, KSI_BUFFER_OVERFLOW, NULL);
				goto cleanup;
			}
			bf -= 2;
			*ptr-- = payloadLength & 0xff;
			*ptr-- = (unsigned char)(0x00 | (tlv->isNonCritical ? KSI_TLV_MASK_LENIENT : 0) | (tlv->isForwardable ? KSI_TLV_MASK_FORWARD : 0) | tlv->tag);
		}
	}

	*buf_free = bf;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int serialize(const KSI_TLV *tlv, unsigned char *buf, unsigned *len, int serializeHeader) {
	KSI_ERR err;
	int res;
	unsigned bf = *len;
	unsigned payloadLength;
	unsigned char *ptr = NULL;
	unsigned i;
	unsigned tmpLen;

	KSI_BEGIN(tlv->ctx, &err);

	res = serializeTlv(tlv, buf, &bf, serializeHeader);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	payloadLength = *len - bf;
	/* Move the serialized value to the begin of the buffer. */
	ptr = buf;
	tmpLen = 0;
	for (i = 0; i < payloadLength; i++) {
		*ptr++ = *(buf + bf + i);
		tmpLen++;
	}

	*len = tmpLen;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(ptr);

	return KSI_RETURN(&err);
}

int KSI_TLV_serialize_ex(const KSI_TLV *tlv, unsigned char *buf, unsigned buf_size, unsigned *len) {
	int res;
	unsigned buf_free = buf_size;

	res = serialize(tlv, buf, &buf_free, 1);
	if (res != KSI_OK) goto cleanup;

	*len = buf_free;

cleanup:

	return res;
}

int KSI_TLV_serialize(const KSI_TLV *tlv, unsigned char **buf, unsigned *buf_len) {
	int res;
	unsigned char tmpBuf[0xffff + 4];
	unsigned tmp_len;

	unsigned char *tmp = NULL;

	res = KSI_TLV_serialize_ex(tlv, tmpBuf, sizeof(tmpBuf), &tmp_len);
	if (res != KSI_OK) goto cleanup;

	tmp = KSI_calloc(tmp_len, 1);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	memcpy(tmp, tmpBuf, tmp_len);

	*buf = tmp;
	*buf_len = tmp_len;

	tmp = NULL;

cleanup:

	KSI_free(tmp);

	return res;
}

/**
 *
 */
int KSI_TLV_serializePayload(KSI_TLV *tlv, unsigned char *buf, unsigned *len) {
	return serialize(tlv, buf, len, 0);
}

#define NOTNEG(a) (a) < 0 ? 0 : a

static int stringify(KSI_TLV *tlv, int indent, char *str, unsigned size, unsigned *len) {
	int res;
	unsigned l = *len;
	size_t i;
	KSI_uint64_t tmpInt;

	if (*len >= size) {
		res = KSI_OK; /* Buffer is full, but do not break the flow. */
		goto cleanup;
	}
	if (indent != 0) {
		l += (unsigned)snprintf(str + l, NOTNEG(size - l), "\n%*s", indent, "");
	}
	if (tlv->tag > 0xff) {
		l += (unsigned)snprintf(str + l, NOTNEG(size - l), "TLV[0x%04x]", tlv->tag);
	} else {
		l += (unsigned)snprintf(str + l, NOTNEG(size - l), "TLV[0x%02x]", tlv->tag);
	}

	l += (unsigned)snprintf(str + l, NOTNEG(size - l), " %c", tlv->isNonCritical ? 'L' : '-');
	l += (unsigned)snprintf(str + l, NOTNEG(size - l), " %c", tlv->isForwardable ? 'F' : '-');

	switch (tlv->payloadType) {
		case KSI_TLV_PAYLOAD_RAW:
			l += (unsigned)snprintf(str + l, NOTNEG(size - l), " len = %llu : ", (unsigned long long)tlv->datap_len);
			for (i = 0; i < tlv->datap_len; i++) {
				l += (unsigned)snprintf(str + l, NOTNEG(size - l), "%02x", tlv->datap[i]);
			}
			break;
		case KSI_TLV_PAYLOAD_STR:
			l += (unsigned)snprintf(str + l, NOTNEG(size - l), " len = %llu : \"%s\"", (unsigned long long)tlv->datap_len, tlv->datap);
			break;
		case KSI_TLV_PAYLOAD_INT:
			res = KSI_TLV_getUInt64Value(tlv, &tmpInt);
			if (res != KSI_OK) goto cleanup;

			l += (unsigned)snprintf(str + l, NOTNEG(size - l), " len = %llu : 0x%llx", (unsigned long long)tlv->datap_len, (unsigned long long) tmpInt);
			break;
		case KSI_TLV_PAYLOAD_TLV:
			l += (unsigned)snprintf(str + l, NOTNEG(size - l), ":");
			res = KSI_TLVList_iter(tlv->nested);
			if (res != KSI_OK) goto cleanup;
			for (i = 0; i < KSI_TLVList_length(tlv->nested); i++) {
				KSI_TLV *tmp = NULL;

				res = KSI_TLVList_elementAt(tlv->nested, i, &tmp);
				if (res != KSI_OK) goto cleanup;
				if (tmp == NULL) break;
				res = stringify(tmp, indent + 2, str, size, &l);
				if (res != KSI_OK) goto cleanup;
			}

			KSI_nofree(tmp);
			break;
		default:
			res = KSI_INVALID_ARGUMENT;
			goto cleanup;
	}

	if (l < size) {
		*len = l;
	} else {
		*len = size;
	}
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_TLV_toString(KSI_TLV *tlv, char **str) {
	KSI_ERR err;
	int res;
	char *tmp = NULL;
	unsigned tmp_size = 0xfffff; /* 1 MB, now this should be enough for everyone. */
	unsigned tmp_len = 0;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, str != NULL) goto cleanup;
	KSI_BEGIN(tlv->ctx, &err);

	tmp = KSI_calloc(tmp_size, 1);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = stringify(tlv, 0, tmp, tmp_size, &tmp_len);
	KSI_CATCH(&err, res) goto cleanup;

	tmp = KSI_realloc(tmp, tmp_len + 1);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	*str = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp);

	return KSI_RETURN(&err);
}

static int expandNested(const KSI_TLV *sample, KSI_TLV *tlv) {
	KSI_ERR err;
	int res;
	size_t i;

	KSI_PRE(&err, sample != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;

	KSI_BEGIN(sample->ctx, &err);

	/* Fail if the TLV tags differ */
	if (sample->tag != tlv->tag) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "TLV types differ");
		goto cleanup;
	}

	/* Cast if necessary. */
	if (sample->payloadType != tlv->payloadType) {
		res = KSI_TLV_cast(tlv, sample->payloadType);
		KSI_CATCH(&err, res) goto cleanup;
	}

	/* Continue if nested. */
	if (sample->payloadType == KSI_TLV_PAYLOAD_TLV) {
		/* Check if nested element count matches */
		if (KSI_TLVList_length(sample->nested) != KSI_TLVList_length(tlv->nested)) {
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Different number of nested TLV's.");
			goto cleanup;
		}

		for (i = 0; i < KSI_TLVList_length(sample->nested); i++) {
			const KSI_TLV *nestedSample = NULL;
			KSI_TLV *nestedTlv = NULL;

			res = KSI_TLVList_elementAt(sample->nested, i, (KSI_TLV **)&nestedSample);
			KSI_CATCH(&err, res) goto cleanup;

			res = KSI_TLVList_elementAt(tlv->nested, i, &nestedTlv);
			KSI_CATCH(&err, res) goto cleanup;

			res = expandNested(nestedSample, nestedTlv);
			KSI_CATCH(&err, res) goto cleanup;

			/* The values are still components of the tlvs, so nothing has to be freed. */
			KSI_nofree(nestedTlv);
			KSI_nofree(nestedSample);
		}

	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_TLV_clone(const KSI_TLV *tlv, KSI_TLV **clone) {
	KSI_ERR err;
	int res;
	unsigned char *buf = NULL;
	unsigned buf_len;
	KSI_TLV *tmp = NULL;


	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, clone != NULL) goto cleanup;

	KSI_BEGIN(tlv->ctx, &err);

	/* Selialize the entire tlv */
	res = KSI_TLV_serialize(tlv, &buf, &buf_len);
	KSI_CATCH(&err, res) goto cleanup;

	/* Recreate the TLV */
	res = KSI_TLV_parseBlob(tlv->ctx, buf, buf_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	/* Reexpand the nested (if any) TLV's */
	res = expandNested(tlv, tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*clone = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(buf);
	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

size_t KSI_TLV_getAbsoluteOffset(const KSI_TLV *tlv) {
	return tlv->absoluteOffset;
}

size_t KSI_TLV_getRelativeOffset(const KSI_TLV *tlv) {
	return tlv->relativeOffset;
}


KSI_IMPLEMENT_GET_CTX(KSI_TLV);
