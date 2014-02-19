#include <string.h>

#include "ksi_internal.h"

/**
 *
 */
static int createOwnBuffer(KSI_TLV *tlv, int copy) {
	KSI_ERR err;
	unsigned char *buf;
	int buf_size = 0xffff + 1;
	int buf_len = 0;

	KSI_begin(tlv->ctx, &err);

	if (tlv->buffer != NULL) {
		KSI_fail(&err, KSI_INVALID_ARGUMENT, "TLV buffer already allocated.");
		goto cleanup;
	}

	buf = KSI_calloc(buf_size, 1);

	if (buf == NULL) {
		KSI_fail(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if (copy) {
		if (tlv->payload.rawVal.ptr == NULL) {
			KSI_fail(&err, KSI_INVALID_ARGUMENT, "Cant copy data from NULL pointer.");
			goto cleanup;
		}
		buf_len = tlv->payload.rawVal.length;

		memcpy(buf, tlv->payload.rawVal.ptr, buf_len);
	}

	tlv->buffer = buf;
	buf = NULL;

	tlv->payload.rawVal.ptr = tlv->buffer;
	tlv->payload.rawVal.length = buf_len;

	tlv->buffer_size = buf_size;

	KSI_success(&err);

cleanup:

	KSI_free(buf);

	return KSI_end(&err);
}

/**
 *
 */
static int encodeAsRaw(KSI_TLV *tlv) {
	KSI_ERR err;

	KSI_begin(tlv->ctx, &err);

	KSI_fail(&err, KSI_UNKNOWN_ERROR, "Unimplemented method.");

	return KSI_end(&err);
}

/**
 *
 */
static int encodeAsString(KSI_TLV *tlv) {
	int res;
	KSI_ERR err;

	KSI_begin(tlv->ctx, &err);

	if (tlv->payloadType == KSI_TLV_PAYLOAD_STR) {
		KSI_success(&err);
		goto cleanup;
	}

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		res = encodeAsRaw(tlv);
		if (res != KSI_OK) {
			KSI_fail(&err, res, NULL);
			goto cleanup;
		}
	}

	if (tlv->buffer == NULL) {
		/* Create local copy. */
		res = createOwnBuffer(tlv, 1);
		if (res != KSI_OK) {
			KSI_fail(&err, res, NULL);
			goto cleanup;
		}
	}

	/* Make the buffer a null-terminated string, but do not change the actual size. */
	*(tlv->payload.rawVal.ptr + tlv->payload.rawVal.length) = '\0';

	KSI_success(&err);

cleanup:

	return KSI_end(&err);
}
/**
 *
 */
static int encodeAsUInt64(KSI_TLV *tlv) {
	int res;
	KSI_ERR err;
	uint64_t value;
	int value_len;

	KSI_begin(tlv->ctx, &err);

	/* Exit when already correct type. */
	if (tlv->payloadType == KSI_TLV_PAYLOAD_INT) {
		KSI_success(&err);
		goto cleanup;
	}

	/* Use only raw format. */
	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		/* Convert the TLV into raw form */
		res = encodeAsRaw(tlv);
		if (res != KSI_OK) {
			KSI_fail(&err, res, NULL);
			goto cleanup;
		}
	}

	/* Verify size of data - fail if overflow. */
	if (tlv->payload.rawVal.length > sizeof(uint64_t)) {
		KSI_fail(&err, KSI_INVALID_FORMAT, "TLV size too long for integer value.");
		goto cleanup;
	}

	/* Decode the big endian value. */
	value = 0;
	for (value_len = 0; value_len < tlv->payload.rawVal.length; value_len++) {
		value = (value << 8) | *(tlv->payload.rawVal.ptr + value_len);
	}

	tlv->payloadType = KSI_TLV_PAYLOAD_INT;

	tlv->payload.uintVal.value = value;
	tlv->payload.uintVal.length = value_len;

	KSI_success(&err);

cleanup:

	return KSI_end(&err);
}

/**
 *
 */
static int appendBlob(KSI_TLV *tlv, char *data, size_t data_length) {
	int size = -1;

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW || tlv->buffer == NULL) {
		goto cleanup;
	}

	if (tlv->payload.rawVal.length + data_length > tlv->buffer_size) {
		goto cleanup;
	}

	memcpy(tlv->payload.rawVal.ptr + tlv->payload.rawVal.length , data, data_length);

	size = tlv->payload.rawVal.length += data_length;

cleanup:

	return size;
}

/**
 *
 */
int KSI_TLV_new(KSI_CTX *ctx, char *data, size_t data_len, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *t = NULL;

	KSI_begin(ctx, &err);

	t = KSI_new(KSI_TLV);
	if (t == NULL) {
		KSI_fail(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	/* Initialize context. */
	t->ctx = ctx;
	/* Initialize the parameters with default values. */
	t->next = NULL;
	t->isLenient = 0;
	t->isForwardable = 0;

	t->payloadType = KSI_TLV_PAYLOAD_RAW;

	if (data != NULL) {
		t->buffer_size = 0;
		t->buffer = NULL;

		t->payload.rawVal.length = data_len;
		t->payload.rawVal.ptr = data;
	} else {
		res = createOwnBuffer(t, 0);
		if (res != KSI_OK) {
			KSI_fail(&err, res, NULL);
			goto cleanup;
		}

		t->payload.rawVal.length = 0;
		t->payload.rawVal.ptr = t->buffer;
	}

	/* Update the out parameter. */
	*tlv = t;
	t = NULL;

	KSI_success(&err);

cleanup:

	KSI_TLV_free(t);
	return KSI_end(&err);
}

/**
 *
 */
void KSI_TLV_free(KSI_TLV *tlv) {
	KSI_TLV *nested = NULL;
	KSI_TLV *nestedNext = NULL;
	if (tlv != NULL) {
		KSI_free(tlv->buffer);

		/* Free nested data */
		if (tlv->payloadType == KSI_TLV_PAYLOAD_TLV) {
			nested = tlv->payload.tlv.list;
			while(nested != NULL) {
				nestedNext = nested->next;
				KSI_TLV_free(nested);
				nested = nestedNext;
			}
		}
		KSI_free(tlv);
	}
}

/**
 *
 */
int KSI_TLV_fromReader(KSI_RDR *rdr, KSI_TLV **tlv) {
	int res;
	KSI_ERR err;
	unsigned char hdr[4];
	int hdr_len = 0;
	int readCount;
	KSI_TLV *t = NULL;
	int length = 0;
	int lenient = 0;
	int forward = 0;
	unsigned int type;
	char buffer[0xffff];


	KSI_begin(rdr->ctx, &err);

	/* Read first two bytes */
	res = KSI_RDR_read(rdr, hdr, 2, &readCount);
	if (res != KSI_OK) {
		KSI_fail(&err, res, NULL);
		goto cleanup;
	}

	if (readCount == 0 && KSI_RDR_isEOF(rdr)) {
		/* Reached end of stream. */
		KSI_success(&err);
		goto cleanup;
	}
	if (readCount != 2) {
		KSI_fail(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	lenient = *hdr & KSI_TLV_MASK_LENIENT;
	forward = *hdr & KSI_TLV_MASK_FORWARD;

	/* Is it a TLV8 or TLV16 */
	if (*hdr & KSI_TLV_MASK_TLV16) {
		/* TLV16 */
		/* Read additional 2 bytes of header */
		res = KSI_RDR_read(rdr, hdr + 2, 2, &readCount);
		if (res != KSI_OK) {
			KSI_fail(&err, res, NULL);
			goto cleanup;
		}
		if (readCount != 2) {
			KSI_fail(&err, KSI_INVALID_FORMAT, NULL);
			goto cleanup;
		}

		type = ((*hdr & KSI_TLV_MASK_TLV8_TYPE) << 8 ) | *(hdr + 1);
		length = (*(hdr + 2) << 8) | *(hdr + 3);
	} else {
		/* TLV8 */
		type = *hdr & KSI_TLV_MASK_TLV8_TYPE;
		length = *(hdr + 1);
	}

	/* Read payload. */
	KSI_RDR_read(rdr, buffer, length, &readCount);

	if (readCount != length) {
		KSI_fail(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	/* Create new TLV object. */
	res = KSI_TLV_new(rdr->ctx, NULL, 0, &t);
	if (res != KSI_OK) {
		KSI_fail(&err, res, NULL);
		goto cleanup;
	}

	t->type = type;

	/* Append raw data. */
	if (appendBlob(t, buffer, length) != length) {
		KSI_fail(&err, KSI_UNKNOWN_ERROR, "Unable to complete TLV object.");
		goto cleanup;
	}

	*tlv = t;
	t = NULL;

	KSI_success(&err);

cleanup:

	KSI_TLV_free(t);

	return KSI_end(&err);
}

/**
 *
 */
int KSI_TLV_getRawValue(KSI_TLV *tlv, unsigned char **buf, int *len, int copy) {
	KSI_ERR err;
	int res;
	char *ptr = NULL;
	size_t ptr_len;

	KSI_begin(tlv->ctx, &err);

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		res = encodeAsRaw(tlv);
		if (res != KSI_OK) {
			KSI_fail(&err, res, NULL);
			goto cleanup;
		}
	}

	if (copy) {
		ptr_len = tlv->payload.rawVal.length;
		ptr = KSI_calloc(ptr_len, 1);
		if (ptr == NULL) {
			KSI_fail(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		memcpy(ptr, tlv->payload.rawVal.ptr, tlv->payload.rawVal.length);

		*buf = ptr;
		ptr = NULL;

		*len = ptr_len;
	} else {
		*buf = tlv->payload.rawVal.ptr;
		*len = tlv->payload.rawVal.length;
	}

	KSI_success(&err);

cleanup:

	KSI_free(ptr);
	return KSI_end(&err);
}

/**
 *
 */
int KSI_TLV_getUInt64Value(KSI_TLV *tlv, uint64_t *val) {
	KSI_ERR err;
	int res;
	int value_len;
	uint64_t value;
	uint64_t mask;

	KSI_begin(tlv->ctx, &err);

	res = encodeAsUInt64(tlv);
	if (res != KSI_OK) {
		KSI_fail(&err, res, NULL);
		goto cleanup;
	}

	*val = tlv->payload.uintVal.value;

	KSI_success(&err);

cleanup:

	return KSI_end(&err);
}

/**
 *
 */
int KSI_TLV_getStringValue(KSI_TLV *tlv, char **buf, int copy) {
	KSI_ERR err;
	int res;
	char *value = NULL;

	KSI_begin(tlv->ctx, &err);

	res = encodeAsString(tlv);
	if (res != KSI_OK) {
		KSI_fail(&err, res, NULL);
		goto cleanup;
	}

	if (copy) {
		value = KSI_calloc(tlv->payload.rawVal.length + 1, 1);
		strncpy(value, tlv->payload.rawVal.ptr, tlv->payload.rawVal.length + 1);
	} else {
		value = tlv->payload.rawVal.ptr;
	}

	*buf = value;
	value = NULL;

	KSI_success(&err);

cleanup:

	KSI_free(value);

	return KSI_end(&err);
}
