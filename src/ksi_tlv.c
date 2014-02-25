#include <string.h>

#include "ksi_internal.h"
#include "ksi_tlv.h"

/**
 *
 */
static int createOwnBuffer(KSI_TLV *tlv, int copy) {
	KSI_ERR err;
	unsigned char *buf = NULL;
	int buf_size = 0xffff + 1;
	int buf_len = 0;

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

	if (copy) {
		if (tlv->payload.rawVal.ptr == NULL) {
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Cant copy data from NULL pointer.");
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

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(buf);

	return KSI_RETURN(&err);
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
static int readTlv(KSI_RDR *rdr, KSI_TLV **tlv, int copy) {
	int res;
	KSI_ERR err;
	unsigned char hdr[4];
	int readCount;
	KSI_TLV *t = NULL;
	size_t length = 0;
	int lenient = 0;
	int forward = 0;
	unsigned int type;
	unsigned char buffer[0xffff];
	unsigned char *ptr = NULL;
	char errstr[1024];


	KSI_BEGIN(rdr->ctx, &err);

	/* Read first two bytes */
	res = KSI_RDR_readIntoBuffer(rdr, hdr, 2, &readCount);
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

	lenient = *hdr & KSI_TLV_MASK_LENIENT;
	forward = *hdr & KSI_TLV_MASK_FORWARD;

	/* Is it a TLV8 or TLV16 */
	if (*hdr & KSI_TLV_MASK_TLV16) {
		/* TLV16 */
		/* Read additional 2 bytes of header */
		res = KSI_RDR_readIntoBuffer(rdr, hdr + 2, 2, &readCount);
		if (res != KSI_OK) {
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}
		if (readCount != 2) {
			KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
			goto cleanup;
		}

		type = ((*hdr & KSI_TLV_MASK_TLV8_TYPE) << 8 ) | *(hdr + 1);
		length = (*(hdr + 2) << 8) | *(hdr + 3);
	} else {
		/* TLV8 */
		type = *hdr & KSI_TLV_MASK_TLV8_TYPE;
		length = *(hdr + 1);
	}

	/* Get the payload. */
	if (rdr->ioType == KSI_IO_MEM && !copy) {
		/* At this point we will reuse the allocated memory. */
		res = KSI_RDR_readMemPtr(rdr, &ptr, length, &readCount);
	} else {
		/* Read and make a copy of the payload. */
		res = KSI_RDR_readIntoBuffer(rdr, buffer, length, &readCount);
	}

	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	if (readCount != length) {
		snprintf(errstr, sizeof(errstr), "Expected to read %d bytes, but got %d", (int)length, readCount);
		KSI_FAIL(&err, KSI_INVALID_FORMAT, errstr);
		goto cleanup;
	}

	/* Create new TLV object. */
	res = KSI_TLV_new(rdr->ctx, ptr, readCount, &t);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	t->type = type;

	if (ptr == NULL) {
		/* Append raw data. */
		if (appendBlob(t, buffer, length) != length) {
			KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Unable to complete TLV object.");
			goto cleanup;
		}
	}

	*tlv = t;
	t = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(ptr);
	KSI_TLV_free(t);

	return KSI_RETURN(&err);
}


/**
 *
 */
static int encodeAsRaw(KSI_TLV *tlv) {
	KSI_ERR err;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType == KSI_TLV_PAYLOAD_RAW) {
		KSI_SUCCESS(&err);
		goto cleanup;
	}

	KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Unimplemented method.");

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
static int encodeAsString(KSI_TLV *tlv) {
	int res;
	KSI_ERR err;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType == KSI_TLV_PAYLOAD_STR) {
		KSI_SUCCESS(&err);
		goto cleanup;
	}

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		res = encodeAsRaw(tlv);
		if (res != KSI_OK) {
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}
	}

	if (tlv->buffer == NULL) {
		/* Create local copy. */
		res = createOwnBuffer(tlv, 1);
		if (res != KSI_OK) {
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}
	}

	/* Make the buffer a null-terminated string, but do not change the actual size. */
	*(tlv->payload.rawVal.ptr + tlv->payload.rawVal.length) = '\0';

	tlv->payloadType = KSI_TLV_PAYLOAD_STR;
	tlv->payload.stringVal = tlv->payload.rawVal.ptr;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}
/**
 *
 */
static int encodeAsUInt64(KSI_TLV *tlv) {
	int res;
	KSI_ERR err;
	uint64_t value;
	int value_len;

	KSI_BEGIN(tlv->ctx, &err);

	/* Exit when already correct type. */
	if (tlv->payloadType == KSI_TLV_PAYLOAD_INT) {
		KSI_SUCCESS(&err);
		goto cleanup;
	}

	/* Convert the TLV into raw form */
	res = encodeAsRaw(tlv);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	/* Verify size of data - fail if overflow. */
	if (tlv->payload.rawVal.length < 1 || tlv->payload.rawVal.length > sizeof(uint64_t)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "TLV size not in range for integer value.");
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

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int appendLastSibling(KSI_TLV **first, KSI_TLV *tlv) {
	KSI_ERR err;

	KSI_BEGIN(tlv->ctx, &err);

	if (*first == NULL) {
		*first = tlv;
	} else {
		(*first)->last->next = tlv;
	}

	(*first)->last = tlv;

	KSI_SUCCESS(&err);

	return KSI_RETURN(&err);
}

int encodeAsNestedTlvs(KSI_TLV *tlv) {
	int res;
	KSI_ERR err;
	KSI_RDR *rdr = NULL;
	KSI_TLV *tmp = NULL;
	KSI_TLV *tlvList = NULL;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType == KSI_TLV_PAYLOAD_TLV) {
		KSI_SUCCESS(&err);
		goto cleanup;
	}

	res = encodeAsRaw(tlv);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	res = KSI_RDR_fromMem(tlv->ctx, tlv->payload.rawVal.ptr, tlv->payload.rawVal.length, 0, &rdr);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}
	/* Try parsing all of the nested TLV's. */
	while (1) {
		res = readTlv(rdr, &tmp, 0);
		if (res != KSI_OK) {
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}

		/* Check if end of reader. */
		if (tmp == NULL) break;

		res = appendLastSibling(&tlvList, tmp);
		if (res != KSI_OK) {
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}

		tmp = NULL;
	}

	tlv->payloadType = KSI_TLV_PAYLOAD_TLV;
	tlv->payload.tlv.current = tlv->payload.tlv.list = tlvList;
	tlvList = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RDR_close(rdr);
	KSI_TLV_free(tmp);
	KSI_TLV_free(tlvList);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_new(KSI_CTX *ctx, unsigned char *data, size_t data_len, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *t = NULL;

	KSI_BEGIN(ctx, &err);

	t = KSI_new(KSI_TLV);
	if (t == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	/* Initialize context. */
	t->ctx = ctx;
	/* Initialize the parameters with default values. */
	t->next = NULL;
	/* Last will point to itself. */
	t->last = t;
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
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}

		t->payload.rawVal.length = 0;
		t->payload.rawVal.ptr = t->buffer;
	}

	/* Update the out parameter. */
	*tlv = t;
	t = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(t);
	return KSI_RETURN(&err);
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

int KSI_TLV_fromReader(KSI_RDR *rdr, KSI_TLV **tlv) {
	/* Read the TLV and make a copy of the memory. */
	return readTlv(rdr, tlv, 1);
}


/**
 *
 */
int KSI_TLV_getRawValue(KSI_TLV *tlv, unsigned char **buf, int *len, int copy) {
	KSI_ERR err;
	int res;
	unsigned char *ptr = NULL;
	size_t ptr_len;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		res = encodeAsRaw(tlv);
		if (res != KSI_OK) {
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}
	}

	if (copy) {
		ptr_len = tlv->payload.rawVal.length;
		ptr = KSI_calloc(ptr_len, 1);
		if (ptr == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
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

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(ptr);
	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_getUInt64Value(KSI_TLV *tlv, uint64_t *val) {
	KSI_ERR err;
	int res;

	KSI_BEGIN(tlv->ctx, &err);

	res = encodeAsUInt64(tlv);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	*val = tlv->payload.uintVal.value;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_getStringValue(KSI_TLV *tlv, char **buf, int copy) {
	KSI_ERR err;
	int res;
	unsigned char *value = NULL;

	KSI_BEGIN(tlv->ctx, &err);

	res = encodeAsString(tlv);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	if (copy) {
		value = KSI_calloc(tlv->payload.rawVal.length + 1, 1);
		if (value == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		strncpy(value, tlv->payload.rawVal.ptr, tlv->payload.rawVal.length + 1);
	} else {
		value = tlv->payload.rawVal.ptr;
	}

	*buf = value;
	value = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(value);

	return KSI_RETURN(&err);
}

int KSI_TLV_getNextNestedTLV(KSI_TLV *tlv, const KSI_TLV **nested) {
	int res;
	KSI_ERR err;
	KSI_TLV *current = NULL;

	KSI_BEGIN(tlv->ctx, &err);

	res = encodeAsNestedTlvs(tlv);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	current = tlv->payload.tlv.current;

	/* Adwance the pointer. */
	if (current != NULL) {
		tlv->payload.tlv.current = current->next;
	}

	*nested = current;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_TLV_fromBlob(KSI_CTX *ctx, unsigned char *data, size_t data_length, KSI_TLV **tlv) {
	KSI_ERR err;
	KSI_RDR *rdr = NULL;
	KSI_TLV *t = NULL;

	int res;

	KSI_BEGIN(ctx, &err);

	res = KSI_RDR_fromMem(ctx, data, data_length, 0, &rdr);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_fromReader(rdr, &t);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	*tlv = t;
	t = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RDR_close(rdr);
	KSI_TLV_free(t);

	return KSI_RETURN(&err);
}
