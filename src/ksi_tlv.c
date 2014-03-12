#include <string.h>


#include "ksi_internal.h"
#include "ksi_tlv.h"

static void tlvList_free(KSI_TLV_LIST *list) {
	KSI_TLV_LIST *tmp = NULL;

	if (list == NULL) return;

	while (list != NULL) {
		tmp = list->next;
		KSI_nofree(list->last);
		KSI_TLV_free(list->tlv);
		KSI_free(list);
		list = tmp;
	}
}

static int tlvList_new(KSI_TLV *tlv, KSI_TLV_LIST **node) {
	KSI_ERR err;
	KSI_TLV_LIST *n = NULL;

	KSI_BEGIN(tlv->ctx, &err);

	n = KSI_new(KSI_TLV_LIST);
	if (n == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	n->tlv = tlv;
	n->next = NULL;
	n->last = n;

	*node = n;
	n = NULL;

	KSI_SUCCESS(&err);

cleanup:

	tlvList_free(n);

	return KSI_RETURN(&err);
}
/**
 *
 */
static int getUintLen(uint64_t uint) {
	int i;
	for (i = sizeof(uint64_t); i > 1; i--) {
		if (uint >> ((i - 1) * 8)) {
			break;
		}
	}
	return i;
}
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
static int appendBlob(KSI_TLV *tlv, unsigned char *data, size_t data_length) {
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
	int isLenient = 0;
	int isForward = 0;
	unsigned int tag;
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

	isLenient = *hdr & KSI_TLV_MASK_LENIENT;
	isForward = *hdr & KSI_TLV_MASK_FORWARD;

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

		tag = ((*hdr & KSI_TLV_MASK_TLV8_TYPE) << 8 ) | *(hdr + 1);
		length = (*(hdr + 2) << 8) | *(hdr + 3);
	} else {
		/* TLV8 */
		tag = *hdr & KSI_TLV_MASK_TLV8_TYPE;
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
	res = KSI_TLV_new(rdr->ctx,tag, isLenient, isForward,  ptr, readCount, 0, &t);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

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
	int res;
	int payloadLength;
	unsigned char *buf = NULL;
	int buf_size = 0;

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

	tlv->payload.rawVal.ptr = buf;
	tlv->payload.rawVal.length = payloadLength;

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

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType == KSI_TLV_PAYLOAD_STR) {
		KSI_SUCCESS(&err);
		goto cleanup;
	}

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
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

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}
/**
 *
 */
static int encodeAsUInt64(KSI_TLV *tlv) {
	KSI_ERR err;
	uint64_t value;
	int value_len;

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

static int appendLastSibling(KSI_TLV_LIST **list, KSI_TLV *tlv) {
	KSI_ERR err;
	KSI_TLV_LIST *node = NULL;
	int res;

	KSI_BEGIN(tlv->ctx, &err);

	res = tlvList_new(tlv, &node);

	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	if (*list == NULL) {
		*list = node;
	} else {
		(*list)->last->next = node;
	}

	(*list)->last = node;
	node = NULL;

	KSI_SUCCESS(&err);

cleanup:

	tlvList_free(node);

	return KSI_RETURN(&err);
}

static int encodeAsNestedTlvs(KSI_TLV *tlv) {
	int res;
	KSI_ERR err;
	KSI_RDR *rdr = NULL;
	KSI_TLV *tmp = NULL;
	KSI_TLV_LIST *tlvList = NULL;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType == KSI_TLV_PAYLOAD_TLV) {
		KSI_SUCCESS(&err);
		goto cleanup;
	}

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
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
	tlv->nested = tlvList;
	tlv->payload.tlv.current = tlvList;
	tlvList = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RDR_close(rdr);
	KSI_TLV_free(tmp);
	tlvList_free(tlvList);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_new(KSI_CTX *ctx, int tag, int isLenient, int isForward, unsigned char *data, size_t data_len, int copy, KSI_TLV **tlv) {
	KSI_ERR err;
	KSI_TLV *t = NULL;

	KSI_BEGIN(ctx, &err);

	t = KSI_new(KSI_TLV);
	if (t == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	/* Initialize context. */
	t->ctx = ctx;
	t->tag = tag;
	/* Make sure the values are *only* 1 or 0. */
	t->isLenient = isLenient ? 1 : 0;
	t->isForwardable = isForward ? 1 : 0;

	t->payloadType = KSI_TLV_PAYLOAD_RAW;
	t->nested = NULL;

	if (data != NULL && !copy) {
		t->buffer_size = 0;
		t->buffer = NULL;

		t->payload.rawVal.length = data_len;
		t->payload.rawVal.ptr = data;
	} else {
		t->buffer_size = 0xffff + 1;
		t->buffer = KSI_calloc(t->buffer_size, 1);
		if (t->buffer == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		t->payload.rawVal.ptr = t->buffer;
		if (data != NULL) {
			memcpy(t->buffer, data, data_len);
			t->payload.rawVal.length = data_len;
		} else {
			t->payload.rawVal.length = 0;
		}
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
	if (tlv != NULL) {
		KSI_free(tlv->buffer);

		/* Free nested data */
		tlvList_free(tlv->nested);
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
	unsigned char *ptr = NULL;
	size_t ptr_len;

	KSI_BEGIN(tlv->ctx, &err);

	/* Check payload type. */
	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
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

	KSI_BEGIN(tlv->ctx, &err);

	/* Check payload type. */
	if (tlv->payloadType != KSI_TLV_PAYLOAD_INT) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
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
	unsigned char *value = NULL;

	KSI_BEGIN(tlv->ctx, &err);

	/* Check payload type. */
	if (tlv->payloadType != KSI_TLV_PAYLOAD_STR) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	if (copy) {
		value = KSI_calloc(tlv->payload.rawVal.length + 1, 1);
		if (value == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		strncpy(value, (char *) tlv->payload.rawVal.ptr, tlv->payload.rawVal.length + 1);
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

/**
 *
 */
int KSI_TLV_getNextNestedTLV(KSI_TLV *tlv, KSI_TLV **nested) {
	KSI_ERR err;
	KSI_TLV_LIST *current = NULL;

	KSI_BEGIN(tlv->ctx, &err);

	/* Check payload type. */
	if (tlv->payloadType != KSI_TLV_PAYLOAD_TLV) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	current = tlv->payload.tlv.current;

	/* Adwance the pointer. */
	if (current != NULL) {
		tlv->payload.tlv.current = current->next;
		*nested = current->tlv;
	} else {
		tlv->payload.tlv.current = NULL;
		*nested = NULL;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TLV_parseBlob(KSI_CTX *ctx, unsigned char *data, size_t data_length, KSI_TLV **tlv) {
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

/**
 *
 */
int KSI_TLV_cast(KSI_TLV *tlv, enum KSI_TLV_PayloadType_en payloadType) {
	KSI_ERR err;

	int res;

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
int KSI_TLV_fromUint(KSI_CTX *ctx, int tag, int isLenient, int isForward, uint64_t uint, KSI_TLV **tlv) {
	KSI_ERR err;
	KSI_TLV *t = NULL;
	int res;

	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, tag, isLenient, isForward, NULL, 0, 0, &t);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	t->payloadType = KSI_TLV_PAYLOAD_INT;
	t->payload.uintVal.length = getUintLen(uint);
	t->payload.uintVal.value = uint;

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
int KSI_TLV_fromString(KSI_CTX *ctx, int tag, int isLenient, int isForward, char *str, KSI_TLV **tlv) {
	KSI_ERR err;
	KSI_TLV *t = NULL;
	int res;

	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, tag, isLenient, isForward, NULL, 0, 0, &t);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	appendBlob(t, str, strlen(str));

	KSI_TLV_cast(t, KSI_TLV_PAYLOAD_STR);
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
int KSI_TLV_isLenient(KSI_TLV *tlv) {
	return tlv->isLenient;
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
int KSI_TLV_getType(KSI_TLV *tlv) {
	return tlv->tag;
}

/**
 *
 */
int KSI_TLV_appendNestedTLV(KSI_TLV *target, KSI_TLV *after, KSI_TLV *tlv) {
	KSI_ERR err;
	KSI_TLV_LIST *appendAfter = NULL;
	KSI_TLV_LIST *tmp = NULL;
	KSI_TLV_LIST *node = NULL;
	int res;

	KSI_BEGIN(target->ctx, &err);

	if (tlv == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Can't add a NULL pointer as a nested TLV");
		goto cleanup;
	}

	if (target->payloadType != KSI_TLV_PAYLOAD_TLV) {
		KSI_FAIL(&err, KSI_TLV_PAYLOAD_TYPE_MISMATCH, NULL);
		goto cleanup;
	}

	if (after != NULL) {
		/* Make sure the TLV is nested in this outer the TLV */
		tmp = target->nested;
		while (tmp != NULL) {
			if (tmp->tlv == after) {
				appendAfter = tmp;
				break;
			}
			tmp = tmp->next;
		}

		if (appendAfter == NULL) {
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Supposed nested TLV is not an immediately nested in the outer TLV.");
			goto cleanup;
		}
	}

	res = tlvList_new(tlv, &node);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	if (appendAfter != NULL) {
		node->next = appendAfter->next;
		appendAfter->next = node;
		if (node->next == NULL) {
			target->nested->last = node;
		}
	} else {
		if (target->nested == NULL) {
			target->nested = node;
		} else {
			target->nested->last->next = node;
		}
		target->nested->last = node;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

