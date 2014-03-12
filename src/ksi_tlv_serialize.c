#include <string.h>

#include "ksi_internal.h"
#include "ksi_tlv.h"

static int serializeTlv(KSI_TLV *tlv, unsigned char *buf, int *buf_free, int serializeHeader);

static int serializeRaw(KSI_TLV *tlv, unsigned char *buf, int *len) {
	KSI_ERR err;
	int payloadLength;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType != KSI_TLV_PAYLOAD_RAW && tlv->payloadType != KSI_TLV_PAYLOAD_STR) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	payloadLength = tlv->payload.rawVal.length;

	if (*len < payloadLength) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	memcpy(buf + *len - payloadLength, tlv->payload.rawVal.ptr, payloadLength);

	*len-=payloadLength;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int serializeUint(KSI_TLV *tlv, unsigned char *buf, int *buf_free) {
	KSI_ERR err;
	int i;
	unsigned char *ptr = buf + *buf_free - 1;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType != KSI_TLV_PAYLOAD_INT) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (*buf_free < tlv->payload.uintVal.length) {
		KSI_FAIL(&err, KSI_BUFFER_OVERFLOW, NULL);
		goto cleanup;
	}

	for (i = 0; i < sizeof(uint64_t) && (i == 0 || (tlv->payload.uintVal.value >> (i * 8))  > 0); i++) {
		*ptr-- = (tlv->payload.uintVal.value >> (i * 8)) & 0xff;
		--*buf_free;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int serializeTlvList(KSI_TLV_LIST *tlvListNode, unsigned char *buf, int *buf_free) {
	KSI_ERR err;
	int res;
	int bf = *buf_free;

	KSI_BEGIN(tlvListNode->tlv->ctx, &err);

	if (tlvListNode->next != NULL) {
		res = serializeTlvList(tlvListNode->next, buf, &bf);
		if (res != KSI_OK) {
			KSI_FAIL(&err, res, NULL);
			goto cleanup;
		}
	}

	res = serializeTlv(tlvListNode->tlv, buf, &bf, 1);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	*buf_free = bf;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int serializeNested(KSI_TLV *tlv, unsigned char *buf, int *buf_free) {
	KSI_ERR err;
	int res;
	int bf = *buf_free;

	KSI_BEGIN(tlv->ctx, &err);

	if (tlv->payloadType != KSI_TLV_PAYLOAD_TLV) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (tlv->nested != NULL) {
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

static int serializePayload(KSI_TLV *tlv, unsigned char *buf, int *buf_free) {
	KSI_ERR err;
	int res;
	int bf = *buf_free;

	KSI_BEGIN(tlv->ctx, &err);

	switch (tlv->payloadType) {
		case KSI_TLV_PAYLOAD_RAW:
		case KSI_TLV_PAYLOAD_STR:
			res = serializeRaw(tlv, buf, &bf);
			break;
		case KSI_TLV_PAYLOAD_INT:
			res = serializeUint(tlv, buf, &bf);
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

static int serializeTlv(KSI_TLV *tlv, unsigned char *buf, int *buf_free, int serializeHeader) {
	KSI_ERR err;
	int res;
	int bf = *buf_free;
	int payloadLength;
	unsigned char *ptr;

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
			bf -= 4;
			if (bf < 0) {
				KSI_FAIL(&err, KSI_BUFFER_OVERFLOW, NULL);
				goto cleanup;
			}
			*ptr-- = 0xff & payloadLength;
			*ptr-- = 0xff & payloadLength >> 8;
			*ptr-- = tlv->tag & 0xff;
			*ptr-- = KSI_TLV_MASK_TLV16 | (KSI_TLV_MASK_LENIENT * tlv->isLenient) | (KSI_TLV_MASK_FORWARD * tlv->isForwardable) | (tlv->tag >> 8);

		} else {
			/* Encode as TLV8 */
			bf -= 2;
			if (bf < 0) {
				KSI_FAIL(&err, KSI_BUFFER_OVERFLOW, NULL);
				goto cleanup;
			}
			*ptr-- = payloadLength & 0xff;
			*ptr-- = 0x00 | (KSI_TLV_MASK_LENIENT * tlv->isLenient) | (KSI_TLV_MASK_FORWARD * tlv->isForwardable) | tlv->tag;
		}
	}

	*buf_free = bf;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int serialize(KSI_TLV *tlv, unsigned char *buf, int *len, int serializeHeader) {
	KSI_ERR err;
	int res;
	int bf = *len;
	int payloadLength;
	unsigned char *ptr;
	int i;

	KSI_BEGIN(tlv->ctx, &err);

	res = serializeTlv(tlv, buf, &bf, serializeHeader);
	if (res != KSI_OK) {
		KSI_FAIL(&err, res, NULL);
		goto cleanup;
	}

	payloadLength = *len - bf;
	/* Move the serialized value to the begin of the buffer. */
	ptr = buf;
	for (i = 0; i < payloadLength; i++) {
		*ptr++ = *(buf + bf + i);
	}

	*len = (int)(ptr - buf);

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(ptr);

	return KSI_RETURN(&err);
}

int KSI_TLV_serialize_ex(KSI_TLV *tlv, unsigned char *buf, int buf_size, int *len) {
	int res;
	int buf_free = buf_size;

	res = serialize(tlv, buf, &buf_free, 1);
	if (res != KSI_OK) goto cleanup;

	*len = buf_free;

cleanup:

	return res;
}

int KSI_TLV_serialize(KSI_TLV *tlv, unsigned char **outBuf, int *outBuf_len) {
	int res;
	unsigned char tmp[0xffff + 4];
	int tmp_len;

	unsigned char *buf = NULL;

	res = KSI_TLV_serialize_ex(tlv, tmp, sizeof(tmp), &tmp_len);
	if (res != KSI_OK) goto cleanup;

	buf = KSI_calloc(tmp_len, 1);
	if (buf == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	memcpy(buf, tmp, tmp_len);

	*outBuf = buf;
	*outBuf_len = tmp_len;

	buf = NULL;

cleanup:

	KSI_free(buf);

	return res;
}

int KSI_TLV_serializePayload(KSI_TLV *tlv, unsigned char *buf, int *len) {
	return serialize(tlv, buf, len, 0);
}
