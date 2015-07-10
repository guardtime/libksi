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

#include <stdlib.h>

#include "io.h"
#include "internal.h"
#include "fast_tlv.h"

typedef int (*reader_t)(void *, unsigned char *, size_t, size_t *);

static int parseHdr(const unsigned char *hdr, size_t hdrLen, struct fast_tlv_s *t) {
	int res = KSI_UNKNOWN_ERROR;

	if (hdr == NULL || t == NULL) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	t->tag = hdr[0] & KSI_TLV_MASK_TLV8_TYPE;

	if (hdr[0] & KSI_TLV_MASK_TLV16) {
		if (hdrLen != 4) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}
		t->tag = ((t->tag << 8) | hdr[1]);
		t->dat_len = ((hdr[2] << 8) | hdr[3]) & 0xffff;
	} else {
		if (hdrLen != 2) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}
		t->dat_len = hdr[1];
	}

	t->hdr_len = hdrLen;
	t->is_nc = (hdr[0] & KSI_TLV_MASK_LENIENT) != 0;
	t->is_fwd = (hdr[0] & KSI_TLV_MASK_FORWARD) != 0;

	res = KSI_OK;

cleanup:

	return res;
}


int readData(void *fd, unsigned char *buf, size_t len, size_t *consumed, struct fast_tlv_s *t, reader_t read_fn) {
	int res = KSI_UNKNOWN_ERROR;
	size_t rd;
	size_t count = 0;

	if (fd == NULL || buf == NULL || len < 2 || t == NULL || read_fn == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	rd = 0;
	res = read_fn(fd, buf, 2, &rd);
	count += rd;
	if (res != KSI_OK) goto cleanup;

	if (rd != 2) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	if (buf[0] & KSI_TLV_MASK_TLV16) {
		if (len < 4) {
			res = KSI_BUFFER_OVERFLOW;
			goto cleanup;
		}

		rd = 0;
		res = read_fn(fd, buf + 2, 2, &rd);
		count += rd;
		if (res != KSI_OK) goto cleanup;

		if (rd != 2) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}

		res = parseHdr(buf, 4, t);
		if (res != KSI_OK) goto cleanup;

	} else {
		res = parseHdr(buf, 2, t);
		if (res != KSI_OK) goto cleanup;
	}

	if (len < t->hdr_len + t->dat_len) {
		res = KSI_BUFFER_OVERFLOW;
		goto cleanup;
	}

	if (t->dat_len > 0) {
		unsigned char *datap = buf + t->hdr_len;
		rd = 0;
		res = read_fn(fd, datap, t->dat_len, &rd);
		count += rd;
		if (res != KSI_OK) goto cleanup;

		if (rd != t->dat_len) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}
	}

	res = KSI_OK;

cleanup:

	if (consumed != NULL) *consumed = count;

	return res;
}

int KSI_FTLV_fileRead(FILE *f, unsigned char *buf, size_t len, size_t *consumed, struct fast_tlv_s *t) {
	return readData(f, buf, len, consumed, t, (reader_t) KSI_IO_readFile);
}

static int wrapSocketRead(int *fd, unsigned char *buf, size_t len, size_t *consumed) {
	return KSI_IO_readSocket(*fd, buf, len, consumed);
}

int KSI_FTLV_socketRead(int fd, unsigned char *buf, size_t len, size_t *consumed, KSI_FTLV *t) {
	return readData(&fd, buf, len, consumed, t, (reader_t) wrapSocketRead);
}

int KSI_FTLV_memRead(const unsigned char *m, size_t l, KSI_FTLV *t) {
	int res = KSI_UNKNOWN_ERROR;

	if (m == NULL || l < 2 || t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Initialize offset. */
	t->off = 0;

	if (m[0] & KSI_TLV_MASK_TLV16) {
		if (l < 4) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}
		res = parseHdr(m, 4, t);
		if (res != KSI_OK) goto cleanup;
	} else {
		res = parseHdr(m, 2, t);
		if (res != KSI_OK) goto cleanup;
	}

	if (l < t->hdr_len + t->dat_len) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_FTLV_memReadN(const unsigned char *buf, size_t buf_len, KSI_FTLV *arr, size_t arr_len, size_t *rd) {
	int res = KSI_UNKNOWN_ERROR;
	const unsigned char *ptr = buf;
	size_t len = buf_len;
	size_t i = 0;
	/* Dummy buffer, used if arr == NULL. */
	KSI_FTLV dummy;
	size_t off = 0;

	if (buf == NULL || buf_len == 0 || (arr != NULL && arr_len == 0) || (arr == NULL && arr_len != 0)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Read up-to arr_len tlvs from the buffer. */
	while ((arr_len == 0 || i < arr_len) && len > 0) {
		size_t tlvLen;
		KSI_FTLV *target = (arr == NULL ? &dummy : &arr[i]);

		/* Read the next tlv. */
		res = KSI_FTLV_memRead(ptr, len, target);
		if (res != KSI_OK) goto cleanup;

		target->off = off;

		/* Calculate consumed bytes. */
		tlvLen = target->hdr_len + target->dat_len;

		ptr += tlvLen;
		len -= tlvLen;
		off += tlvLen;
		++i;
	}

	/* If the output variable is set, evaluate it. */
	if (rd != NULL) {
		*rd = i;
	}

	res = KSI_OK;

cleanup:

	return res;
}
