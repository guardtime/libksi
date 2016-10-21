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

#include <string.h>

#include "tlv_element.h"
#include "internal.h"

KSI_IMPLEMENT_LIST(KSI_TlvElement, KSI_TlvElement_free);
KSI_IMPLEMENT_REF(KSI_TlvElement);

#define HDR_LEN(tag, dat_len) (((tag) > 0x1f || (dat_len) > 0xff) ? 4 : 2)

int KSI_TlvElement_new(KSI_TlvElement **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TlvElement *tmp = NULL;

	tmp = KSI_new(KSI_TlvElement);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	memset(tmp, 0, sizeof(KSI_TlvElement));

	/* Correct way to indicate reference. */
	tmp->ref = 1;

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TlvElement_free(tmp);

	return res;
}

int KSI_TlvElement_parse(unsigned char *dat, size_t dat_len, KSI_TlvElement **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TlvElement *tmp = NULL;

	if ((dat == NULL && dat_len != 0) || out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_new(&tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_FTLV_memRead(dat, dat_len, &tmp->ftlv);
	if (res != KSI_OK) goto cleanup;

	tmp->ptr = dat;
	tmp->ptr_own = 0;

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TlvElement_free(tmp);

	return res;
}
static int remap(KSI_TlvElement *el, unsigned char *buf, size_t buf_len) {
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *ptr = buf;
	size_t len = buf_len;
	KSI_FTLV ftlv;
	size_t i;

	if (el == NULL || buf == NULL || buf_len == 0) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&ftlv, 0, sizeof(ftlv));

	res = KSI_FTLV_memRead(buf, buf_len, &ftlv);
	if (res != KSI_OK) goto cleanup;

	if (ftlv.tag != el->ftlv.tag) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	ptr += ftlv.hdr_len;
	len -= ftlv.hdr_len;

	if (el->subList != NULL) {
		for (i = 0; i < KSI_TlvElementList_length(el->subList); i++) {
			KSI_TlvElement *pSub = NULL;
			size_t consumed = 0;

			res = KSI_TlvElementList_elementAt(el->subList, i, &pSub);
			if (res != KSI_OK || pSub == NULL) {
				if (res == KSI_OK) res = KSI_INVALID_STATE;
				goto cleanup;
			}

			res = remap(pSub, ptr, len);
			if (res != KSI_OK) goto cleanup;

			consumed = pSub->ftlv.hdr_len + pSub->ftlv.dat_len;

			if (consumed > len) {
				res = KSI_INVALID_STATE;
				goto cleanup;
			}
			ptr += consumed;
			len -= consumed;
		}
	} else {
		memmove(ptr, el->ptr, len);
	}
	if (el->ptr_own) {
		KSI_free(el->ptr);
	}

	el->ftlv = ftlv;
	el->ptr_own = 0;
	el->ptr = buf;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_TlvElement_detach(KSI_TlvElement *el) {
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *buf = NULL;
	size_t len;


	res = KSI_TlvElement_serialize(el, NULL, 0, &len, 0);
	if (res != KSI_OK) goto cleanup;

	buf = KSI_malloc(len);
	if (buf == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = KSI_TlvElement_serialize(el, buf, len, &len, 0);
	if (res != KSI_OK) goto cleanup;

	res = remap(el, buf, len);
	if (res != KSI_OK) goto cleanup;

	el->ptr_own = 1;
	buf = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(buf);

	return res;
}

void KSI_TlvElement_free(KSI_TlvElement *t) {
	if (t != NULL) {
		if (t->ref <= 1) {
			KSI_TlvElementList_free(t->subList);

			if (t->ptr_own) KSI_free(t->ptr);

			/* When ref_count == 0 we assume this is a stacked instance of the object. */
			if (t->ref != 0) {
				KSI_free(t);
			}
		} else {
			--t->ref;
		}
	}
}

int KSI_TlvElement_serialize(KSI_TlvElement *element, unsigned char *buf, size_t buf_size, size_t *len, int opt) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	size_t dat_len = 0;
	size_t hdr_len = 0;

	if (element == NULL || (buf == NULL && buf_size != 0)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (element->subList == NULL || KSI_TlvElementList_length(element->subList) == 0) {
		dat_len = element->ftlv.dat_len;

		if (buf != NULL) {
			if (buf_size <= element->ftlv.dat_len) {
				res = KSI_BUFFER_OVERFLOW;
				goto cleanup;
			}


			if (dat_len != 0) {
				memcpy(buf + buf_size - dat_len, element->ptr + element->ftlv.hdr_len, dat_len);
			}
		}
	} else {
		size_t tmpLen = 0;
		for (i = KSI_TlvElementList_length(element->subList); i > 0; i--) {
			KSI_TlvElement *tmp = NULL;

			res = KSI_TlvElementList_elementAt(element->subList, i - 1, &tmp);
			if (res != KSI_OK) goto cleanup;

			/* Get the size of the element. */
			res = KSI_TlvElement_serialize(tmp, NULL, 0, &tmpLen, 0);
			if (res != KSI_OK) goto cleanup;

			if (buf != NULL) {
				res = KSI_TlvElement_serialize(tmp, buf + buf_size - dat_len - tmpLen, tmpLen, NULL, KSI_TLV_OPT_NO_MOVE);
				if (res != KSI_OK) goto cleanup;
			}

			dat_len += tmpLen;
		}
	}

	/* Calculate the header length only if the header is required. */
	if ((opt & KSI_TLV_OPT_NO_HEADER) == 0) {
		hdr_len = HDR_LEN(element->ftlv.tag, dat_len);
	}

	if (buf != NULL) {
		size_t startIdx;

		if (hdr_len + dat_len > buf_size) {
			res = KSI_BUFFER_OVERFLOW;
			goto cleanup;
		}

		startIdx = buf_size - dat_len;

		if ((opt & KSI_TLV_OPT_NO_HEADER) == 0) {
			startIdx--;
			if (hdr_len == 4) {
				buf[startIdx--] = element->ftlv.dat_len & 0xff;
				buf[startIdx--] = (element->ftlv.dat_len >> 8) & 0xff;
				buf[startIdx--] = element->ftlv.tag & 0xff;
				buf[startIdx] = (element->ftlv.tag >> 8) & KSI_TLV_MASK_TLV8_TYPE;
				buf[startIdx] |= KSI_TLV_MASK_TLV16;
			} else {
				buf[startIdx--] = element->ftlv.dat_len & 0xff;
				buf[startIdx] = element->ftlv.tag & KSI_TLV_MASK_TLV8_TYPE;
			}

			if (element->ftlv.is_fwd) buf[startIdx] |= KSI_TLV_MASK_FORWARD;
			if (element->ftlv.is_nc) buf[startIdx] |= KSI_TLV_MASK_LENIENT;
		}

		if ((opt & KSI_TLV_OPT_NO_MOVE) == 0) {
			memmove(buf, buf + startIdx, hdr_len + dat_len);
		}
	}

	if (len != NULL) *len = hdr_len + dat_len;

	res = KSI_OK;

cleanup:

	return res;
}

static int convertToNested(KSI_TlvElement *el) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(KSI_TlvElement) *list = NULL;
	KSI_TlvElement *tmp = NULL;

	if (el == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (el->subList == NULL) {
		/* The pointer points to the header of the TLV not the data itself. */
		unsigned char *ptr = el->ptr + el->ftlv.hdr_len;
		size_t len = el->ftlv.dat_len;

		res = KSI_TlvElementList_new(&list);
		if (res != KSI_OK) goto cleanup;

		while (len > 0) {
			size_t consumed = 0;

			res = KSI_TlvElement_parse(ptr, len, &tmp);
			if (res != KSI_OK) goto cleanup;

			consumed = tmp->ftlv.dat_len + tmp->ftlv.hdr_len;

			res = KSI_TlvElementList_append(list, tmp);
			if (res != KSI_OK) goto cleanup;

			tmp = NULL;

			if (len < consumed) {
				res = KSI_INVALID_FORMAT;
				goto cleanup;
			}

			len -= consumed;
			ptr += consumed;
		}

		el->subList = list;
		list = NULL;
	}

	res = KSI_OK;

cleanup:

	return res;
}

struct filter_st {
	void *filters;
	size_t filters_len;
	KSI_LIST(KSI_TlvElement) *result;
};

static int filter_tags(KSI_TlvElement *el, void *filterCtx) {
	int res = KSI_UNKNOWN_ERROR;
	struct filter_st *fc = filterCtx;
	unsigned *tags;
	size_t i;

	if (el == NULL || fc == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tags = fc->filters;

	if (fc->result == NULL) {
		res = KSI_TlvElementList_new(&fc->result);
		if (res != KSI_OK) goto cleanup;
	}

	for (i = 0; i < fc->filters_len; i++) {
		if (el->ftlv.tag == tags[i]) {
			KSI_TlvElement *ref = NULL;
			res = KSI_TlvElementList_append(fc->result, ref = KSI_TlvElement_ref(el));
			if (res != KSI_OK) {
				/* Cleanup the reference. */
				KSI_TlvElement_free(ref);

				goto cleanup;
			}
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_TlvElement_appendElement(KSI_TlvElement *parent, KSI_TlvElement *child) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TlvElement *ref = NULL;

	if (parent == NULL || child == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = convertToNested(parent);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TlvElementList_append(parent->subList, ref = KSI_TlvElement_ref(child));
	if (res != KSI_OK) {
		/* Cleanup the reference. */
		KSI_TlvElement_free(ref);

		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_TlvElement_setElement(KSI_TlvElement *parent, KSI_TlvElement *child) {
	int res = KSI_UNKNOWN_ERROR;
	size_t *pos = NULL;
	struct filter_st fc;
	KSI_TlvElement *ptr = NULL;

	fc.filters = NULL;
	fc.filters_len = 0;
	fc.result = NULL;

	if (parent == NULL || child == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = convertToNested(parent);
	if (res != KSI_OK) goto cleanup;

	fc.filters = &child->ftlv.tag;
	fc.filters_len = 1;


	res = KSI_TlvElementList_foldl(parent->subList, &fc, filter_tags);
	if (res != KSI_OK) goto cleanup;

	switch (KSI_TlvElementList_length(fc.result)) {
		case 0: /* Add a new value. */
			res = KSI_TlvElement_appendElement(parent, child);
			if (res != KSI_OK) goto cleanup;
			break;
		case 1: /* Replace the existing value. */
			res = KSI_TlvElementList_elementAt(fc.result, 0, &ptr);
			if (res != KSI_OK) goto cleanup;

			res = KSI_TlvElementList_indexOf(parent->subList, ptr, &pos);
			if (res != KSI_OK) goto cleanup;

			if (pos == NULL) {
				res = KSI_INVALID_STATE;
				goto cleanup;
			}

			{
				KSI_TlvElement *ref = NULL;
				res = KSI_TlvElementList_replaceAt(parent->subList, *pos, ref = KSI_TlvElement_ref(child));
				if (res != KSI_OK) {
					/* Cleanup the reference. */
					KSI_TlvElement_free(ref);

					goto cleanup;
				}
			}
			break;
		default:
			/* More than one result, we have no idea what to do. */
			res = KSI_INVALID_STATE;
			goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_free(pos);
	KSI_TlvElementList_free(fc.result);

	return res;
}

int KSI_TlvElement_getElement(KSI_TlvElement *parent, unsigned tag, KSI_TlvElement **el) {
	int res = KSI_UNKNOWN_ERROR;
	struct filter_st fc;
	KSI_TlvElement *tmp = NULL;

	fc.filters = NULL;
	fc.filters_len = 0;
	fc.result = NULL;

	if (parent == NULL || el == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = convertToNested(parent);
	if (res != KSI_OK) goto cleanup;

	fc.filters = &tag;
	fc.filters_len = 1;

	res = KSI_TlvElementList_foldl(parent->subList, &fc, filter_tags);
	if (res != KSI_OK) goto cleanup;

	switch (KSI_TlvElementList_length(fc.result)) {
		case 0:
			/* Nothing to do - tag not found.*/
			break;
		case 1:
			res = KSI_TlvElementList_elementAt(fc.result, 0, &tmp);
			if (res != KSI_OK) goto cleanup;

			*el = KSI_TlvElement_ref(tmp);

			break;
		default:
			/* More than one result, we have no idea what to do. */
			res = KSI_INVALID_STATE;
			goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_TlvElementList_free(fc.result);

	return res;
}

int KSI_TlvElement_getUtf8String(KSI_TlvElement *parent, KSI_CTX *ctx, unsigned tag, KSI_Utf8String **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TlvElement *el = NULL;
	KSI_Utf8String *tmp = NULL;
	unsigned char buf[0xffff + 4];
	size_t len;

	if (parent == NULL || out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_getElement(parent, tag, &el);
	if (res != KSI_OK) goto cleanup;

	if (el != NULL) {
		res = KSI_TlvElement_serialize(el, buf, sizeof(buf), &len, KSI_TLV_OPT_NO_HEADER);
		if (res != KSI_OK) goto cleanup;

		res = KSI_Utf8String_new(ctx, (char *)buf, len, &tmp);
		if (res != KSI_OK) goto cleanup;
	}

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TlvElement_free(el);
	KSI_Utf8String_free(tmp);

	return res;
}

int KSI_TlvElement_getOctetString(KSI_TlvElement *parent, KSI_CTX *ctx, unsigned tag, KSI_OctetString **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TlvElement *el = NULL;
	KSI_OctetString *tmp = NULL;
	unsigned char buf[0xffff + 4];
	size_t len;

	if (parent == NULL || out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_getElement(parent, tag, &el);
	if (res != KSI_OK) goto cleanup;

	if (el != NULL) {
		res = KSI_TlvElement_serialize(el, buf, sizeof(buf), &len, KSI_TLV_OPT_NO_HEADER);
		if (res != KSI_OK) goto cleanup;

		res = KSI_OctetString_new(ctx, buf, len, &tmp);
		if (res != KSI_OK) goto cleanup;
	}

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TlvElement_free(el);
	KSI_OctetString_free(tmp);

	return res;
}

int KSI_TlvElement_getInteger(KSI_TlvElement *parent, KSI_CTX *ctx, unsigned tag, KSI_Integer **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TlvElement *el = NULL;
	KSI_Integer *tmp = NULL;
	unsigned char buf[0xffff + 4];
	size_t len;
	size_t i;
	KSI_uint64_t val = 0;

	if (parent == NULL || out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_getElement(parent, tag, &el);
	if (res != KSI_OK) goto cleanup;

	if (el != NULL) {
		if (el->ftlv.dat_len > 8 ) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}

		res = KSI_TlvElement_serialize(el, buf, sizeof(buf), &len, KSI_TLV_OPT_NO_HEADER);
		if (res != KSI_OK) goto cleanup;

		for (i = 0; i < len; i++) {
			val = (val << 8) | buf[i];
		}

		res = KSI_Integer_new(ctx, val, &tmp);
		if (res != KSI_OK) goto cleanup;
	}

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TlvElement_free(el);
	KSI_Integer_free(tmp);

	return res;
}

int KSI_TlvElement_setUtf8String(KSI_TlvElement *parent, unsigned tag, KSI_Utf8String *s) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TlvElement *el = NULL;

	if (parent == NULL || s == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_new(&el);
	if (res != KSI_OK) goto cleanup;

	el->ftlv.tag = tag;
	el->ftlv.dat_len = KSI_Utf8String_size(s);
	el->ptr_own = 0;
	el->ptr = (unsigned char *)KSI_Utf8String_cstr(s);

	res = KSI_TlvElement_detach(el);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TlvElement_setElement(parent, el);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	KSI_TlvElement_free(el);

	return res;
}

int KSI_TlvElement_setInteger(KSI_TlvElement *parent, unsigned tag, KSI_Integer *s) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TlvElement *el = NULL;
	unsigned char buf[8];
	KSI_uint64_t val;

	if (parent == NULL || s == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TlvElement_new(&el);
	if (res != KSI_OK) goto cleanup;

	el->ftlv.tag = tag;
	el->ftlv.dat_len = 0;
	el->ptr_own = 0;
	el->ptr = NULL;

	val = KSI_Integer_getUInt64(s);

	while (val > 0 && el->ftlv.dat_len < sizeof(buf)) {
		buf[sizeof(buf) - ++el->ftlv.dat_len] = val & 0xff;
		val >>= 8;
	}

	if (val != 0) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	if (el->ftlv.dat_len > 0) {
		el->ptr = buf + sizeof(buf)  - el->ftlv.dat_len;
	}

	res = KSI_TlvElement_detach(el);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TlvElement_setElement(parent, el);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	KSI_TlvElement_free(el);

	return res;
}

