#include "ksi_internal.h"

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

	/* Initialize the parameters with default values. */
	t->next = NULL;
	t->isLenient = 0;
	t->isForwardable = 0;

	t->encoding = KSI_TLV_ENC_RAW;

	if (data != NULL) {
		t->buffer_size = 0;
		t->buffer = NULL;

		t->encode.rawVal.length = data_len;
		t->encode.rawVal.ptr = data;
	} else {
		t->buffer_size = 0xffff; /* Max size of the buffer. */
		t->buffer = KSI_calloc(t->buffer_size, 1);
		if (t->buffer == NULL) {
			KSI_fail(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		t->encode.rawVal.length = 0;
		t->encode.rawVal.ptr = t->buffer;
	}

	/* Update the out parameter. */
	*tlv = t;
	t = NULL;

	KSI_success(&err);

cleanup:

	KSI_TLV_free(t);
	return KSI_end(&err);
}

void KSI_TLV_free(KSI_TLV *tlv) {
	KSI_TLV *nested = NULL;
	KSI_TLV *nestedNext = NULL;
	if (tlv != NULL) {
		KSI_free(tlv->buffer);

		/* Free nested data */
		if (tlv->encoding == KSI_TLV_ENC_TLV) {
			nested = tlv->encode.tlv.list;
			while(nested != NULL) {
				nestedNext = nested->next;
				KSI_TLV_free(nested);
				nested = nestedNext;
			}
		}
		KSI_free(tlv);
	}
}

/*
int KSI_TLV_fromBlob_new(KSI_CTX *ctx, char *data, size_t data_length, KSI_TLV **tlv);

int KSI_TLV_getRawValue(KSI_TLV *tlv, char *rawVal, size_t rawVal_size, , int *len);

int KSI_TLV_getIntValue(KSI_TLV *tlv, size_t bitSize, uint64_t *intVal);

int KSI_TLV_getStringValue(KSI_TLV *tlv, char *strVal, size_t strVal_size);
*/
