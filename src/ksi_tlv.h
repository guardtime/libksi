#ifndef _KSI_TLV_H_
#define _KSI_TLV_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum KSI_TLV_Encoding_en {
	KSI_TLV_ENC_RAW,
	KSI_TLV_ENC_STR,
	KSI_TLV_ENC_INT,
	KSI_TLV_ENC_TLV
};

struct KSI_TLV_st {
	/* Flags */
	int isLenient;
	int isForwardable;

	/* Max size of the buffer. Default is 0xffff bytes. */
	size_t buffer_size;
	/* Internal storage. */
	char *buffer;


	enum KSI_TLV_Encoding_en encoding;

	union {
		struct {
			char *ptr; /* Pointer to raw value */
			size_t length;
		} rawVal;
		uint64_t uintVal;
		char stringVal;
		struct {
			KSI_TLV *list;
			KSI_TLV *current;
		} tlv;
	} encode;

	/* Next tlv in a linked list */
	KSI_TLV *next;
};

/* Creates an empty TLV with its own memory (always 0xffff bytes long).*/
int KSI_TLV_new(KSI_CTX *ctx, char *data, size_t data_len, KSI_TLV **tlv);

int KSI_TLV_fromBlob_new(KSI_CTX *ctx, char *data, size_t data_length, KSI_TLV **tlv);

int KSI_TLV_getRawValue(KSI_TLV *tlv, char *rawVal, size_t rawVal_size, int *len);

int KSI_TLV_getIntValue(KSI_TLV *tlv, size_t bitSize, uint64_t *intVal);

int KSI_TLV_getStringValue(KSI_TLV *tlv, char *strVal, size_t strVal_size);

// TODO Functions for nested TLV's.

void KSI_TLV_free(KSI_TLV *tlv);

#ifdef __cplusplus
}
#endif


#endif
