#ifndef _KSI_TLV_H_
#define _KSI_TLV_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KSI_TLV_MASK_TLV16 0x80
#define KSI_TLV_MASK_LENIENT 0x04
#define KSI_TLV_MASK_FORWARD 0x20

#define KSI_TLV_MASK_TLV8_TYPE 0x1f

struct KSI_TLV_st {
	/* Context. */
	KSI_CTX *ctx;

	/* Flags */
	int isLenient;
	int isForwardable;

	/* TLV type. */
	unsigned int type;

	/* Max size of the buffer. Default is 0xffff bytes. */
	int buffer_size;

	/* Internal storage. */
	unsigned char *buffer;

	/* How the payload is encoded internally. */
	enum KSI_TLV_PayloadType_en payloadType;

	union {
		struct {
			unsigned char *ptr; /* Pointer to raw value */
			int length;
		} rawVal;
		struct {
			uint64_t value;
			int length;
		}uintVal;
		char *stringVal;
		struct {
			KSI_TLV *list;
			KSI_TLV *current;
		} tlv;
	} payload;

	/* Next tlv in a linked list */
	KSI_TLV *next;
	/* Pointer to the last element of a list. By default pointing to itself. */
	KSI_TLV *last;
};

#ifdef __cplusplus
}
#endif


#endif
