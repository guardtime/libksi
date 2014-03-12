#ifndef _KSI_TLV_H_
#define _KSI_TLV_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KSI_TLV_MASK_TLV16 0x80
#define KSI_TLV_MASK_LENIENT 0x40
#define KSI_TLV_MASK_FORWARD 0x20

#define KSI_TLV_MASK_TLV8_TYPE 0x1f

/**
 * List of TLV's
 */
typedef struct KSI_TLV_list_st KSI_TLV_LIST;
struct KSI_TLV_list_st {
	/* The TLV value in this list node. */
	KSI_TLV *tlv;

	/* Pointer to the last node of this list. */
	KSI_TLV_LIST *last;

	/* Pointer to the next node of this list. */
	KSI_TLV_LIST *next;

};

struct KSI_TLV_st {
	/* Context. */
	KSI_CTX *ctx;

	/* Flags */
	int isLenient;
	int isForwardable;

	/* TLV tag. */
	unsigned int tag;

	/* Max size of the buffer. Default is 0xffff bytes. */
	int buffer_size;

	/* Internal storage. */
	unsigned char *buffer;

	/* Internal storage of nested TLV's */
	KSI_TLV_LIST *nested;

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
		struct {
			KSI_TLV_LIST *current;
		} tlv;
	} payload;
};

#ifdef __cplusplus
}
#endif


#endif
