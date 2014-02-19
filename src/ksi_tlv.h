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

enum KSI_TLV_PayloadType_en {
	KSI_TLV_PAYLOAD_RAW,
	KSI_TLV_PAYLOAD_STR,
	KSI_TLV_PAYLOAD_INT,
	KSI_TLV_PAYLOAD_TLV
};

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
		char stringVal;
		struct {
			KSI_TLV *list;
			KSI_TLV *current;
		} tlv;
	} payload;

	/* Next tlv in a linked list */
	KSI_TLV *next;
};

/* Creates an empty TLV with its own memory (always 0xffff bytes long).*/
int KSI_TLV_new(KSI_CTX *ctx, char *data, size_t data_len, KSI_TLV **tlv);

int KSI_TLV_fromBlob(KSI_CTX *ctx, char *data, size_t data_length, KSI_TLV **tlv);

int KSI_TLV_getRawValue(KSI_TLV *tlv, unsigned char **buf, int *len, int copy);

int KSI_TLV_getUInt64Value(KSI_TLV *tlv, uint64_t *val);

int KSI_TLV_getStringValue(KSI_TLV *tlv, char **buf, int copy);

int KSI_TLV_getNextNestedTLV(KSI_TLV *tlv, const KSI_TLV **nested);

void KSI_TLV_free(KSI_TLV *tlv);

#ifdef __cplusplus
}
#endif


#endif
