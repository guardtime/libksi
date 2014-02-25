#ifndef _KSI_INTERNAL_H_
#define _KSI_INTERNAL_H_

#include <stdint.h>

#include "ksi_base.h"
#include "ksi_err.h"
#include "ksi_io.h"
#include "ksi_log.h"

/* Create a new object of type. */
#define KSI_new(typeVar) (typeVar *)(KSI_calloc(sizeof(typeVar), 1))

/* Returns Empty string if #str==NULL otherwise returns #str itself */
#define KSI_strnvl(str) ((str) == NULL)?"":(str)

/* Dummy macro for indicating that the programmer knows and did not forget to free up some pointer. */
#define KSI_nofree(ptr)

#ifdef __cplusplus
extern "C" {
#endif


struct KSI_CTX_st {

/**
 *  ERROR HANDLING.
 **/
	/* Status code of the last executed function. */
	int statusCode;

	/* Array of errors. */
	KSI_ERR *errors;

	/* Length of error array. */
	size_t errors_size;

	/* Count of errors (usually #error_end - #error_start + 1, unless error count > #errors_size. */
	size_t errors_count;

/**
 * LOGGING
 */
	/* Log level see enum KSI_LOG_LVL_en */
	int logLevel;
	/* Filename where to write the log. NULL or "-" means stdout. */
	char *logFile;

	/* Stream to write log. */
	FILE *logStream; // TODO! Do we need more options?

};

void *KSI_malloc(size_t size);
void *KSI_calloc(size_t num, size_t size);
void *KSI_realloc(void *ptr, size_t size);
void KSI_free(void *ptr);

/**********
 * KSI TLV
 **********/

enum KSI_TLV_PayloadType_en {
	KSI_TLV_PAYLOAD_RAW,
	KSI_TLV_PAYLOAD_STR,
	KSI_TLV_PAYLOAD_INT,
	KSI_TLV_PAYLOAD_TLV
};

/* Creates an empty TLV with its own memory (always 0xffff bytes long).*/
int KSI_TLV_new(KSI_CTX *ctx, unsigned char *data, size_t data_len, KSI_TLV **tlv);

int KSI_TLV_cast(KSI_TLV *tlv, enum KSI_TLV_PayloadType_en);

int KSI_TLV_fromBlob(KSI_CTX *ctx, unsigned char *data, size_t data_length, KSI_TLV **tlv);

int KSI_TLV_getRawValue(KSI_TLV *tlv, unsigned char **buf, int *len, int copy);

int KSI_TLV_getUInt64Value(KSI_TLV *tlv, uint64_t *val);

int KSI_TLV_getStringValue(KSI_TLV *tlv, char **buf, int copy);

int KSI_TLV_getNextNestedTLV(KSI_TLV *tlv, KSI_TLV **nested);

void KSI_TLV_free(KSI_TLV *tlv);


#ifdef __cplusplus
}
#endif


#endif
