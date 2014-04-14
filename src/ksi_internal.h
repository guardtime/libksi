#ifndef _KSI_INTERNAL_H_
#define _KSI_INTERNAL_H_

#include <stdint.h>

#include "ksi_base.h"
#include "ksi_err.h"
#include "ksi_log.h"
#include "ksi_tlv_tags.h"

#define KSI_UINT16_MINSIZE(val) ((val > 0xff) ? 2 : 1)
#define KSI_UINT32_MINSIZE(val) ((val > 0xffff) ? (2 + KSI_UINT16_MINSIZE((val) >> 16)) : KSI_UINT16_MINSIZE((val)))
#define KSI_UINT64_MINSIZE(val) (((val) > 0xffffffff) ? (4 + KSI_UINT32_MINSIZE((val) >> 32)) : KSI_UINT32_MINSIZE((val)))

/* Create a new object of type. */
#define KSI_new(typeVar) (typeVar *)(KSI_calloc(sizeof(typeVar), 1))

/* Returns Empty string if #str==NULL otherwise returns #str itself */
#define KSI_strnvl(str) ((str) == NULL)?"":(str)

/* Dummy macro for indicating that the programmer knows and did not forget to free up some pointer. */
#define KSI_nofree(ptr)

#define KSI_IMPLEMENT_GET_CTX(type)							\
KSI_CTX *type##_getCtx(type *o) {				 			\
	return o->ctx; 											\
} 															\

#ifdef __cplusplus
extern "C" {
#endif

struct KSI_CTX_st {

	/******************
	 *  ERROR HANDLING.
	 ******************/

	/* Status code of the last executed function. */
	int statusCode;

	/* Array of errors. */
	KSI_ERR *errors;

	/* Length of error array. */
	size_t errors_size;

	/* Count of errors (usually #error_end - #error_start + 1, unless error count > #errors_size. */
	size_t errors_count;

	/**********
	 * LOGGING.
	 **********/

	/* Log level see enum KSI_LOG_LVL_en */
	int logLevel;
	/* Filename where to write the log. NULL or "-" means stdout. */
	char *logFile;

	/* Stream to write log. */
	FILE *logStream; // TODO! Do we need more options?

	/************
	 * TRANSPORT.
	 ************/

	KSI_NetProvider *netProvider;
};

int KSI_parseSignature(KSI_CTX *ctx, unsigned char *rawPdu, int rawPdu_len, KSI_Signature **signature);

#ifdef __cplusplus
}
#endif


#endif
