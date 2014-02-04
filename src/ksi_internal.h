#ifndef _KSI_INTERNAL_H_
#define _KSI_INTERNAL_H_

#include "ksi_base.h"
#include "ksi_err.h"
#include "ksi_log.h"
#include "ksi_tlv.h"

/* Create a new object of type. */
#define KSI_new(typeVar) (typeVar *)(KSI_calloc(sizeof(typeVar), 1))

/* Returns Empty string if #str==NULL otherwise returns #str itself */
#define KSI_strnvl(str) ((str) == NULL)?"":(str)

#define KSI_begin(ctx) (KSI_LOG_debug((ctx), "Begin called from %s:%d\n", __FILE__, __LINE__), KSI_ERR_clearErrors((ctx)))
#define KSI_end(ctx) (KSI_LOG_debug((ctx), "End called from %s:%d\n", __FILE__, __LINE__) , KSI_ERR_getStatus((ctx)))
#define KSI_failExt(ctx, statusCode, extErrCode, message) (KSI_LOG_debug((ctx), "External fail called from %s:%d\n", __FILE__, __LINE__), KSI_ERR_fail((ctx), (statusCode), (extErrCode), __FILE__, __LINE__, (message)))
#define KSI_fail(ctx, statusCode, message) (KSI_LOG_debug((ctx), "Fail called from %s:%d\n", __FILE__, __LINE__), KSI_ERR_fail((ctx), (statusCode), 0, __FILE__, __LINE__, (message)))
#define KSI_success(ctx) KSI_ERR_success((ctx))
#define KSI_OK(ctx) KSI_ERR_isOK((ctx))

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

/* Error structure.*/
struct KSI_ERR_st {
	/* Free text error message to be displayed. */
	char message[1024];

	/* Filename of the error. */
	char fileName[1024];

	/* Line number where the error was logd. */
	size_t lineNr;

	/* Status code. */
	int statusCode;

	/* Error code */
	int extErrorCode;
};

void *KSI_malloc(size_t size);
void *KSI_calloc(size_t num, size_t size);
void *KSI_realloc(void *ptr, size_t size);
void KSI_free(void *ptr);

#ifdef __cplusplus
}
#endif


#endif
