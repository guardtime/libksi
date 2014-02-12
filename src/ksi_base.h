#ifndef _KSI_BASE_H_
#define _KSI_BASE_H_

#include <stdio.h>

/* Returns true if context has no errors. */
#define KSI_CTX_OK(ctx) ((ctx) != NULL && (ctx)->statusCode == KSI_OK && (ctx)->errors_count == 0)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KSI_CTX_st KSI_CTX;
typedef struct KSI_ERR_st KSI_ERR;

/* KSI reader type. */
typedef struct KSI_RDR_st KSI_RDR;

enum KSI_StatusCode {
	/* RETURN CODES WHICH ARE NOT ERRORS */
	KSI_OK = 0,

	/* SYNTAX ERRORS */
	KSI_INVALID_ARGUMENT = 0x00000100,

	/* SYSTEM ERRORS */
	KSI_OUT_OF_MEMORY = 0x00000300,
	KSI_IO_ERROR,

	KSI_UNKNOWN_ERROR
};

const char *KSI_getErrorString(int statusCode);

/**
 * Initialize KSI context #KSI_CTX
 */

int KSI_CTX_new(KSI_CTX **context);

/**
 * Free KSI context.
 */
void KSI_CTX_free(KSI_CTX *context);


/****************************
 *  ERROR HANDLING FUNCTIONS.
 ****************************/

/**
 * Get the last status set.
 */
int KSI_ERR_getStatus(KSI_CTX *ctx);

/**
 * Dump error stack trace to stream
 */
int KSI_CTX_statusDump(KSI_CTX *ctx, FILE *f);

/****************
 * LOG FUNCTIONS.
 ****************/

/**
 * Set log file.
 *
 * \note this method will append to the file if it exists.
 */
int KSI_LOG_init(KSI_CTX *ctx, char *fileName, int logLevel);

/**
 * Change the log level.
 */
int KSI_LOG_setLevel(int logLevel);

#ifdef __cplusplus
}
#endif

#endif
