/*
 * ksi_err.h
 *
 *  Created on: 05.02.2014
 *      Author: henri
 */

#ifndef KSI_ERR_H_
#define KSI_ERR_H_

#define KSI_BEGIN(ctx, err) (KSI_LOG_debug((ctx), "Begin called from %s:%d\n", __FILE__, __LINE__), KSI_ERR_init((ctx), (err)))
#define KSI_PRE(err, cond) if (!(cond) && (KSI_ERR_init(NULL, (err)) == KSI_OK) && (KSI_FAIL((err), KSI_INVALID_ARGUMENT, NULL) == KSI_OK))
#define KSI_PRE_NOT_NULL(err, exp) if (((exp) == NULL) && (KSI_ERR_init(NULL, (err)) == KSI_OK))
#define KSI_RETURN(err) (KSI_LOG_debug((err)->ctx, "End called from %s:%d\n", __FILE__, __LINE__), KSI_ERR_apply((err)))
#define KSI_FAIL_EXT(err, statusCode, extErrCode, message) (KSI_LOG_debug((err)->ctx, "External fail called from %s:%d\n", __FILE__, __LINE__), KSI_ERR_fail((err), (statusCode), (extErrCode), __FILE__, __LINE__, (message)))
#define KSI_FAIL(err, statusCode, message) (KSI_LOG_debug((err)->ctx, "Fail called from %s:%d\n", __FILE__, __LINE__), KSI_ERR_fail((err), (statusCode), 0, __FILE__, __LINE__, (message)))
#define KSI_CATCH(err, res) if ((res) != KSI_OK && KSI_FAIL((err), res, NULL))
#define KSI_SUCCESS(err) KSI_ERR_success((err))

#ifdef __cplusplus
extern "C" {
#endif

/* Error structure.*/
struct KSI_ERR_st {
	/* Free text error message to be displayed. */
	char message[1024];

	/* Filename of the error. */
	char fileName[1024];

	/* Line number where the error was logd. */
	ssize_t lineNr;

	/* Status code. */
	int statusCode;

	/* Error code */
	int extErrorCode;

	/* Pointer to parent context. */
	KSI_CTX *ctx;
};

/**
 * Init error environment.
 *
 * \return KSI_OK
 */
int KSI_ERR_init(KSI_CTX *ctx, KSI_ERR *err);

/**
 * Clear all errors from context.
 */
void KSI_ERR_clearErrors(KSI_CTX *ctx);

/**
 * Add an error to context #ctx.
 */
int KSI_ERR_fail(KSI_ERR *ctx, int statusCode, int extErrorCode, char *fileName, int lineNr, char *message);

/**
 * State that the function finished successfully.
 */
void KSI_ERR_success(KSI_ERR *err);

int KSI_ERR_apply(KSI_ERR *err);

#ifdef __cplusplus
}
#endif

#endif /* KSI_ERR_H_ */
