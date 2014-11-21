#ifndef KSI_ERR_H_
#define KSI_ERR_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif



/**
 * \addtogroup errorhandling Errorhandling functions.
 * @{
 */

/* Error structure.*/
struct KSI_ERR_st {
	/* Free text error message to be displayed. */
	char message[1024];

	/* Filename of the error. */
	char fileName[1024];

	/* Line number where the error was logd. */
	unsigned int lineNr;

	/* Status code. */
	int statusCode;

	/* Error code */
	long extErrorCode;

	/* Pointer to parent context. */
	KSI_CTX *ctx;
};

/**
 * Init error environment.
 * \param[in]	ctx			KSI context.
 * \param[in]	err			Error container.
 *
 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
int KSI_ERR_init(KSI_CTX *ctx, KSI_ERR *err);

/**
 * Clear all errors from context.
 * \param[in]		ctx			KSI context.
 */
void KSI_ERR_clearErrors(KSI_CTX *ctx);

/**
 * Add an error to context \c ctx.
 * \param[in]	ctx				KSI context.
 * \param[in]	statusCode		KSI status code (\see #KSI_StatusCode).
 * \param[in]	extErrorCode	External error code.
 * \param[in]	fileName		Filename where the error was raised.
 * \param[in]	lineNr			Line number where the error was raised.
 * \param[in]	message			Pointer to null-terminated error message (or NULL).
 *
 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
int KSI_ERR_fail(KSI_ERR *ctx, int statusCode, long extErrorCode, char *fileName, unsigned int lineNr, const char *message);

/**
 * State that the function finished successfully.
 * \param[in]	err		Error container.
 */
void KSI_ERR_success(KSI_ERR *err);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_ERR_H_ */
