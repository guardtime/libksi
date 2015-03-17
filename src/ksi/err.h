/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

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
 * Push an error message to the error stack of the context.
 */
void KSI_ERR_push(KSI_CTX *ctx, int statusCode, long extErrorCode, const char *fileName, unsigned int lineNr, const char *message);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_ERR_H_ */
