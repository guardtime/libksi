/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
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
 * Finalizes the current error stack.
 * \param[in]		err		Pointer to the error object.
 */
int KSI_ERR_apply(KSI_ERR *err);
int KSI_ERR_pre(KSI_ERR *err, int cond, char *fileName, int lineNr);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_ERR_H_ */
