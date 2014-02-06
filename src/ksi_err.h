/*
 * ksi_err.h
 *
 *  Created on: 05.02.2014
 *      Author: henri
 */

#ifndef KSI_ERR_H_
#define KSI_ERR_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Clear all errors from context.
 */
int KSI_ERR_clearErrors(KSI_CTX *ctx);

/**
 * Add an error to context #ctx.
 */
int KSI_ERR_fail(KSI_CTX *ctx, int statusCode, int extErrorCode, char *fileName, int lineNr, char *message);

/**
 * State that the function finished successfully.
 */
int KSI_ERR_success(KSI_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif /* KSI_ERR_H_ */
