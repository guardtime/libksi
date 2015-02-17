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

#ifndef VERIFICATION_H_
#define VERIFICATION_H_

#include "ksi.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \addtogroup signature
	 * @{
	 */

	/**
	 * This type keeps track of all the performed verification steps (#KSI_VerificationStep_en) and
	 * their results.
	 */
	typedef struct KSI_VerificationResult_st KSI_VerificationResult;

	/**
	 * This type holds a concrete result for a single verification step (#KSI_VerificationStep_en).
	 */
	typedef struct KSI_VerificationStepResult_st KSI_VerificationStepResult;

	/**
	 * Enumeration of all KSI signature (#KSI_Signature) available verification steps.
	 */
	typedef enum KSI_VerificationStep_en {
	    /**
	     * Check if signature input hash and document hash match.
	     */
	    KSI_VERIFY_DOCUMENT = 0x01,

	    /**
	     * Verify the aggregation chain internally.
	     */
	    KSI_VERIFY_AGGRCHAIN_INTERNALLY = 0x02,

	    /**
	     * Check if calendar chain matches aggregation chain
	     */
	    KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN = 0x04,

	    /**
	     * Verify calendar chain internally.
	     */
	    KSI_VERIFY_CALCHAIN_INTERNALLY = 0x08,

	    /**
	     * Verify calendar chain using calendar auth record.
	     */
	    KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC = 0x10,

	    /**
	     * Verify calendar chain with publication.
	     */
	    KSI_VERIFY_CALCHAIN_WITH_PUBLICATION = 0x20,

	    /**
	     * Verify signature against online calendar
	     */
	    KSI_VERIFY_CALCHAIN_ONLINE = 0x40,

	    /**
	     * OK!verify that calendar authentication record signature is correct
	     */
	    KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE = 0x80,

	    /**
	     * check publication file signature
	     */
	    KSI_VERIFY_PUBFILE_SIGNATURE = 0x100,

	    /**
	     * Check if publication record is stored in KSI Trust provider
	     */
	    KSI_VERIFY_PUBLICATION_WITH_PUBFILE = 0x200,

	} KSI_VerificationStep;

	/**
	 * Initializes the #KSI_VerificationResult object.
	 * \param[in]	info		Pointer to #KSI_VerificationResult.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationResult_init(KSI_VerificationResult *info, KSI_CTX *ctx);

	/**
	 * Reset the value of #KSI_VerificationResult.
	 * \param[in]	info		Pointer to #KSI_VerificationResult.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationResult_reset(KSI_VerificationResult *info);

	/**
	 * Mark the verification step as failure.
	 * \param[in]	info		Verification result.
	 * \param[in]	step		Verification step.
	 * \param[in]	desc		Verification failure message.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationResult_addFailure(KSI_VerificationResult *info, KSI_VerificationStep step, const char *desc);

	/**
	 * Mark the verification step as success.
	 * \param[in]	info		Verification result.
	 * \param[in]	step		Verification step.
	 * \param[in]	desc		Verification success message.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationResult_addSuccess(KSI_VerificationResult *info, KSI_VerificationStep step, const char *desc);

	/**
	 * Returns the performed step count.
	 * \param[in]	info		Verification result.
	 * \return count of elements in the verification info.
	 */
	size_t KSI_VerificationResult_getStepResultCount(const KSI_VerificationResult *info);

	/**
	 * Get the a verification step with the given index.
	 * \param[in]	info		Verification result.
	 * \param[in]	index		Index of the step.
	 * \param[out]	result		Verification step result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationResult_getStepResult(const KSI_VerificationResult *info, size_t index, const KSI_VerificationStepResult **result);

	/**
	 * Returns 0 if the given verification step is not performed.
	 * \param[in]	info		Verification result.
	 * \param[in]	step		Verification step.
	 * \return 0 is the given verification step is not performed.
	 */
	int KSI_VerificationResult_isStepPerformed(const KSI_VerificationResult *info, enum KSI_VerificationStep_en step);

	/**
	 * Returns 0 if the given verification step is not performed or the performed step was
	 * unsuccessful.
	 * \param[in]	info		Verification result.
	 * \param[in]	step		Verification step.
	 * \returns 0 if the given verification step was unsuccessful or not performed.
	 */
	int KSI_VerificationResult_isStepSuccess(const KSI_VerificationResult *info, enum KSI_VerificationStep_en step);

	/**
	 * Returns the #KSI_VerificationStep value or 0 on an error.
	 * \param[in]	result 		Verification step result.
	 * \returns 0 if the given verification step was unsuccessful or not performed.
	 */
	int KSI_VerificationStepResult_getStep(const KSI_VerificationStepResult *result);

	/**
	 * Returns if the verification step result was successful.
	 * \param[in]	result		Verification step result.
	 * \return If the step was not successful 0 is returned, otherwise !0.
	 */
	int KSI_VerificationStepResult_isSuccess(const KSI_VerificationStepResult *result);

	/**
	 * Returns a pointer to the description of this step result.
	 * \param[in]	result		Verification step result.
	 */
	const char *KSI_VerificationStepResult_getDescription(const KSI_VerificationStepResult *result);

	/**
	 * @}
	 */
#ifdef __cplusplus
}
#endif

#endif /* VERIFICATION_INFO_H_ */
