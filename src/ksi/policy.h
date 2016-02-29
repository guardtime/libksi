/*
 * Copyright 2013-2016 Guardtime, Inc.
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

#ifndef POLICY_H
#define	POLICY_H

#include "types_base.h"

#ifdef	__cplusplus
extern "C" {
#endif

	/**
	 * Enumeration of all KSI policy (#KSI_Policy) verification result codes.
	 */
	typedef enum VerificationResultCode_en {
		/** Verification succeeded, which means there's a way to prove the correctness of the signature. */
		VER_RES_OK,
		/** Verification not possible, which means there is not enough data to prove or disprove the correctness of the signature. */
		VER_RES_NA,
		/** Verification failed, which means the signature is definitely invalid or the document does not match with the signature. */
		VER_RES_FAIL
	} VerificationResultCode;

	/**
	 * Enumeration of all KSI policy (#KSI_Policy) verification error codes.
	 */
	typedef enum VerificationErrorCode_en {
		/** Wrong document. */
		VER_ERR_GEN_1,
		/** Verification inconclusive. */
		VER_ERR_GEN_2,
		/** Inconsistent aggregation hash chains. */
		VER_ERR_INT_1,
		/** Inconsistent aggregation hash chain aggregation times. */
		VER_ERR_INT_2,
		/** Calendar hash chain input hash mismatch. */
		VER_ERR_INT_3,
		/** Calendar hash chain aggregation time mismatch. */
		VER_ERR_INT_4,
		/** Calendar hash chain shape inconsistent with aggregation time. */
		VER_ERR_INT_5,
		/** Calendar hash chain time inconsistent with calendar auth record time. */
		VER_ERR_INT_6,
		/** Calendar hash chain time inconsistent with publication time. */
		VER_ERR_INT_7,
		/** Calendar hash chain root has inconsistent with calendar auth record time. */
		VER_ERR_INT_8,
		/** Calendar hash chain root has inconsistent with publication time. */
		VER_ERR_INT_9,
		/** Extender response calendar root hash mismatch. */
		VER_ERR_PUB_1,
		/** Extender response inconsistent. */
		VER_ERR_PUB_2,
		/** Extender response input hash mismatch. */
		VER_ERR_PUB_3,
		/** Certificate not found. */
		VER_ERR_KEY_1,
		/** PKI signature not verified with certificate. */
		VER_ERR_KEY_2,
		/** Calendar root hash mismatch. */
		VER_ERR_CAL_1,
		/** Aggregation hash chain root hash and calendar hash chain input hash mismatch. */
		VER_ERR_CAL_2,
		/** Aggregation time mismatch. */
		VER_ERR_CAL_3,
		/** Aggregation hash chain right links are inconsistent. */
		VER_ERR_CAL_4,
		/** No error. */
		VER_ERR_NONE
	} VerificationErrorCode;

	struct VerificationResult_st {
		VerificationResultCode resultCode;
		VerificationErrorCode errorCode;
		const char *ruleName;
	};

	typedef struct VerificationResult_st KSI_RuleVerificationResult;
	typedef struct VerificationResult_st KSI_RuleResult;

	typedef struct VerificationResult_st KSI_PolicyResult;

	typedef struct PolicyResultList KSI_PolicyResultList;

	typedef struct KSI_PolicyVerificationResult_st {
		KSI_PolicyResult finalResult;
		KSI_LIST(KSI_PolicyResult) *results;
	} KSI_PolicyVerificationResult;

	typedef struct VerificationPolicy_st KSI_Policy;

	typedef struct VerificationPolicySimplified_st KSI_PolicySimplified;

	typedef struct VerificationContext_st VerificationContext;

	/**
	 * Creates a #KSI_Policy containing the rules for calendar based verification.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	policy		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_setFallback, #KSI_Policy_verify, #KSI_Policy_free
	 */
	int KSI_Policy_createCalendarBased(KSI_CTX *ctx, KSI_Policy **policy);

	/**
	 * Creates a #KSI_Policy containing the rules for key based verification.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	policy		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_setFallback, #KSI_Policy_verify, #KSI_Policy_free
	 */
	int KSI_Policy_createKeyBased(KSI_CTX *ctx, KSI_Policy **policy);

	/**
	 * Creates a #KSI_Policy containing the rules for publications file based verification.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	policy		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_setFallback, #KSI_Policy_verify, #KSI_Policy_free
	 */
	int KSI_Policy_createPublicationsFileBased(KSI_CTX *ctx, KSI_Policy **policy);

	/**
	 * Creates a #KSI_Policy containing the rules for user provided publication based verification.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	policy		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_setFallback, #KSI_Policy_verify, #KSI_Policy_free
	 */
	int KSI_Policy_createUserProvidedPublicationBased(KSI_CTX *ctx, KSI_Policy **policy);

	/**
	 * Sets a fallback policy for a primary policy.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	policy		Primary policy to be secured with a fallback policy.
	 * \param[in]	fallback	Fallback policy.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_createxxx, #KSI_Policy_verify, #KSI_Policy_free
	 */
	int KSI_Policy_setFallback(KSI_CTX *ctx, KSI_Policy *policy, KSI_Policy *fallback);

	/**
	 * Verifies a KSI signature (provided in \c context) according to specified \c policy.
	 * If the verification fails with #NA or #FAIL and a fallback policy has been set with
	 * #KSI_Policy_setFallback, the verification continues according to the fallback policy.
	 * A list of verification results is created into \c result, containing the result and error
	 * codes for the primary policy and potential fallback policies. The user is responsible
	 * for freeing the \c result object with #KSI_PolicyVerificationResult_free.
	 * \param[in]	policy		Policy to be verified.
	 * \param[in]	context		Context for verifying the policy.
	 * \param[out]	result		List of verification results
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_setFallback, #KSI_Policy_free, #KSI_PolicyVerificationResult_free
	 */
	int KSI_Policy_verify(KSI_Policy *policy, VerificationContext *context, KSI_PolicyVerificationResult **result);

	/**
	 * Frees the \c policy object. The function does not free any potential
	 * fallback policy objects which the user must free separately.
	 * \param[in] policy
	 *
	 * \see #KSI_Policy_createxxx
	 */
	void KSI_Policy_free(KSI_Policy *policy);

	/**
	 * Frees the verification result object.
	 * \param[in]	result		List of verification results to be freed.
	 *
	 * \see #KSI_Policy_verify
	 */
	void KSI_PolicyVerificationResult_free(KSI_PolicyVerificationResult *result);

	/**
	 * Creates a verification context.
	 * \param[in]	ctx		KSI context.
	 * \param[out]	context	Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationContext_create(KSI_CTX *ctx, VerificationContext **context);

	/**
	 * Frees the verification context object, including all internal objects.
	 * \param[in]	context		Verification context to be freed.
	 *
	 * \see #KSI_VerificationContext_create, #KSI_VerificationContext_clean
	 */
	void KSI_VerificationContext_free(VerificationContext *context);

	/**
	 * Frees the temporary data in the context object.
	 * \param[in]	context		Verification context to be cleaned.
	 *
	 * \see #KSI_VerificationContext_create, #KSI_VerificationContext_free
	 */
	void KSI_VerificationContext_clean(VerificationContext *context);


#ifdef	__cplusplus
}
#endif

#endif	/* POLICY_H */
