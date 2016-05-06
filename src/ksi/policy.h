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

#include "types.h"
#include "ksi.h"

#ifdef	__cplusplus
extern "C" {
#endif

	struct KSI_VerificationContext_st {
		KSI_CTX *ctx;

		/** Signature to be verified */
		KSI_Signature *sig;

		/** Indicates whether signature extention is allowed */
		int extendingAllowed;

		/** Initial aggregation level. */
		KSI_uint64_t docAggrLevel;

		/** Document hash to be verified. */
		KSI_DataHash *documentHash;

		/** Publication string to be used. */
		KSI_PublicationData *userPublication;

		/** Publication file to be used. */
		KSI_PublicationsFile *userPublicationsFile;

		void *tempData;
	};

	/**
	 * Enumeration of all KSI policy (#KSI_Policy) verification result codes.
	 */
	typedef enum KSI_VerificationResultCode_en {
		/** Verification succeeded, which means there's a way to prove the correctness of the signature. */
		KSI_VER_RES_OK,
		/** Verification not possible, which means there is not enough data to prove or disprove the correctness of the signature. */
		KSI_VER_RES_NA,
		/** Verification failed, which means the signature is definitely invalid or the document does not match with the signature. */
		KSI_VER_RES_FAIL
	} KSI_VerificationResultCode;

	/**
	 * Enumeration of all KSI policy (#KSI_Policy) verification error codes.
	 */
	typedef enum KSI_VerificationErrorCode_en {
		/** Wrong document. */
		KSI_VER_ERR_GEN_1,
		/** Verification inconclusive. */
		KSI_VER_ERR_GEN_2,
		/** Inconsistent aggregation hash chains. */
		KSI_VER_ERR_INT_1,
		/** Inconsistent aggregation hash chain aggregation times. */
		KSI_VER_ERR_INT_2,
		/** Calendar hash chain input hash mismatch. */
		KSI_VER_ERR_INT_3,
		/** Calendar hash chain aggregation time mismatch. */
		KSI_VER_ERR_INT_4,
		/** Calendar hash chain shape inconsistent with aggregation time. */
		KSI_VER_ERR_INT_5,
		/** Calendar hash chain time inconsistent with calendar auth record time. */
		KSI_VER_ERR_INT_6,
		/** Calendar hash chain time inconsistent with publication time. */
		KSI_VER_ERR_INT_7,
		/** Calendar hash chain root has inconsistent with calendar auth record time. */
		KSI_VER_ERR_INT_8,
		/** Calendar hash chain root has inconsistent with publication time. */
		KSI_VER_ERR_INT_9,
		/** Aggregation hash chain chain index mismatch. */
		KSI_VER_ERR_INT_10,
		/** Extender response calendar root hash mismatch. */
		KSI_VER_ERR_PUB_1,
		/** Extender response inconsistent. */
		KSI_VER_ERR_PUB_2,
		/** Extender response input hash mismatch. */
		KSI_VER_ERR_PUB_3,
		/** Certificate not found. */
		KSI_VER_ERR_KEY_1,
		/** PKI signature not verified with certificate. */
		KSI_VER_ERR_KEY_2,
		/** Calendar root hash mismatch. */
		KSI_VER_ERR_CAL_1,
		/** Aggregation hash chain root hash and calendar hash chain input hash mismatch. */
		KSI_VER_ERR_CAL_2,
		/** Aggregation time mismatch. */
		KSI_VER_ERR_CAL_3,
		/** Aggregation hash chain right links are inconsistent. */
		KSI_VER_ERR_CAL_4,
		/** No error. */
		KSI_VER_ERR_NONE
	} KSI_VerificationErrorCode;

	struct KSI_RuleVerificationResult_st {
		KSI_VerificationResultCode resultCode;
		KSI_VerificationErrorCode errorCode;
		const char *ruleName;
		const char *policyName;
		size_t stepsPerformed;
		size_t stepsSuccessful;
		size_t stepsFailed;
	};

	typedef struct KSI_RuleVerificationResult_st KSI_RuleVerificationResult;

	KSI_DEFINE_LIST(KSI_RuleVerificationResult);

	typedef struct KSI_PolicyVerificationResult_st {
		KSI_RuleVerificationResult finalResult;
		KSI_LIST(KSI_RuleVerificationResult) *ruleResults;
		KSI_LIST(KSI_RuleVerificationResult) *policyResults;
	} KSI_PolicyVerificationResult;

	typedef struct KSI_Policy_st KSI_Policy;

	typedef enum RuleType_en {
		KSI_RULE_TYPE_BASIC,
		KSI_RULE_TYPE_COMPOSITE_AND,
		KSI_RULE_TYPE_COMPOSITE_OR
	} KSI_RuleType;

	typedef struct KSI_Rule_st {
		KSI_RuleType type;
		const void *rule;
	} KSI_Rule;

	typedef struct KSI_VerificationContext_st KSI_VerificationContext;

	/**
	 * Gets a pointer to a predefined #KSI_Policy object with rules for internal verification.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	policy		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_SignatureVerifier_verify
	 */
	int KSI_Policy_getInternal(KSI_CTX *ctx, const KSI_Policy **policy);

	/**
	 * Gets a pointer to a predefined #KSI_Policy object with rules for calendar based verification.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	policy		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_SignatureVerifier_verify
	 */
	int KSI_Policy_getCalendarBased(KSI_CTX *ctx, const KSI_Policy **policy);

	/**
	 * Gets a pointer to a predefined #KSI_Policy object with rules for key based verification.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	policy		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_SignatureVerifier_verify
	 */
	int KSI_Policy_getKeyBased(KSI_CTX *ctx, const KSI_Policy **policy);

	/**
	 * Gets a pointer to a predefined #KSI_Policy object with rules for publications file based verification.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	policy		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_SignatureVerifier_verify
	 */
	int KSI_Policy_getPublicationsFileBased(KSI_CTX *ctx, const KSI_Policy **policy);

	/**
	 * Gets a pointer to a predefined #KSI_Policy object with rules for user provided publication based verification.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	policy		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_SignatureVerifier_verify
	 */
	int KSI_Policy_getUserProvidedPublicationBased(KSI_CTX *ctx, const KSI_Policy **policy);

	/**
	 * Gets a pointer to a predefined #KSI_Policy object with rules for general verification.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	policy		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_SignatureVerifier_verify
	 */
	int KSI_Policy_getGeneral(KSI_CTX *ctx, const KSI_Policy **policy);

	/**
	 * Creates a policy based on user defined rules. User gets ownership of the policy and
	 * is responsible for freeing the policy later with #KSI_Policy_free. As the policy owner,
	 * the user is free to set a fallback policy with #KSI_Policy_setFallback.
	 *
	 * \param[in]	ctx		KSI context.
	 * \param[in]	rules	Pointer to user defined rules to be assigned to the policy.
	 * \param[in]	name	Name to be given to the policy.
	 * \param[out]	policy	Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_free, #KSI_SignatureVerifier_verify, #KSI_Policy_setFallback
	 */
	int KSI_Policy_create(KSI_CTX *ctx, const KSI_Rule *rules, const char *name, KSI_Policy **policy);

	/**
	 * Clones a predefined #KSI_Policy, allowing the user to change the default fallback policy later.
	 * User gets ownership of the cloned policy and is responsible for freeing the policy.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	policy		Policy to be cloned.
	 * \param[out]	clone		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_setFallback, #KSI_SignatureVerifier_verify, #KSI_Policy_free
	 */
	int KSI_Policy_clone(KSI_CTX *ctx, const KSI_Policy *policy, KSI_Policy **clone);

	/**
	 * Sets a fallback policy for a primary policy. The primary policy must be owned by the user,
	 * so it can be either a user created or cloned policy, but not a predefined policy.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	policy		Primary policy to be secured with a fallback policy.
	 * \param[in]	fallback	Fallback policy.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_create, #KSI_Policy_clone, #KSI_SignatureVerifier_verify, #KSI_Policy_free
	 */
	int KSI_Policy_setFallback(KSI_CTX *ctx, KSI_Policy *policy, const KSI_Policy *fallback);

	/**
	 * Verifies a KSI signature (provided in \c context) according to specified \c policy.
	 * If the verification fails with #KSI_VER_RES_NA or #KSI_VER_RES_FAIL and a fallback policy has been set with
	 * #KSI_Policy_setFallback, the verification continues according to the fallback policy.
	 * A list of verification results is created into \c result, containing the result and error
	 * codes for the primary policy and potential fallback policies. The user is responsible
	 * for freeing the \c result object with #KSI_PolicyVerificationResult_free.
	 * \param[in]	policy		Policy to be verified.
	 * \param[in]	context		Context for verifying the policy.
	 * \param[out]	result		List of verification results
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_getxxx, #KSI_Policy_setFallback, #KSI_PolicyVerificationResult_free
	 */
	int KSI_SignatureVerifier_verify(const KSI_Policy *policy, KSI_VerificationContext *context, KSI_PolicyVerificationResult **result);

	/**
	 * Frees a user created or cloned #KSI_Policy object. Predefined policies cannot be freed.
	 * The function does not free any potential fallback policy objects which the user must free separately.
	 * \param[in] policy
	 *
	 * \see #KSI_Policy_create, #KSI_Policy_clone
	 */
	void KSI_Policy_free(KSI_Policy *policy);

	/**
	 * Frees the verification result object.
	 * \param[in]	result		List of verification results to be freed.
	 *
	 * \see #KSI_SignatureVerifier_verify
	 */
	void KSI_PolicyVerificationResult_free(KSI_PolicyVerificationResult *result);

	/**
	 * Frees the temporary data in the context object.
	 * \param[in]	context		Verification context to be cleaned.
	 *
	 * \see #KSI_VerificationContext_create, #KSI_VerificationContext_free
	 */
	void KSI_VerificationContext_clean(KSI_VerificationContext *context);

	/**
	 *
	 */
	int KSI_VerificationContext_reset(KSI_VerificationContext *context);

	/**
	 *
	 */
	int KSI_VerificationContext_init(KSI_VerificationContext *context, KSI_CTX *);

#ifdef	__cplusplus
}
#endif

#endif	/* POLICY_H */
