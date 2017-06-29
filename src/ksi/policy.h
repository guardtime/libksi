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
#include "common.h"

#ifdef	__cplusplus
extern "C" {
#endif

	struct KSI_VerificationContext_st {
		KSI_CTX *ctx;

		/** Signature being verified. */
		KSI_Signature *signature;

		/** Indicates whether signature extention is allowed (0 means no, and any non-zero is considered to be true). */
		int extendingAllowed;

		/** Initial aggregation level. */
		KSI_uint64_t docAggrLevel;

		/** Document hash to be verified. */
		const KSI_DataHash *documentHash;

		/** Publication string to be used. */
		const KSI_PublicationData *userPublication;

		/** Publication file to be used. */
		KSI_PublicationsFile *userPublicationsFile;

		void *tempData;
	};

	/**
	 * Enumeration of all KSI policy (#KSI_Policy) verification result codes.
	 */
	typedef enum KSI_VerificationResultCode_en {
		/** Verification succeeded, which means there's a way to prove the correctness of the signature. */
		KSI_VER_RES_OK = 0x00,
		/** Verification not possible, which means there is not enough data to prove or disprove the correctness of the signature. */
		KSI_VER_RES_NA = 0x01,
		/** Verification failed, which means the signature is definitely invalid or the document does not match with the signature. */
		KSI_VER_RES_FAIL = 0x02,
	} KSI_VerificationResultCode;

	/**
	 * Helper macro containing a list of KSI signature verification error codes.
	 */
	#define KSI_VERIFICATION_ERROR_CODE_LIST\
		/*Type  Code  Offset  StrCode      Description*/\
		_(GEN,  1,    0x100,  "GEN-01",    "Wrong document")\
		_(GEN,  2,    0x100,  "GEN-02",    "Verification inconclusive") \
		_(GEN,  3,    0x100,  "GEN-03",    "Input hash level too large") \
		\
		_(INT,  1,    0x200,  "INT-01",    "Inconsistent aggregation hash chains") \
		_(INT,  2,    0x200,  "INT-02",    "Inconsistent aggregation hash chain aggregation times") \
		_(INT,  3,    0x200,  "INT-03",    "Calendar hash chain input hash mismatch") \
		_(INT,  4,    0x200,  "INT-04",    "Calendar hash chain aggregation time mismatch") \
		_(INT,  5,    0x200,  "INT-05",    "Calendar hash chain shape inconsistent with aggregation time") \
		_(INT,  6,    0x200,  "INT-06",    "Calendar hash chain time inconsistent with calendar authentication record time") \
		_(INT,  7,    0x200,  "INT-07",    "Calendar hash chain time inconsistent with publication time") \
		_(INT,  8,    0x200,  "INT-08",    "Calendar hash chain root hash is inconsistent with calendar authentication record input hash") \
		_(INT,  9,    0x200,  "INT-09",    "Calendar hash chain root hash is inconsistent with published hash value") \
		_(INT,  10,   0x200,  "INT-10",    "Aggregation hash chain chain index mismatch") \
		_(INT,  11,   0x200,  "INT-11",    "The metadata record in the aggregation hash chain may not be trusted") \
		_(INT,  12,   0x200,  "INT-12",    "Inconsistent chain indexes") \
		\
		_(PUB,  1,    0x300,  "PUB-01",    "Extender response calendar root hash mismatch") \
		_(PUB,  2,    0x300,  "PUB-02",    "Extender response inconsistent") \
		_(PUB,  3,    0x300,  "PUB-03",    "Extender response input hash mismatch") \
		_(PUB,  4,    0x300,  "PUB-04",    "Publication record hash and user provided publication hash mismatch") \
		_(PUB,  5,    0x300,  "PUB-05",    "Publication record hash and publications file publication hash mismatch") \
		\
		_(KEY,  1,    0x400,  "KEY-01",    "Certificate not found") \
		_(KEY,  2,    0x400,  "KEY-02",    "PKI signature not verified with certificate") \
		_(KEY,  3,    0x400,  "KEY-03",    "Signing certificate not valid at aggregation time") \
		\
		_(CAL,  1,    0x500,  "CAL-01",    "Calendar root hash mismatch between signature and calendar database chain") \
		_(CAL,  2,    0x500,  "CAL-02",    "Aggregation hash chain root hash and calendar database hash chain input hash mismatch") \
		_(CAL,  3,    0x500,  "CAL-03",    "Aggregation time mismatch") \
		_(CAL,  4,    0x500,  "CAL-04",    "Calendar hash chain right links are inconsistent")

	/**
	 * Enumeration of all KSI policy (#KSI_Policy) verification error codes.
	 */
	typedef enum KSI_VerificationErrorCode_en {
		/** No error. */
		KSI_VER_ERR_NONE = 0x00,
#define _(type, code, offset, cor, desc) KSI_VER_ERR_##type##_##code = (offset + code),
		KSI_VERIFICATION_ERROR_CODE_LIST
#undef _
		__NOF_VER_ERRORS
	} KSI_VerificationErrorCode;

	struct KSI_RuleVerificationResult_st {
		/** The result of the verification. */
		KSI_VerificationResultCode resultCode;
		/** Error code of the verification. */
		KSI_VerificationErrorCode errorCode;
		/** Last perfomed rule name. */
		const char *ruleName;
		/** Last performed policy name. */
		const char *policyName;
		/** Bitmap of the verification steps performed. */
		size_t stepsPerformed;
		/** Bitmap of the successful steps performed. */
		size_t stepsSuccessful;
		/** Bitmap of the failed steps performed. */
		size_t stepsFailed;
	};

	typedef struct KSI_RuleVerificationResult_st KSI_RuleVerificationResult;

	KSI_DEFINE_LIST(KSI_RuleVerificationResult);
#define KSI_RuleVerificationResultList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_RuleVerificationResultList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_RuleVerificationResultList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_RuleVerificationResultList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_RuleVerificationResultList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_RuleVerificationResultList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_RuleVerificationResultList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_TlvElementList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_TlvElementList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	/**
	 * Policy verification result structure.
	 */
	struct KSI_PolicyVerificationResult_st {
		/** Reference counter. */
		size_t ref;
		/** Verification result. */
		KSI_VerificationResultCode resultCode;
		/** Detailed verification result. */
		KSI_RuleVerificationResult finalResult;
		/** Results for individual rules performed. */
		KSI_LIST(KSI_RuleVerificationResult) *ruleResults;
		/** Results for individual policies performed. */
		KSI_LIST(KSI_RuleVerificationResult) *policyResults;
	};

	KSI_DEFINE_EXTERN(const KSI_Policy* KSI_VERIFICATION_POLICY_EMPTY);
	KSI_DEFINE_EXTERN(const KSI_Policy* KSI_VERIFICATION_POLICY_INTERNAL);
	KSI_DEFINE_EXTERN(const KSI_Policy* KSI_VERIFICATION_POLICY_CALENDAR_BASED);
	KSI_DEFINE_EXTERN(const KSI_Policy* KSI_VERIFICATION_POLICY_KEY_BASED);
	KSI_DEFINE_EXTERN(const KSI_Policy* KSI_VERIFICATION_POLICY_PUBLICATIONS_FILE_BASED);
	KSI_DEFINE_EXTERN(const KSI_Policy* KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED);
	KSI_DEFINE_EXTERN(const KSI_Policy* KSI_VERIFICATION_POLICY_GENERAL);

	typedef enum RuleType_en {
		KSI_RULE_TYPE_BASIC,
		KSI_RULE_TYPE_COMPOSITE_AND,
		KSI_RULE_TYPE_COMPOSITE_OR
	} KSI_RuleType;

	typedef struct KSI_Rule_st {
		KSI_RuleType type;
		const void *rule;
	} KSI_Rule;

	/**
	 * Get #KSI_VerificationErrorCode string representation.
	 *
	 * \param[in]		errorCode		#KSI_VerificationErrorCode value.
	 *
	 * \return A pointer to a statically allocated string value. This pointer may
	 * not be freed by the caller.
	 */
	const char *KSI_VerificationErrorCode_toString(int errorCode);

	/**
	 * Get #KSI_VerificationErrorCode from its string representation.
	 * \param[in]		errCodeStr		C string.
	 * \return #KSI_VerificationErrorCode value. If not found #KSI_VER_ERR_NONE is returned.
	 */
	int KSI_VerificationErrorCode_fromString(const char *errCodeStr);

	/**
	 * Function to convert a #KSI_VerificationErrorCode value to a human readable
	 * string value.
	 *
	 * \param[in]		errorCode		#KSI_VerificationErrorCode value.
	 *
	 * \return A pointer to a statically allocated string value. This pointer may
	 * not be freed by the caller.
	 */
	const char *KSI_Policy_getErrorString(int errorCode);

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
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_setFallback, #KSI_PolicyVerificationResult_free
	 */
	int KSI_SignatureVerifier_verify(const KSI_Policy *policy, KSI_VerificationContext *context, KSI_PolicyVerificationResult **result);

	/**
	 * Frees a user created or cloned #KSI_Policy object. Predefined policies cannot be freed.
	 * The function does not free any potential fallback policy objects which the user must free separately.
	 * \param[in] policy
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Policy_create, #KSI_Policy_clone
	 */
	void KSI_Policy_free(KSI_Policy *policy);

	/**
	 * Frees the verification result object.
	 * \param[in]	result		List of verification results to be freed.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_SignatureVerifier_verify
	 */
	void KSI_PolicyVerificationResult_free(KSI_PolicyVerificationResult *result);

	/**
	 * Frees the temporary data in the context object.
	 * \param[in]	context		Verification context to be cleaned.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_VerificationContext_init
	 */
	void KSI_VerificationContext_clean(KSI_VerificationContext *context);

	/**
	 * Initializes the context with default values.
	 * \param[in]	context 	The verification context.
	 * \param[in]	ctx			The KSI context.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationContext_init(KSI_VerificationContext *context, KSI_CTX *ctx);

#ifdef	__cplusplus
}
#endif

#endif	/* POLICY_H */
