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

#ifndef KSI_VERIFY_DEPRECATED_H_
#define KSI_VERIFY_DEPRECATED_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This function verifies the signature using online resources. If the
 * signature has a publication attached to it, the publication is verified
 * using the publications file. Otherwise, the signature is verified by
 * an attempt to extend it.
 *
 * \param[in]	sig			KSI signature.
 * \param[in]	ctx			KSI context, if NULL the context of the signature is used.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_Signature_verifyAggregated, #KSI_Signature_verifyAggregatedHash, #KSI_Signature_verifyDataHash
 */
KSI_FN_DEPRECATED(int KSI_Signature_verify(KSI_Signature *sig, KSI_CTX *ctx), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * This function behaves like #KSI_Signature_verify except, it takes an extra parameter
 * \c level, which indicates the level of the local aggregation.
 *
 * \param[in]	sig			KSI signature.
 * \param[in]	ctx			KSI context, if NULL the context of the signature is used.
 * \param[in]	level		The local aggregation level.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_Signature_verify, #KSI_Signature_verifyAggregatedHash, #KSI_Signature_verifyDataHash
 */
KSI_FN_DEPRECATED(int KSI_Signature_verifyAggregated(KSI_Signature *sig, KSI_CTX *ctx, KSI_uint64_t level), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * This function verifies the signature using online resources. The signature is
 * verified by an attempt to extend it. If the extending and verification are successful,
 * the signature itself is not modified.
 *
 * \param[in]	sig			KSI signature.
 * \param[in]	ctx			KSI context, if NULL the context of the signature is used.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
KSI_FN_DEPRECATED(int KSI_Signature_verifyOnline(KSI_Signature *sig, KSI_CTX *ctx), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * This function verifies given hash value \c hsh using the signature \c sig. If
 * the hash value does not match the input hash value of the signature, a
 * #KSI_VERIFICATION_FAILURE error code is returned.
 *
 * This function does not allow the document hash to be NULL, if you only need to
 * verify the signature without having the original document (or document hash) use
 * #KSI_Signature_verify.
 *
 * \param[in]	sig			KSI signature.
 * \param[in]	ctx			KSI context - if NULL, the context of the signature is used.
 * \param[in]	docHash		The signed document hash. The hash may not be NULL.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
KSI_FN_DEPRECATED(int KSI_Signature_verifyDataHash(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *docHash), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * This function verifies signature using given publication.
 * \param[in]	sig			KSI signature.
 * \param[in]	ctx			KSI context.
 * \param[in]	publication	Publication data used in verification process.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
KSI_FN_DEPRECATED(int KSI_Signature_verifyWithPublication(KSI_Signature *sig, KSI_CTX *ctx, const KSI_PublicationData *publication), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * This function behaves similar to #KSI_Signature_verifyDataHash except it takes an extra parameter
 * \c rootLevel which indicates the local aggregation level.
 *
 * This function does not allow the document hash to be NULL, if you only need to
 * verify the signature without having the original document (or document hash) use
 * #KSI_Signature_verifyAggregated.
 *
 * \param[in]	sig			KSI signature.
 * \param[in]	ctx			KSI context - if NULL, the context of the signature is used.
 * \param[in]	rootHash	The signed aggregation root hash.
 * \param[in]	rootLevel	The level of the root hash.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
KSI_FN_DEPRECATED(int KSI_Signature_verifyAggregatedHash(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *rootHash, KSI_uint64_t rootLevel), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * Accessor method for verification results.
 * \param[in]	sig			KSI signature.
 * \param[out]	info		Pointer to the receiving pointer.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
KSI_FN_DEPRECATED(int KSI_Signature_getVerificationResult(KSI_Signature *sig, const KSI_VerificationResult **info), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * Mark the verification step as failure.
 * \param[in]	info		Verification result.
 * \param[in]	step		Verification step.
 * \param[in]	desc		Verification failure message.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
KSI_FN_DEPRECATED(int KSI_VerificationResult_addFailure(KSI_VerificationResult *info, KSI_VerificationStep step, const char *desc), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * Mark the verification step as success.
 * \param[in]	info		Verification result.
 * \param[in]	step		Verification step.
 * \param[in]	desc		Verification success message.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
KSI_FN_DEPRECATED(int KSI_VerificationResult_addSuccess(KSI_VerificationResult *info, KSI_VerificationStep step, const char *desc), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * Returns the performed step count.
 * \param[in]	info		Verification result.
 * \return count of elements in the verification info.
 */
KSI_FN_DEPRECATED(size_t KSI_VerificationResult_getStepResultCount(const KSI_VerificationResult *info), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * Get the a verification step with the given index.
 * \param[in]	info		Verification result.
 * \param[in]	index		Index of the step.
 * \param[out]	result		Verification step result.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
KSI_FN_DEPRECATED(int KSI_VerificationResult_getStepResult(const KSI_VerificationResult *info, size_t index, const KSI_VerificationStepResult **result), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * Returns 0 if the given verification step is not performed.
 * \param[in]	info		Verification result.
 * \param[in]	step		Verification step.
 * \return 0 is the given verification step is not performed.
 */
KSI_FN_DEPRECATED(int KSI_VerificationResult_isStepPerformed(const KSI_VerificationResult *info, enum KSI_VerificationStep_en step), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * Returns 0 if the given verification step is not performed or the performed step was
 * unsuccessful.
 * \param[in]	info		Verification result.
 * \param[in]	step		Verification step.
 * \returns 0 if the given verification step was unsuccessful or not performed.
 */
KSI_FN_DEPRECATED(int KSI_VerificationResult_isStepSuccess(const KSI_VerificationResult *info, enum KSI_VerificationStep_en step), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * Returns a pointer to the last failure message. If there are no failure messages or
 * an error occurred \c NULL is returned.
 * \param[in]	info		Verification result.
 * \returns Pointer to the last failure message or \c NULL.
 */
KSI_FN_DEPRECATED(const char *KSI_VerificationResult_lastFailureMessage(const KSI_VerificationResult *info), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * Returns the #KSI_VerificationStep value or 0 on an error.
 * \param[in]	result 		Verification step result.
 * \returns 0 if the given verification step was unsuccessful or not performed.
 */
KSI_FN_DEPRECATED(int KSI_VerificationStepResult_getStep(const KSI_VerificationStepResult *result), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * Returns if the verification step result was successful.
 * \param[in]	result		Verification step result.
 * \return If the step was not successful 0 is returned, otherwise !0.
 */
KSI_FN_DEPRECATED(int KSI_VerificationStepResult_isSuccess(const KSI_VerificationStepResult *result), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

/**
 * Returns a pointer to the description of this step result.
 * \param[in]	result		Verification step result.
 */
KSI_FN_DEPRECATED(const char *KSI_VerificationStepResult_getDescription(const KSI_VerificationStepResult *result), New verification approach is described in [Verification Tutorial](tutorial/t2_verifying.md).);

#ifdef __cplusplus
}
#endif

#endif /* KSI_VERIFY_DEPRECATED_H_ */
