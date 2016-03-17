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

#ifndef KSI_SIGNATURE_VERIFY_H_
#define KSI_SIGNATURE_VERIFY_H_

#include "types.h"
#include "policy.h"
#include "signature.h"

#ifdef __cplusplus
extern "C" {
#endif


	/**
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_internal(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, KSI_uint64_t rootLevel, KSI_PolicyVerificationResult **result);

	/**
	 * This function verified signature internal consistency
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_internalConsistency(KSI_Signature *sig, KSI_CTX *ctx, KSI_PolicyVerificationResult **result);

	/**
	 * This function verifies given hash value \c hsh using the signature \c sig.
	 *
	 * This function does not allow the document hash to be NULL, if you only need to
	 * verify the signature without having the original document (or document hash) use
	 * #KSI_SignatureVerify_internalConsistency.
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[in]		hsh	    The signed document hash. The hash may not be NULL.
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_documentHash(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, KSI_PolicyVerificationResult **result);


	/**
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_UserProvidedPublicationBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PublicationData *pubData, int extPerm, KSI_PolicyVerificationResult **result);

	/**
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_PublicationsFileBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PublicationsFile *pubFile, int extPerm, KSI_PolicyVerificationResult **result);

	/**
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_KeyBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PolicyVerificationResult **result);

	/**
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_CalendarBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PolicyVerificationResult **result);



#ifdef __cplusplus
}
#endif

#endif /* KSI_SIGNATURE_VERIFY_H_ */
