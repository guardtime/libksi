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
	 * This functions is used to verify signature \c sig internal consistency. This function behaves as
	 * #KSI_SignatureVerify_internalConsistency except it takes two extra optional parametest \c hsh \c lvl
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[in]		ctx		KSI context
	 * \param[in]		hsh	    Document hash or aggregation root hash when used with root level \c lvl.
	 * If set to NULL, the hash value in the provided signature is not verified
	 * \param[in]		lvl	    Local aggregation level. Base level is 0
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \see #KSI_SignatureVerify_internalConsistency
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_internal(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, KSI_uint64_t lvl, KSI_PolicyVerificationResult **result);

	/**
	 * This functions is used to verify signature \c sig internal consistency.
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[in]		ctx		KSI context
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_internalConsistency(KSI_Signature *sig, KSI_CTX *ctx, KSI_PolicyVerificationResult **result);

	/**
	 * This function verifies given hash value \c hsh using the signature \c sig. This function behaves as
	 * #KSI_SignatureVerify_internalConsistency except it takes an extra parametest \c hsh. This function does
	 * not allow the document hash to be NULL, if you only need to verify the signature without having the
	 * original document (or document hash) use #KSI_SignatureVerify_internalConsistency.
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[in]		ctx		KSI context
	 * \param[in]		hsh	    The signed document hash. The hash may not be NULL.
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \see #KSI_SignatureVerify_internalConsistency
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_documentHash(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, KSI_PolicyVerificationResult **result);


	/**
	 * This function can be used to verify signature \c sig using user provided publication data \c pubData
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[in]		ctx		KSI context
	 * \param[in]		pubData	Publication data
	 * \param[in]		extPerm Extending permission flag
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_userProvidedPublicationBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PublicationData *pubData, int extPerm, KSI_PolicyVerificationResult **result);

	/**
	 * This function can be used to verify signature \c sig using publications file \c pubFile
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[in]		ctx		KSI context
	 * \param[in]		pubFile	Publications file. This parameres is optional, set to NULL if common publications file should be used.
	 * \param[in]		extPerm Extending permission flag
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_publicationsFileBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PublicationsFile *pubFile, int extPerm, KSI_PolicyVerificationResult **result);

	/**
	 * This function can be used if the signature \c sig contains a calendar hash chain and a calendar
	 * authentication record. Key-based verification should be used for short-term verification before a
	 * publication becomes available.
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[in]		ctx		KSI context
	 * \param[in]		pubFile	Publications file. This parameres is optional, set to NULL if common publications file should be used.
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_keyBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PublicationsFile *pubFile, KSI_PolicyVerificationResult **result);

	/**
	 * This function is used to verify the signature \c sig on-line services. It requires access to the extending
	 * service and allows verification using the calendar database as the trust anchor.
	 *
	 * \param[in]		sig	    KSI signature to be verified.
	 * \param[in]		ctx		KSI context
	 * \param[out]		result	Pointer to the verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_PolicyVerificationResult_free.
	 */
	int KSI_SignatureVerify_calendarBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PolicyVerificationResult **result);



#ifdef __cplusplus
}
#endif

#endif /* KSI_SIGNATURE_VERIFY_H_ */
