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

#ifdef __cplusplus
extern "C" {
#endif

#ifndef KSI_SIGNATURE_STRUCT
	#define KSI_SIGNATURE_STRUCT
	typedef struct KSI_Signature_st KSI_Signature;
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
KSI_FN_DEPRECATED(int KSI_Signature_verify(KSI_Signature *sig, KSI_CTX *ctx));

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
KSI_FN_DEPRECATED(int KSI_Signature_verifyAggregated(KSI_Signature *sig, KSI_CTX *ctx, KSI_uint64_t level));

/**
 * This function verifies the signature internally without attempting to extend it.
 * A publication, if attached to the signature, is not verified.
 *
 * \param[in]	sig			KSI signature.
 * \param[in]	ctx			KSI context, if NULL the context of the signature is used.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_Signature_verifyAggregated, #KSI_Signature_verifyAggregatedHash, #KSI_Signature_verifyDataHash
 */
KSI_FN_DEPRECATED(int KSI_Signature_verifyInternally(KSI_Signature *sig, KSI_CTX *ctx));

/**
 * This function verifies the signature offline without attempting to extend it.
 * If the signature has a publication attached to it, the publication is verified
 * using the publications file.
 *
 * \param[in]	sig			KSI signature.
 * \param[in]	ctx			KSI context, if NULL the context of the signature is used.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_Signature_verifyAggregated, #KSI_Signature_verifyAggregatedHash, #KSI_Signature_verifyDataHash
 */
KSI_FN_DEPRECATED(int KSI_Signature_verifyOffline(KSI_Signature *sig, KSI_CTX *ctx));

/**
 * This function verifies the signature using online resources. The signature is
 * verified by an attempt to extend it. If the extending and verification are successful,
 * the signature itself is not modified.
 *
 * \param[in]	sig			KSI signature.
 * \param[in]	ctx			KSI context, if NULL the context of the signature is used.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
KSI_FN_DEPRECATED(int KSI_Signature_verifyOnline(KSI_Signature *sig, KSI_CTX *ctx));

/**
 * Verifies that the document matches the signature.
 * \param[in]	sig			KSI signature.
 * \param[in]	ctx			KSI context.
 * \param[in]	doc			Pointer to document.
 * \param[in]	doc_len		Document length.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
KSI_FN_DEPRECATED(int KSI_Signature_verifyDocument(KSI_Signature *sig, KSI_CTX *ctx, void *doc, size_t doc_len));

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
KSI_FN_DEPRECATED(int KSI_Signature_verifyDataHash(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *docHash));

/**
 * This function verifies signature using given publication.
 * \param[in]	sig			KSI signature.
 * \param[in]	ctx			KSI context.
 * \param[in]	publication	Publication data used in verification process.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
KSI_FN_DEPRECATED(int KSI_Signature_verifyWithPublication(KSI_Signature *sig, KSI_CTX *ctx, const KSI_PublicationData *publication));

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
KSI_FN_DEPRECATED(int KSI_Signature_verifyAggregatedHash(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *rootHash, KSI_uint64_t rootLevel));

/**
 * Accessor method for verification results.
 * \param[in]	sig			KSI signature.
 * \param[out]	info		Pointer to the receiving pointer.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
KSI_FN_DEPRECATED(int KSI_Signature_getVerificationResult(KSI_Signature *sig, const KSI_VerificationResult **info));

#ifdef __cplusplus
}
#endif

#endif /* KSI_VERIFY_DEPRECATED_H_ */
