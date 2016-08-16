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


#ifndef SIGNATURE_HELPER_H_
#define SIGNATURE_HELPER_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * Access method for the hash algorithm used to hash the signed document.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		algo_id		Pointer to the receiving hash id variable.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHasher_open, #KSI_DataHash_create, #KSI_DataHasher_close,
	 * #KSI_Signature_createDataHasher.
	 */
	int KSI_Signature_getHashAlgorithm(KSI_Signature *sig, KSI_HashAlgorithm *algo_id);

	/**
	 * This method creates a data hasher object to be used on the signed data.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		hsr			Data hasher.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHasher_free, #KSI_DataHasher_close, #KSI_DataHasher_open,
	 * #KSI_Signature_getHashAlgorithm.
	 */
	int KSI_Signature_createDataHasher(KSI_Signature *sig, KSI_DataHasher **hsr);

	/**
	 * Verifies that the document matches the signature.
	 * \param[in]	sig			KSI signature.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	doc			Pointer to document.
	 * \param[in]	doc_len		Document length.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_Signature_verifyDocument(KSI_Signature *sig, KSI_CTX *ctx, void *doc, size_t doc_len);

	/**
	 * A convenience function for reading a signature from a file.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		fileName	Name of the signature file.
	 * \param[out]		sig			Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note It must be noted that access to metadata, supported by some file systems,
	 * is limited by the use of function \c fopen. Alternate Data Streams (WIndows NTFS)
	 * and Resource Forks (OS X HFS) may or may not be supported, depending on the
	 * C standard library used in the application.
	 */
	int KSI_Signature_fromFile(KSI_CTX *ctx, const char *fileName, KSI_Signature **sig);

	/**
	 * This function signs the given data hash \c hsh. This function requires a access to
	 * a working aggregator and fails if it is not accessible.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		hsh			Document hash.
	 * \param[out]		signature	Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note For signing hash values, the use of #KSI_createSignature is strongly
	 * recomended.
	 * \see #KSI_createSignature, KSI_Signature_free
	 */
	int KSI_Signature_sign(KSI_CTX *ctx, KSI_DataHash *hsh, KSI_Signature **signature);

	/**
	 * \deprecated This function is deprecated and #KSI_Signature_sign should be used instead.
	 * \see #KSI_Signature_sign
	 */
	KSI_FN_DEPRECATED(int KSI_Signature_create(KSI_CTX *ctx, KSI_DataHash *hsh, KSI_Signature **signature));

	/**
	 * \deprecated This function is deprecated and #KSI_Signature_signAggregated should be used instead.
	 * \see #KSI_Signature_signAggregated
	 */
	KSI_FN_DEPRECATED(int KSI_Signature_createAggregated(KSI_CTX *ctx, KSI_DataHash *rootHash, KSI_uint64_t rootLevel, KSI_Signature **signature));

#ifdef __cplusplus
}
#endif

#endif /* SIGNATURE_HELPER_H_ */
