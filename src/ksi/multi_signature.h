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

#ifndef MULTI_SIGNATURE_H_
#define MULTI_SIGNATURE_H_

#include "ksi.h"

#ifdef __cplusplus
extern "C" {
#endif
	/**
	 * \addtogroup multi_signature KSI Multi Signature Container
	 * The multi signature container is a structure to store several KSI signatures. It does not store
	 * the references to the signatures itself, but the internal components. While extracting a signature
	 * it is a new object.
	 * @{
	 */

	typedef struct KSI_MultiSignature_st KSI_MultiSignature;

	/**
	 * Constructor for an empty multi signature container.
	 * \param[in]		ctx			KSI context.
	 * \param[out]		ms			Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The caller must free the multi signature container by calling #KSI_MultiSignature_free.
	 */
	int KSI_MultiSignature_new(KSI_CTX *ctx, KSI_MultiSignature **ms);

	/**
	 * Cleanup method for the multi signature container.
	 * \param[in]		ms			The multi signature container to be freed.
	 */
	void KSI_MultiSignature_free(KSI_MultiSignature *ms);

	/**
	 * Method for adding a uni-signature to the multi signature container.
	 * \param[in]		ms			The multi signature container.
	 * \param[in]		sig			The uni signature to be aaded.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The signature won't change ownership and needs to be freed.
	 */
	int KSI_MultiSignature_add(KSI_MultiSignature *ms, const KSI_Signature *sig);

	/**
	 * Method for extracting uni-signatures from the multi signature container.
	 * \param[in]		ms			The multi signature container.
	 * \param[in]		hsh			The hash value of the signed data.
	 * \param[out]		sig			Pointer to the receiving pointer.
	 * \note The multi signature container is not a collection type. When a signature is added and
	 * later extracted from it, the objects are different and thus the output signature must be freed
	 * individually.
	 * \return status code (#KSI_OK, when operation succeeded, #KSI_MULTISIG_NOT_FOUND if the
	 * the signature was not found, otherwise an error code).
	 */
	int KSI_MultiSignature_get(KSI_MultiSignature *ms, const KSI_DataHash *hsh, KSI_Signature **sig);

	/**
	 * This method is used to remove a uni signature from the multi signature container.
	 * \param[in]		ms			The multi signature container.
	 * \param[in]		hsh			The hash value of the signed data.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_MultiSignature_remove(KSI_MultiSignature *ms, const KSI_DataHash *hsh);

	/**
	 * This function is used to get all the hash algorithms for the input data used in this
	 * multi signature container.
	 * \param[in]		ms			The multi signature container.
	 * \param[out]		arr			Pointer to the receiving pointer.
	 * \param[out]		arr_len		Length of the output array.
	 * \note The output array belongs to the caller, and therefore is responsible for cleaning up the memory
	 * using #KSI_free.
	 * \see #KSI_free
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_MultiSignature_getUsedHashAlgorithms(KSI_MultiSignature *ms, KSI_HashAlgorithm **arr, size_t *arr_len);

	/**
	 * This function extends all signatures to the nearest (oldest) publication.
	 * \param[in]		ms			The multi signature container.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_MultiSignature_extend(KSI_MultiSignature *ms);

	/**
	 * This function extends all signatures created before the publication record to the given publication.
	 * \param[in]		ms			The multi signature container.
	 * \param[in]		pubRec		Publication record.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_MultiSignature_extendToPublication(KSI_MultiSignature *ms, const KSI_PublicationRecord *pubRec);

	KSI_DEFINE_WRITE_BYTES(KSI_MultiSignature);

	/**
	 * Parses a KSI multi signature container from a raw buffer. The raw buffer may be freed after
	 * this function finishes. To reserialize the multi signature container use #KSI_MultiSignature_writeBytes.
	 *
	 * \param[in]		ctx			KSI context.
	 * \param[in]		raw			Pointer to the raw signature.
	 * \param[in]		raw_len		Length of the raw signature.
	 * \param[out]		ms			Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_MultiSignature_free
	 */
	int KSI_MultiSignature_parse(KSI_CTX *ctx, const unsigned char *raw, size_t raw_len, KSI_MultiSignature **ms);

	/**
	 * This function reads and parses the multi signature container from a file.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		fileName	File name of the multi signature container.
	 * \param[out]		ms			Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_MultiSignature_free
	 * \note It must be noted that access to metadata, supported by some file systems,
	 * is limited by the use of function \c fopen. Alternate Data Streams (WIndows NTFS)
	 * and Resource Forks (OS X HFS) may or may not be supported, depending on the
	 * C standard library used in the application.
	 */
	int KSI_MultiSignature_fromFile(KSI_CTX *ctx, const char *fileName, KSI_MultiSignature **ms);

	/**
	 * This function allocates enough memory and serializes the multi signature container into it.
	 * \param[in]		ms			KSI multi signature container.
	 * \param[out]		raw			Pointer to the receiving pointer.
	 * \param[out]		raw_len		Pointer to the reveiving length variable.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_MultiSignature_fromFile, #KSI_MultiSignature_parse
	 */
	int KSI_MultiSignature_serialize(KSI_MultiSignature *ms, unsigned char **raw, size_t *raw_len);

	/**
	 * @}
	 */

#ifdef __cplusplus
}
#endif

#endif /* MULTI_SIGNATURE_H_ */
