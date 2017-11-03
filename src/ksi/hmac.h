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

#ifndef HMAC_H
#define	HMAC_H

#include "types.h"

#ifdef	__cplusplus
extern "C" {
#endif
	/**
	 * \addtogroup util
	 * @{
	 */

	/**
	 * This structure is used for calculating the HMAC hash values.
	 * \see #KSI_DataHash, #KSI_HmacHasher_open, #KSI_HmacHasher_reset, #KSI_HmacHasher_close, #KSI_HmacHasher_free
	 */
	typedef struct KSI_HmacHasher_st KSI_HmacHasher;

	/**
	 * Creates a #KSI_DataHash representing the HMAC value calculated by the key and data using \c alg as the hash algorithm.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	algo_id		Hash algorithm ID see KSI_Hash
	 * \param[in]	key			Key value for the HMAC.
	 * \param[in]	data		Pointer to the data to be HMAC'ed.
	 * \param[in]	data_len	Length of the data.
	 * \param[out]	hmac		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHash_free
	 */
	int KSI_HMAC_create(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, const char *key, const unsigned char *data, size_t data_len, KSI_DataHash **hmac);

	/**
	 * Starts an HMAC computation.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		algo_id 	Identifier of the hash algorithm.
	 * See #KSI_HashAlgorithm_en for possible values.
	 * \param[in]		key			Key value for the HMAC.
	 * \param[out] hasher Pointer that will receive pointer to the
	 * hasher object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_HmacHasher_add, #KSI_HmacHasher_close
	 */
	int KSI_HmacHasher_open(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, const char *key, KSI_HmacHasher **hasher);

	/**
	 * Resets the state of the HMAC computation.
	 * \param[in]	hasher			The hasher.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_HmacHasher_open, #KSI_HmacHasher_close
	 */
	int KSI_HmacHasher_reset(KSI_HmacHasher *hasher);

	/**
	 * Adds data to an open HMAC computation.
	 *
	 * \param[in]	hasher				Hasher object.
	 * \param[in]	data				Pointer to the data to be hashed.
	 * \param[in]	data_length			Length of the hashed data.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_HmacHasher_open, #KSI_HmacHasher_close
	 */
	int KSI_HmacHasher_add(KSI_HmacHasher *hasher, const void *data, size_t data_length);

	/**
	 * Finalizes an HMAC computation.
	 * \param[in]	hasher			Hasher object.
	 * \param[out]	hmac			Pointer that will receive pointer to the hash object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_HmacHasher_open, #KSI_HmacHasher_add, #KSI_HmacHasher_free
	 */
	int KSI_HmacHasher_close(KSI_HmacHasher *hasher, KSI_DataHash **hmac);

	/**
	 * Frees the hasher object.
	 * \param[in]		hasher			Hasher object.
	 *
	 * \see #KSI_HmacHasher_open
	 */
	void KSI_HmacHasher_free(KSI_HmacHasher *hasher);


	/**
	 * @}
	 */
#ifdef	__cplusplus
}
#endif

#endif	/* HMAC_H */

