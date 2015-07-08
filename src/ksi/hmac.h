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

#include "types_base.h"

#ifdef	__cplusplus
extern "C" {
#endif
	/**
	 * \addtogroup util
	 * @{
	 */

	/**
	 * Creates a #KSI_DataHash representing the HMAC value calculated by the key and data using \c alg as the hash algorithm.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	hash_id		Hash algorithm ID see KSI_Hash
	 * \param[in]	key			Key value for the HMAC.
	 * \param[in]	data		Pointer to the data to be HMAC'ed.
	 * \param[in]	data_len	Length of the data.
	 * \param[out]	hmac		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHash_free
	 */
	int KSI_HMAC_create(KSI_CTX *ctx, int hash_id, const char *key, const unsigned char *data, size_t data_len, KSI_DataHash **hmac);

	/**
	 * @}
	 */
#ifdef	__cplusplus
}
#endif

#endif	/* HMAC_H */

