/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
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
	int KSI_HMAC_create(KSI_CTX *ctx, int hash_id, const char *key, const unsigned char *data, unsigned data_len, KSI_DataHash **hmac);

	/**
	 * @}
	 */
#ifdef	__cplusplus
}
#endif

#endif	/* HMAC_H */

