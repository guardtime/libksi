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

#ifndef KSI_CRC32_H_
#define KSI_CRC32_H_

#ifdef __cplusplus
extern "C" {
#endif
/**
 * \addtogroup util Util
 * @{
 */

	/**
	 * Calculates CRC32 checksum.
	 * \param[in]		data		Pointer to the data.
	 * \param[in]		length		Length of the data.
	 * \param[in]		ival		Initial value. Pass 0 for the first or single call to this
	 * 								function and pass result from the previous call for the next part of the
	 * 								data.
	 * \return CRC32 of the data.
	 */
	unsigned long KSI_crc32(const void *data, size_t length, unsigned long ival);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* KSI_CRC32_H_ */
