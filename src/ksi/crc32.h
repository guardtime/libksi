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

#ifndef KSI_CRC32_H_
#define KSI_CRC32_H_

#include <stddef.h>

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
