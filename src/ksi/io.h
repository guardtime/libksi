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

#ifndef KSI_IO_H_
#define KSI_IO_H_

#include "ksi.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * Reads \c size bytes from the socket.
	 * \param[in]	fd		Socket descriptor
	 * \param[in]	buf		Pointer to pre-allocated buffer.
	 * \param[in]	size	Size of \c buf.
	 * \param[out]	count	Output of read bytes.
	 *
	 * \return The method will return KSI_OK when no error occurred.
	 */
	int KSI_IO_readSocket(int fd, void *buf, size_t size, size_t *count);

	/**
	 * Reads \c size bytes from the file stream.
	 * \param[in]	f		File descriptor
	 * \param[in]	buf		Pointer to pre-allocated buffer.
	 * \param[in]	size	Size of \c buf.
	 * \param[out]	count	Output of read bytes.
	 *
	 * \return The method will return KSI_OK when no error occurred.
	 */
	int KSI_IO_readFile(FILE *f, void *buf, size_t size, size_t *count);

#ifdef __cplusplus
}
#endif

#endif /* KSI_IO_H_ */
