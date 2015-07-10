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

	/* TODO
	 *
	 */
	int KSI_RDR_fromStream(KSI_CTX *ctx, FILE *file, KSI_RDR **rdr);

	/* TODO!
	 *
	 */
	int KSI_RDR_fromMem(KSI_CTX *ctx, const unsigned char *buffer, const size_t buffer_length, KSI_RDR **rdr);
	int KSI_RDR_fromSharedMem(KSI_CTX *ctx, unsigned char *buffer, const size_t buffer_length, KSI_RDR **rdr);
	int KSI_RDR_fromSocket(KSI_CTX *ctx, int socketfd, KSI_RDR **rdr);

	/* TODO!
	 *
	 */
	int KSI_RDR_isEOF(KSI_RDR *rdr);

	int KSI_RDR_getOffset(KSI_RDR *rdr, size_t *offset);

	/* TODO!
	 * Reads at maximum #bufferLength bytes into #buffer and stores number of read bytes in #readCount.
	 *
	 * \return KSI_OK when no errors occurred.
	 */
	int KSI_RDR_read_ex(KSI_RDR *rdr, unsigned char *buffer, const size_t bufferLength, size_t *readCount);

	/* TODO!
	 * Method for reading from reader without copying data. The pointer #ptr will point to the parent payload
	 * area (which itself may not belong to the parent).
	 *
	 * \return The method will return KSI_OK when no error occurred.
	 *
	 * \note This method can be applied to only #KSI_RDR which is based on a memory buffer.
	 */
	int KSI_RDR_read_ptr(KSI_RDR *rdr, unsigned char **ptr, const size_t len, size_t *readCount);

	/* TODO!
	 *
	 */
	void KSI_RDR_close(KSI_RDR *rdr);

	int KSI_RDR_verifyEnd(KSI_RDR *rdr);

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

	KSI_DEFINE_GET_CTX(KSI_RDR);


#ifdef __cplusplus
}
#endif

#endif /* KSI_IO_H_ */
