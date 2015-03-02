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
	int KSI_RDR_fromFile(KSI_CTX *ctx, const char *fileName, const char *flags, KSI_RDR **rdr);

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
	 * Reads at maximum #bufferLength bytes into #buffer and strores number of read bytes in #readCount.
	 *
	 * \return KSI_OK when no errors occured.
	 */
	int KSI_RDR_read_ex(KSI_RDR *rdr, unsigned char *buffer, const size_t bufferLength, size_t *readCount);

	/* TODO!
	 * Method for reading from reader without copyng data. The pointer #ptr will point to the parent payload
	 * area (which itself may not belong to the parent).
	 *
	 * \return The method will return KSI_OK when no error occured.
	 *
	 * \note This method can be applied to only #KSI_RDR which is based on a memory buffer.
	 */
	int KSI_RDR_read_ptr(KSI_RDR *rdr, unsigned char **ptr, const size_t len, size_t *readCount);

	/* TODO!
	 *
	 */
	void KSI_RDR_close(KSI_RDR *rdr);

	int KSI_RDR_verifyEnd(KSI_RDR *rdr);

	KSI_DEFINE_GET_CTX(KSI_RDR);


#ifdef __cplusplus
}
#endif

#endif /* KSI_IO_H_ */
