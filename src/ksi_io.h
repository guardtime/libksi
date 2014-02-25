#ifndef KSI_IO_H_
#define KSI_IO_H_

#include <stdio.h>

#include "ksi_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	KSI_IO_FILE,
	KSI_IO_MEM
} KSI_IO_Type;

struct KSI_RDR_st {
	/* Context for the reader. */
	KSI_CTX *ctx;

	/* Type of the reader (see #KSI_IO_Type) */
	KSI_IO_Type ioType;

	/* Union of inputs. */
	union {
		/* KSI_IO_FILE type input. */
		FILE *file;

		/* KSI_IO_MEM type input */
		struct {
			char *buffer;
			size_t buffer_length;

			/* Does the memory belong to this reader? */
			int ownCopy;
		} mem;
	} data;

	/* Offset of stream. */
	size_t offset;

	/* Indicates end of stream.
	 * \note This will be set after reading the stream. */
	int eof;
};

int KSI_RDR_fromFile(KSI_CTX *ctx, const char *fileName, const char *flags, KSI_RDR **rdr);

int KSI_RDR_fromMem(KSI_CTX *ctx, unsigned char *buffer, const size_t buffer_length, int ownCopy, KSI_RDR **rdr);

int KSI_RDR_isEOF(KSI_RDR *rdr);

/**
 * Reads at maximum #bufferLength bytes into #buffer and strores number of read bytes in #readCount.
 *
 * \return KSI_OK when no errors occured.
 */
int KSI_RDR_readIntoBuffer(KSI_RDR *rdr, unsigned char *buffer, const size_t bufferLength, int *readCount);

/**
 * Method for reading from reader without copyng data. The pointer #ptr will point to the parent payload
 * area (which itself may not belong to the parent).
 *
 * \return The method will return KSI_OK when no error occured.
 *
 * \note This method can be applied to only #KSI_RDR which is based on a memory buffer.
 */
int KSI_RDR_readMemPtr(KSI_RDR *rdr, unsigned char **ptr, const size_t len, int *readCount);

void KSI_RDR_close(KSI_RDR *rdr);

#ifdef __cplusplus
}
#endif

#endif /* KSI_IO_H_ */
