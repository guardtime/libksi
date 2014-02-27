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

#ifdef __cplusplus
}
#endif

#endif /* KSI_IO_H_ */
