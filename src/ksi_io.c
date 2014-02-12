#include <stdlib.h>
#include <string.h>

#include "ksi_internal.h"

static KSI_RDR *newReader(KSI_CTX *ctx, KSI_IO_Type ioType) {
	KSI_RDR *rdr = NULL;
	rdr = KSI_new(KSI_RDR);
	if (rdr == NULL) goto cleanup;

	rdr->ctx = ctx;
	rdr->eof = 0;
	rdr->ioType = ioType;
	rdr->offset = 0;

cleanup:
	return rdr;
}

int KSI_RDR_fromFile(KSI_CTX *ctx, const char *fileName, const char *flags, KSI_RDR **rdr) {
	KSI_ERR err;
	KSI_RDR *reader = NULL;
	FILE *file = NULL;

	KSI_begin(ctx, &err);

	reader = newReader(ctx, KSI_IO_FILE);
	if (reader == NULL) {
		KSI_fail(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	file = fopen(fileName, flags);

	if (file == NULL) {
		KSI_fail(&err, KSI_IO_ERROR, "Unable to open file");
		goto cleanup;
	}

	reader->data.file = file;
	file = NULL;

	*rdr = reader;
	reader = NULL;

	KSI_success(ctx);

cleanup:
	if (file != NULL) fclose(file);
	KSI_RDR_close(reader);

	return KSI_end(&err);
}

int KSI_RDR_fromMem(KSI_CTX *ctx, char *buffer, const size_t buffer_length, int ownCopy, KSI_RDR **rdr) {
	KSI_ERR err;
	KSI_RDR *reader = NULL;
	char *buf = NULL;

	KSI_begin(ctx, &err);

	reader = newReader(ctx, KSI_IO_FILE);
	if (reader == NULL) {
		KSI_fail(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if (ownCopy) {
		buf = KSI_calloc(buffer_length, 1);
	} else {
		buf = buffer;
	}

	reader->data.mem.buffer = buf;
	buf = NULL;

	reader->data.mem.buffer_length = buffer_length;
	reader->data.mem.ownCopy = ownCopy;

	*rdr = reader;
	reader = NULL;
cleanup:
	KSI_free(buf);

	KSI_RDR_close(reader);

	return KSI_end(&err);
}


int KSI_RDR_isEOF(KSI_RDR *rdr) {
	return rdr->eof;
}


int KSI_RDR_read(KSI_RDR *rdr, char *buffer, size_t *length)  {
	KSI_ERR err;
	KSI_begin(rdr->ctx, &err);

	switch (rdr->ioType) {
		case KSI_IO_FILE:

			break;
		case KSI_IO_MEM:
			break;
		default:
			KSI_fail(&err, KSI_UNKNOWN_ERROR, "Unsupported KSI IO TYPE");
	}

cleanup:
	return KSI_end(&err);
}


void KSI_RDR_close(KSI_RDR *rdr)  {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;

	if (rdr == NULL) return;

	ctx = rdr->ctx;
	rdr->ctx = NULL;

	/* NB! Do not call #KSI_begin. */

	switch (rdr->ioType) {
		case KSI_IO_FILE:
			if (rdr->data.file != NULL) {
				if (!fclose(rdr->data.file)) {
					KSI_fail(&err, KSI_IO_ERROR, "Unable to close file.");
				}
			}
			rdr->data.file = NULL;
			break;
		case KSI_IO_MEM:
			if (rdr->data.mem.ownCopy) {
				KSI_free(rdr->data.mem.buffer);
				rdr->data.mem.buffer = NULL;
			}
			break;
		default:
			KSI_fail(&err, KSI_UNKNOWN_ERROR, "Unsupported KSI IO TYPE");
	}

	KSI_free(rdr);
}
