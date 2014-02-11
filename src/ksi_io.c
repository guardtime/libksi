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

	KSI_success(&err);

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

static int readFromFile(KSI_RDR *rdr, char *buffer, const size_t size, int *readCount) {
	KSI_ERR err;
	int count;

	/* Init error handling. */
	KSI_begin(rdr->ctx, &err);
	count = fread(buffer, 1, size, rdr->data.file);
	/* Update metadata. */
	rdr->offset += count;
	rdr->eof = feof(rdr->data.file);

	if (readCount != NULL) *readCount = count;

	KSI_success(&err);

cleanup:

	return KSI_end(&err);
}

static int readFromMem(KSI_RDR *rdr, char *buffer, const size_t size, int *readCount) {
	KSI_ERR err;
	int count;

	/* Init error handling. */
	KSI_begin(rdr->ctx, &err);

	/* Max bytes still to read. */
	count = rdr->data.mem.buffer_length - rdr->offset;

	/* Update if requested for less. */
	if (count > size) count = size;

	memcpy(buffer, rdr->data.mem.buffer + rdr->offset, count);

	/* Update metadata */
	rdr->offset += count;
	rdr->eof = (rdr->offset == rdr->data.mem.buffer_length);

	if (readCount != NULL) *readCount = count;

	KSI_success(&err);

cleanup:

	return KSI_end(&err);
}


int KSI_RDR_read(KSI_RDR *rdr, char *buffer, const size_t bufferLength, int *readCount)  {
	KSI_ERR err;
	int res;

	KSI_begin(rdr->ctx, &err);

	switch (rdr->ioType) {
		case KSI_IO_FILE:
			res = readFromFile(rdr, buffer, bufferLength, readCount);
			break;
		case KSI_IO_MEM:
			res = readFromMem(rdr, buffer, bufferLength, readCount);
			break;
		default:
			KSI_fail(&err, KSI_UNKNOWN_ERROR, "Unsupported KSI IO TYPE");
			goto cleanup;
	}

	if (res != KSI_OK) goto cleanup;

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
				if (fclose(rdr->data.file)) {
					rdr->data.file = NULL;
					KSI_ERR_fail(&err, KSI_IO_ERROR, 0, __FILE__, __LINE__, "Unable to close log file.");
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
