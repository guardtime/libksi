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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#include "internal.h"
#include "io.h"

#ifndef _WIN32
#  include "sys/socket.h"
#  define socket_error errno
#  define socketTimedOut EWOULDBLOCK
#else
#  define socket_error WSAGetLastError()
#  define socketTimedOut WSAETIMEDOUT
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

typedef enum {
	KSI_IO_FILE,
	KSI_IO_MEM,
	KSI_IO_SOCKET
} KSI_IO_Type;

struct KSI_RDR_st {
	/* Context for the reader. */
	KSI_CTX *ctx;

	/* Type of the reader (see #KSI_IO_Type) */
	int ioType;

	/* Union of inputs. */
	union {
		/* KSI_IO_FILE type input. */
		FILE *file;

		/* KSI_IO_MEM type input */
		struct {
			unsigned char *buffer;
			size_t buffer_length;

			/* Does the memory belong to this reader? */
			int ownCopy;
		} mem;
		int socketfd;
	} data;

	/* Offset of stream. */
	size_t offset;

	/* Indicates end of stream.
	 * \note This will be set after reading the stream. */
	int eof;
};

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

int KSI_RDR_getOffset(KSI_RDR *rdr, size_t *offset) {
	int res = KSI_UNKNOWN_ERROR;
	if (rdr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(rdr->ctx);

	if (offset == NULL) {
		KSI_pushError(rdr->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	*offset = rdr->offset;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_RDR_fromStream(KSI_CTX *ctx, FILE *file, KSI_RDR **rdr) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RDR *reader = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || file == NULL || rdr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	reader = newReader(ctx, KSI_IO_FILE);
	if (reader == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	reader->data.file = file;

	*rdr = reader;
	reader = NULL;

	res = KSI_OK;

cleanup:

	KSI_RDR_close(reader);

	return res;
}

int KSI_RDR_fromFile(KSI_CTX *ctx, const char *fileName, const char *flags, KSI_RDR **rdr) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RDR *reader = NULL;
	FILE *file = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || fileName == NULL || flags == NULL || rdr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	file = fopen(fileName, flags);
	if (file == NULL) {
		KSI_pushError(ctx, res = KSI_IO_ERROR, "Unable to open file");
		goto cleanup;
	}

	res = KSI_RDR_fromStream(ctx, file, &reader);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	file = NULL;

	*rdr = reader;
	reader = NULL;

	res = KSI_OK;

cleanup:

	if (file != NULL) fclose(file);
	KSI_RDR_close(reader);

	return res;
}


static int createReader_fromMem(KSI_CTX *ctx, unsigned char *buffer, const size_t buffer_length, int ownCopy, KSI_RDR **rdr) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RDR *reader = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || buffer == NULL || rdr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	reader = newReader(ctx, KSI_IO_MEM);
	if (reader == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	reader->data.mem.buffer = buffer;

	reader->data.mem.buffer_length = buffer_length;
	reader->data.mem.ownCopy = ownCopy;

	*rdr = reader;
	reader = NULL;

	res = KSI_OK;

cleanup:

	KSI_RDR_close(reader);

	return res;
}

int KSI_RDR_fromMem(KSI_CTX *ctx, const unsigned char *buffer, const size_t buffer_length, KSI_RDR **rdr) {
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *buf = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || buffer == NULL || rdr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	buf = KSI_calloc(buffer_length, 1);
	if (buf == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	memcpy(buf, buffer, buffer_length);

	res = createReader_fromMem(ctx, buf, buffer_length, 1, rdr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	buf = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(buf);

	return res;
}

int KSI_RDR_fromSharedMem(KSI_CTX *ctx, unsigned char *buffer, const size_t buffer_length, KSI_RDR **rdr) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || buffer == NULL || rdr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = createReader_fromMem(ctx, buffer, buffer_length, 0, rdr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_RDR_fromSocket(KSI_CTX *ctx, int socketfd, KSI_RDR **rdr) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RDR *reader = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || socketfd < 0 || rdr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	reader = newReader(ctx, KSI_IO_SOCKET);
	if (reader == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	reader->data.socketfd = socketfd;

	*rdr = reader;
	reader = NULL;

	res = KSI_OK;

cleanup:

	return res;
}


int KSI_RDR_isEOF(KSI_RDR *rdr) {
	return rdr->eof;
}

static int readFromFile(KSI_RDR *rdr, unsigned char *buffer, const size_t size, size_t *readCount) {
	int res = KSI_UNKNOWN_ERROR;
	size_t count;

	if (rdr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(rdr->ctx);

	if (buffer == NULL || readCount == NULL) {
		KSI_pushError(rdr->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	count = fread(buffer, 1, size, rdr->data.file);
	/* Update metadata. */
	rdr->offset += count;
	rdr->eof = feof(rdr->data.file);

	*readCount = count;

	res = KSI_OK;

cleanup:

	return res;
}

static int readFromMem(KSI_RDR *rdr, unsigned char *buffer, const size_t buffer_size, size_t *readCount) {
	int res = KSI_UNKNOWN_ERROR;
	size_t count = 0;

	if (rdr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(rdr->ctx);
	if (buffer == NULL || readCount == NULL) {
		KSI_pushError(rdr->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (rdr->data.mem.buffer_length > rdr->offset) {
		/* Max bytes still to read. */
		count = rdr->data.mem.buffer_length - rdr->offset;

		/* Update if requested for less. */
		if (count > buffer_size) count = buffer_size;

		memcpy(buffer, rdr->data.mem.buffer + rdr->offset, count);

		rdr->offset += count;
	}

	/* Update metadata */
	rdr->eof = (rdr->offset >= rdr->data.mem.buffer_length);

	if (readCount != NULL) *readCount = count;

	res = KSI_OK;

cleanup:

	return res;
}

static int readFromSocket(KSI_RDR *rdr, unsigned char *buffer, const size_t size, size_t *readCount) {
	int res = KSI_UNKNOWN_ERROR;
	size_t count = 0;

	if (rdr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(rdr->ctx);

	if (buffer == NULL || readCount == NULL) {
		KSI_pushError(rdr->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if(size > INT_MAX){
		KSI_pushError(rdr->ctx, res = KSI_INVALID_ARGUMENT, "Unable to read more than MAX_INT from the socket.");
		goto cleanup;
	}

	while (!rdr->eof && size > count) {
		int c = recv(rdr->data.socketfd, (char *)buffer + count, (int)(size - count), 0);

		if (c < 0) {
			if (socket_error == socketTimedOut) {
				KSI_pushError(rdr->ctx, res = KSI_NETWORK_RECIEVE_TIMEOUT, "Unable to read from socket."); // TODO! Add errno
			} else {
				KSI_pushError(rdr->ctx, res = KSI_IO_ERROR, "Unable to read from socket."); // TODO! Add errno
			}
			goto cleanup;
		}

		rdr->eof = (c == 0);
		count += c;
	}
	/* Update metadata */
	rdr->offset += count;

	if (readCount != NULL) *readCount = count;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_RDR_read_ex(KSI_RDR *rdr, unsigned char *buffer, const size_t bufferLength, size_t *readCount)  {
	int res = KSI_UNKNOWN_ERROR;

	if (rdr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(rdr->ctx);

	if (buffer == NULL || readCount == NULL) {
		KSI_pushError(rdr->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	switch (rdr->ioType) {
		case KSI_IO_FILE:
			res = readFromFile(rdr, buffer, bufferLength, readCount);
			break;
		case KSI_IO_MEM:
			res = readFromMem(rdr, buffer, bufferLength, readCount);
			break;
		case KSI_IO_SOCKET:
			res = readFromSocket(rdr, buffer, bufferLength, readCount);
			break;
		default:
			KSI_pushError(rdr->ctx, res = KSI_UNKNOWN_ERROR, "Unsupported KSI IO TYPE");
			goto cleanup;
	}

	if (res != KSI_OK) {
		KSI_pushError(rdr->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_RDR_read_ptr(KSI_RDR *rdr, unsigned char **ptr, const size_t len, size_t *readCount) {
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *p = NULL;
	size_t count = 0;

	if (rdr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(rdr->ctx);
	if (ptr == NULL || readCount == NULL) {
		KSI_pushError(rdr->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	switch (rdr->ioType) {
		case KSI_IO_FILE:
			break;
		case KSI_IO_MEM:
			if (rdr->offset < rdr->data.mem.buffer_length) {
				p = rdr->data.mem.buffer + rdr->offset;
				count = len;
				if (rdr->offset + count > rdr->data.mem.buffer_length) {
					count = rdr->data.mem.buffer_length - rdr->offset;
					rdr->eof = 1;
				}

				rdr->offset += count;

				*ptr = p;
				*readCount = count;
			} else {
				rdr->eof = 1;
				*readCount = 0;
			}
			break;
		default:
			KSI_pushError(rdr->ctx, res = KSI_UNKNOWN_ERROR, "Unsupported KSI IO TYPE");
			goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

void KSI_RDR_close(KSI_RDR *rdr)  {
	KSI_CTX *ctx = NULL;

	if (rdr == NULL) return;

	ctx = rdr->ctx;
	rdr->ctx = NULL;

	switch (rdr->ioType) {
		case KSI_IO_FILE:
			if (rdr->data.file != NULL) {
				if (fclose(rdr->data.file)) {
					rdr->data.file = NULL;
					KSI_LOG_warn(ctx, "Unable to close log file.");
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
		case KSI_IO_SOCKET:
			break;
		default:
			KSI_LOG_warn(ctx, "Unsupported KSI IO-type - possible MEMORY LEAK");
	}

	KSI_free(rdr);
}

int KSI_RDR_verifyEnd(KSI_RDR *rdr) {
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *buf = NULL;
	size_t buf_len = 0;

	if (rdr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(rdr->ctx);

	res = KSI_RDR_read_ptr(rdr, &buf, 1, &buf_len);
	if (res != KSI_OK || buf != NULL) {
		KSI_pushError(rdr->ctx, res = KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_nofree(buf);

	return res;

}

KSI_IMPLEMENT_GET_CTX(KSI_RDR);
