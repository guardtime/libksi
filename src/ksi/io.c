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
	KSI_RDR *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || file == NULL || rdr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = newReader(ctx, KSI_IO_FILE);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->data.file = file;

	*rdr = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_RDR_close(tmp);

	return res;
}

static int createReader_fromMem(KSI_CTX *ctx, unsigned char *buffer, const size_t buffer_length, KSI_RDR **rdr) {
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

	*rdr = reader;
	reader = NULL;

	res = KSI_OK;

cleanup:

	KSI_RDR_close(reader);

	return res;
}

int KSI_RDR_fromSharedMem(KSI_CTX *ctx, unsigned char *buffer, const size_t buffer_length, KSI_RDR **rdr) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || buffer == NULL || rdr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = createReader_fromMem(ctx, buffer, buffer_length, rdr);
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
	KSI_RDR *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || socketfd < 0 || rdr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = newReader(ctx, KSI_IO_SOCKET);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->data.socketfd = socketfd;

	*rdr = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_RDR_close(tmp);

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

int KSI_IO_readSocket(int fd, void *buf, size_t size, size_t *readCount) {
	int res = KSI_UNKNOWN_ERROR;
	int c;
	size_t rd = 0;
	unsigned char *ptr = (unsigned char *) buf;
	size_t len = size;

	if (fd < 0 || buf == NULL || size == 0) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

#ifdef _WIN32
	if (len > INT_MAX) {
		res = KSI_BUFFER_OVERFLOW;
		goto cleanup;
	}
#endif


	while (len > 0) {
#ifdef _WIN32
		c = recv(fd, ptr, (int) len, 0);
#else
		c = recv(fd, ptr, len, 0);
#endif
		if (c < 0) {
			if (socket_error == socketTimedOut) {
				res = KSI_NETWORK_RECIEVE_TIMEOUT;
			} else {
				res = KSI_IO_ERROR;
			}
			goto cleanup;
		}

		/* Do this check just to be safe. */
		if (c > len) {
			res = KSI_BUFFER_OVERFLOW;
			goto cleanup;
		}
		rd += c;

		len -= c;
		ptr += c;
	}



	res = KSI_OK;

cleanup:

	if (readCount != NULL) *readCount = rd;

	return res;
}

int KSI_IO_readFile(FILE *f, void *buf, size_t size, size_t *count) {
	int res = KSI_UNKNOWN_ERROR;
	size_t rd = 0;

	if (f == NULL || buf == NULL || size == 0) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	rd = fread(buf, 1, size, f);

	res = KSI_OK;

cleanup:

	if (count != NULL) *count = rd;

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
			rdr->data.file = NULL;
			break;
		case KSI_IO_MEM:
			rdr->data.mem.buffer = NULL;
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
