/*
 * Copyright 2013-2017 Guardtime, Inc.
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
#include "impl/net_sock_impl.h"

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
		KSI_SCK_TEMP_FAILURE_RETRY(c, recv(fd, ptr, (int) len, 0));
#else
		KSI_SCK_TEMP_FAILURE_RETRY(c, recv(fd, ptr, len, 0));
#endif
		if (c == 0) {
			/* Connection closed from server side. */
			res = KSI_NETWORK_ERROR;
			goto cleanup;
		} else if (c == KSI_SCK_SOCKET_ERROR) {
			if (KSI_SCK_errno == KSI_SCK_EWOULDBLOCK || KSI_SCK_errno == KSI_SCK_ETIMEDOUT) {
				res = KSI_NETWORK_RECIEVE_TIMEOUT;
			} else {
				res = KSI_IO_ERROR;
			}
			goto cleanup;
		}

		/* Do this check just to be safe. */
		if ((size_t) c > len) {
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
