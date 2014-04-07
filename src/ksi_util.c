#include "ksi_internal.h"

int KSI_decodeHexStr(const char *hexstr, unsigned char *buf, int buf_size, int *buf_length) {
	int res = KSI_UNKNOWN_ERROR;
	int i = 0;
	int len = 0;
	int count = 0;

	while (hexstr[i]) {
		char chr = hexstr[i++];
		if (isspace(chr)) continue;

		if (len >= buf_size) {
			res = KSI_BUFFER_OVERFLOW;
			goto cleanup;
		}

		if (count == 0) {
			buf[len] = 0;
		}

		chr = tolower(chr);
		if (isdigit(chr)) {
			buf[len] = buf[len] << 4 | (chr - '0');
		} else if (chr >= 'a' && chr <= 'f') {
			buf[len] = buf[len] << 4 | (chr - 'a' + 10);
		} else {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}

		if (++count > 1) {
			count = 0;
			len++;
		}
	}

	if (count != 0) {
		/* Single char hex value. */
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	*buf_length = len;

	res = KSI_OK;

cleanup:

	return res;
}
