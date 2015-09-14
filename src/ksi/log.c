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

#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "internal.h"
#include "ctx_impl.h"
#include "tlv.h"

static const char *level2str(int level) {
	switch (level) {
		case KSI_LOG_DEBUG: return "DEBUG";
		case KSI_LOG_INFO: return "INFO";
		case KSI_LOG_NOTICE: return "NOTICE";
		case KSI_LOG_WARN: return "WARN";
		case KSI_LOG_ERROR: return "ERROR";
		default: return "UNKNOWN LOG LEVEL";
	}
}

static int writeLog(KSI_CTX *ctx, int logLevel, char *format, va_list va) {
	int res = KSI_UNKNOWN_ERROR;
	char msg[0xffff + 1024];

	if (ctx == NULL || format == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	if (ctx->loggerCB == NULL || ctx->logLevel < logLevel) {
		/* Do not perform logging. */
		res = KSI_OK;
		goto cleanup;
	}

	KSI_vsnprintf(msg, sizeof(msg), format, va);
	res = ctx->loggerCB(ctx->loggerCtx, logLevel, msg);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static int KSI_LOG_log(KSI_CTX *ctx, int level, char *format, ...) {
	int res;
	va_list va;
	va_start(va, format);
	res = writeLog(ctx, level, format, va);
	va_end(va);
	return res;
}

#define KSI_LOG_FN(suffix, level) \
int KSI_LOG_##suffix(KSI_CTX *ctx, char *format, ...) { \
	int res; \
	va_list va; \
	va_start(va, format); \
	res = writeLog(ctx, KSI_LOG_##level, format, va); \
	va_end(va); \
	return res; \
}

KSI_LOG_FN(debug, DEBUG);
KSI_LOG_FN(info, INFO);
KSI_LOG_FN(notice, NOTICE);
KSI_LOG_FN(warn, WARN);
KSI_LOG_FN(error, ERROR);

int KSI_LOG_logBlob(KSI_CTX *ctx, int level, const char *prefix, const unsigned char *data, size_t data_len) {
	int res = KSI_UNKNOWN_ERROR;
	char *logStr = NULL;
	size_t logStr_size = 0;
	size_t logStr_len = 0;
	size_t i;

	if (ctx == NULL || (data == NULL && data_len != 0) || (data != NULL && data_len == 0)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (level < ctx->logLevel) goto cleanup;

	logStr_size = data_len * 2 + 1;

	logStr = KSI_calloc(logStr_size, 1);
	if (logStr == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	for (i = 0; i < data_len; i++) {
		size_t written;
		written = KSI_snprintf(logStr + logStr_len, logStr_size - logStr_len, "%02x", data[i]);
		if (written == 0 || (size_t) written > logStr_size - logStr_len) {
			res = KSI_BUFFER_OVERFLOW;
			goto cleanup;
		}
		logStr_len += (unsigned)written;
	}

	res = KSI_LOG_log(ctx, level, "%s (len = %lld): %s", prefix, (long long)data_len, logStr);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	KSI_free(logStr);

	return res;
}

int KSI_LOG_logTlv(KSI_CTX *ctx, int level, const char *prefix, const KSI_TLV *tlv) {
	int res = KSI_UNKNOWN_ERROR;
	char serialized[0x1ffff];

	if (level < ctx->logLevel) {
		res = KSI_OK;
		goto cleanup;
	}

	if (tlv != NULL) {
		KSI_TLV_toString(tlv, serialized, sizeof(serialized));
		res = KSI_LOG_log(ctx, level, "%s:\n%s", prefix, serialized);
	} else {
		res = KSI_LOG_log(ctx, level, "%s:\n%s", prefix, "(null)");
	}

cleanup:

	if (res != KSI_OK) {
		KSI_LOG_log(ctx, level, "%s: Unable to log tlv value - %s", prefix, KSI_getErrorString(res));
	}

	return res;
}

int KSI_LOG_logDataHash(KSI_CTX *ctx, int level, const char *prefix, const KSI_DataHash *hsh) {
	int res = KSI_UNKNOWN_ERROR;
	const unsigned char *imprint = NULL;
	size_t imprint_len = 0;

	if (level < ctx->logLevel) {
		res = KSI_OK;
		goto cleanup;
	}

	if (hsh == NULL) {
		res = KSI_LOG_log(ctx, level, "%s: null", prefix);
		goto cleanup;
	}
	res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_LOG_logBlob(ctx, level, prefix, imprint, imprint_len);

cleanup:

	if (res != KSI_OK) {
		KSI_LOG_log(ctx, level, "%s: Unable to log data hash value - %s", prefix, KSI_getErrorString(res));
	}

	KSI_nofree(imprint);

	return res;
}

int KSI_LOG_logCtxError(KSI_CTX *ctx, int level) {
	KSI_ERR *err = NULL;
	unsigned int i;
	int res = KSI_UNKNOWN_ERROR;

	if(ctx == NULL) goto cleanup;

	if (level < ctx->logLevel) {
		res = KSI_OK;
		goto cleanup;
	}
	KSI_LOG_log(ctx, level, "KSI error trace:");
	if (ctx->errors_count == 0) {
		KSI_LOG_log(ctx, level, "  No errors.");
		goto cleanup;
	}

	/* List all errors, starting from the most general. */
	for (i = 0; i < ctx->errors_count && i < ctx->errors_size; i++) {
		err = ctx->errors + ((ctx->errors_count - i - 1) % ctx->errors_size);
		KSI_LOG_log(ctx, level, "  %3u) %s:%u - (%d/%ld) %s", ctx->errors_count - i, err->fileName, err->lineNr,err->statusCode, err->extErrorCode, err->message);
	}

	/* If there where more errors than buffers for the errors, indicate the fact */
	if (ctx->errors_count > ctx->errors_size) {
		KSI_LOG_log(ctx, level, "  ... (more errors)");
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_LOG_StreamLogger(void *logCtx, int logLevel, const char *message) {
	char time_buf[32];
	struct tm *tm_info;
	time_t timer;
	FILE *f = (FILE *) logCtx;

	timer = time(NULL);

	tm_info = localtime(&timer);
	if (tm_info == NULL) {
		return KSI_UNKNOWN_ERROR;
	}

	if (f != NULL) {
		strftime(time_buf, sizeof(time_buf), "%d.%m.%Y %H:%M:%S", tm_info);
		fprintf(f, "%s [%s] - %s\n", level2str(logLevel), time_buf, message);
	}

	return KSI_OK;
}

