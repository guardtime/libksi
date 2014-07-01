#include <stdarg.h>
#include <string.h>
#include <time.h>

#include "internal.h"

struct KSI_Logger_st {
	KSI_CTX *ctx;
	int logLevel;
	FILE *logStream;
	char *logFile;

};

static const char *level2str(int level) {
	switch (level) {
		case KSI_LOG_TRACE: return "TRACE";
		case KSI_LOG_DEBUG: return "DEBUG";
		case KSI_LOG_WARN: return "WARN";
		case KSI_LOG_INFO: return "INFO";
		case KSI_LOG_ERROR: return "ERROR";
		case KSI_LOG_FATAL: return "FATAL";
		default: return "UNKNOWN LOG LEVEL";
	}
}

static int writeLog(KSI_CTX *ctx, int logLevel, char *format, va_list va) {
	int res;
	FILE *f = NULL;
	struct tm *tm_info;
	char time_buf[32];
	time_t timer;
	KSI_Logger *logger = NULL;

	res = KSI_getLogger(ctx, &logger);
	if (res != KSI_OK) goto cleanup;

	timer = time(NULL);


	if (ctx == NULL || format == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	if (logger == NULL || logger->logLevel < logLevel) {
		/* Do not perform logging.
		 * NB! Do not call macro #KSI_success. */
		res = KSI_OK;

		goto cleanup;
	}
	f = logger->logStream;

	if (f != NULL) {
		tm_info = localtime(&timer);
		strftime(time_buf, sizeof(time_buf), "%d.%m.%Y %H:%M:%S", tm_info);

		fprintf(f, "%s [%s] - ", level2str(logLevel), time_buf);
		vfprintf(f, format, va);
		fprintf(f, "\n");
	}
	/* NB! Do not call macro #KSI_success. */
	res = KSI_OK;

cleanup:

	return res;
}

#define KSI_LOG_FN(suffix, level) \
int KSI_LOG_##suffix(KSI_CTX *ctx, char *format, ...) { \
	int res; \
	va_list va; \
	va_start(va, format);\
	res = writeLog(ctx, KSI_LOG_##level, format, va); \
	va_end(va); \
	return res; \
}

KSI_LOG_FN(trace, TRACE);
KSI_LOG_FN(debug, DEBUG);
KSI_LOG_FN(warn, WARN);
KSI_LOG_FN(info, INFO);
KSI_LOG_FN(error, ERROR);
KSI_LOG_FN(fatal, FATAL);

static int KSI_LOG_log(KSI_CTX *ctx, int level, char *format, ...) {
	int res;
	va_list va;
	va_start(va, format);
	res = writeLog(ctx, level, format, va); \
	va_end(va);
	return res;
}


int KSI_Logger_new(KSI_CTX *ctx, char *fileName, int logLevel, KSI_Logger **logger) {
	KSI_ERR err;
	KSI_Logger *tmp = NULL;

	FILE *f = NULL;
	char *logFileName = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, logger != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (logLevel < KSI_LOG_NONE || logLevel > KSI_LOG_DEBUG) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_Logger);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	if (fileName != NULL) {
		f = fopen(fileName, "a");
		if (f == NULL) {
			KSI_FAIL(&err, KSI_IO_ERROR, "Unable to open log file for append.");
			goto cleanup;
		}
	}

	/* Copy log file name */
	if (fileName != NULL) {
		logFileName = KSI_calloc(strlen(fileName) + 1, 1);
		if (logFileName == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}
		strncpy(logFileName, fileName, strlen(fileName));
	}

	/* Update the context */
	tmp->ctx = ctx;

	tmp->logFile = logFileName;
	logFileName = NULL;
	tmp->logStream = (f != NULL ? f : stdout);
	f = NULL;

	tmp->logLevel = logLevel;

	*logger = tmp;
	tmp = NULL;

	KSI_ERR_success(&err);

cleanup:

	KSI_Logger_free(tmp);
	KSI_free(logFileName);
	if (f != NULL) fclose(f);

	return KSI_ERR_apply(&err);
}

void KSI_Logger_free(KSI_Logger *logger) {
	if (logger != NULL) {
		if (logger->logFile != NULL && logger->logStream != NULL) {
			fclose(logger->logStream);
		}

		KSI_free(logger->logFile);
		KSI_free(logger);
	}
}

int KSI_LOG_logBlob(KSI_CTX *ctx, int level, const char *prefix, const unsigned char *data, int data_len) {
	int res = KSI_UNKNOWN_ERROR;
	char *logStr = NULL;
	int logStr_size = 0;
	int logStr_len = 0;
	int i;
	KSI_Logger *logger = NULL;

	res = KSI_getLogger(ctx, &logger);
	if (res != KSI_OK) {
		goto cleanup;
	}

	if (logger == NULL || level < logger->logLevel) goto cleanup;

	logStr_size = data_len * 2 + 1;

	logStr = KSI_calloc(logStr_size, 1);
	if (logStr == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	for (i = 0; i < data_len; i++) {
		logStr_len += snprintf(logStr + logStr_len, logStr_size - logStr_len, "%02x", data[i]);
	}

	res = KSI_LOG_log(ctx, level, "%s (len = %d): %s", prefix, data_len, logStr);

cleanup:

	KSI_free(logStr);

	return res;
}

int KSI_LOG_logTlv(KSI_CTX *ctx, int level, const char *prefix, KSI_TLV *tlv) {
	int res = KSI_UNKNOWN_ERROR;
	char *serialized = NULL;
	KSI_Logger *logger = NULL;

	res = KSI_getLogger(ctx, &logger);
	if (res != KSI_OK) goto cleanup;

	if (logger == NULL || level < logger->logLevel) {
		res = KSI_OK;
		goto cleanup;
	}

	if (tlv != NULL) {
		res = KSI_TLV_toString(tlv, &serialized);
		if (res != KSI_OK) goto cleanup;

		res = KSI_LOG_log(ctx, level, "%s:\n%s", prefix, serialized);
	} else {
		res = KSI_LOG_log(ctx, level, "%s:\n%s", prefix, "(null)");
	}

cleanup:

	if (res != KSI_OK) {
		KSI_LOG_log(ctx, level, "%s: Unable to log tlv value - %s", prefix, KSI_getErrorString(res));
	}

	KSI_free(serialized);

	return res;
}

int KSI_LOG_logDataHash(KSI_CTX *ctx, int level, const char *prefix, KSI_DataHash *hsh) {
	int res = KSI_UNKNOWN_ERROR;
	const unsigned char *imprint = NULL;
	int imprint_len = 0;
	KSI_Logger *logger = NULL;

	res = KSI_getLogger(ctx, &logger);
	if (res != KSI_OK) goto cleanup;

	if (logger == NULL || level < logger->logLevel) {
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

int KSI_LOG_setLogLevel(KSI_Logger *logger, int level) {
	int res = KSI_UNKNOWN_ERROR;

	logger->logLevel = level;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_LOG_setLogFile(KSI_Logger *logger, char *file) {
	int res = KSI_UNKNOWN_ERROR;

	if (logger->logStream != NULL) {
		fclose(logger->logStream);
		logger->logStream = NULL;
	}

	if (file != NULL && strlen(file) > 0) {
		logger->logStream = fopen(file, "a");
		if (logger->logStream == NULL) goto cleanup;
	} else {
		logger->logStream = stdout;
	}
	res = KSI_OK;

cleanup:

	return res;
}
