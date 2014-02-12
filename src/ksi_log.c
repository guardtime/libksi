#include <stdarg.h>
#include <string.h>

#include "ksi_internal.h"

static const char *level2str(int level) {
	switch (level) {
		case KSI_LOG_DEBUG: return "DEBUG";
		case KSI_LOG_WARN: return "WARN";
		case KSI_LOG_INFO: return "INFO";
		case KSI_LOG_ERROR: return "ERROR";
		case KSI_LOG_FATAL: return "FATAL";
		default: return "UNKNOWN LOG LEVEL";
	}
}

static int writeLog(KSI_CTX *ctx, int logLevel, char *format, va_list va) {
	KSI_ERR err;
	/* Do not call #KSI_begin. */
	KSI_ERR_init(ctx, &err);

	if (ctx == NULL || format == NULL) {
		KSI_ERR_fail(&err, KSI_INVALID_ARGUMENT, 0, __FILE__, __LINE__, NULL);
		goto cleanup;
	}

	if (ctx->logLevel < logLevel) {
		/* Do not perform logging.
		 * NB! Do not call macro #KSI_success. */
		KSI_ERR_success(&err);

		goto cleanup;
	}

	if (ctx->logStream != NULL) {
		fprintf(ctx->logStream, "%s: ", level2str(logLevel));
		vfprintf(ctx->logStream, format, va);
		fprintf(ctx->logStream, "\n");
	}

	/* NB! Do not call macro #KSI_success. */
	KSI_ERR_success(&err);

cleanup:

	return KSI_ERR_apply(&err);
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

KSI_LOG_FN(debug, DEBUG);
KSI_LOG_FN(warn, WARN);
KSI_LOG_FN(info, INFO);
KSI_LOG_FN(error, ERROR);
KSI_LOG_FN(fatal, FATAL);


static int closeLogFile(KSI_CTX *ctx) {
	KSI_ERR err;
	KSI_ERR_init(ctx, &err);

	if (ctx->logFile != NULL) {
		if (!fclose(ctx->logStream)) {
			KSI_ERR_fail(&err, KSI_IO_ERROR, 0, __FILE__, __LINE__, NULL);
			goto cleanup;
		}

		KSI_free(ctx->logFile);
		ctx->logFile = NULL;
	}
	ctx->logStream = NULL;

	KSI_ERR_success(&err);

cleanup:
	return KSI_ERR_apply(&err);
}

int KSI_LOG_init(KSI_CTX *ctx, char *fileName, int logLevel) {
	KSI_ERR err;
	int res;

	FILE *f = NULL;
	char *logFileName = NULL;

	KSI_ERR_init(ctx, &err);

	if (logLevel < KSI_LOG_NONE || logLevel > KSI_LOG_DEBUG) {
		KSI_ERR_fail(&err, KSI_INVALID_ARGUMENT, 0, __FILE__, __LINE__, NULL);
		goto cleanup;
	}

	if (fileName == NULL || !strcmp("-", fileName)) {
		f = stdout;
	} else {
		f = fopen(fileName, "a");
		if (f == NULL) {
			KSI_ERR_fail(&err, KSI_IO_ERROR, 0, __FILE__, __LINE__, "Unable to open log file for append.");
			goto cleanup;
		}
	}

	/* Close the log file */
	res = closeLogFile(ctx);
	if (res != KSI_OK) goto cleanup;

	/* Copy log file name */
	if (f != stdout) {
		logFileName = KSI_calloc(strlen(fileName) + 1, 1);
		if (logFileName == NULL) {
			KSI_ERR_fail(&err, KSI_OUT_OF_MEMORY, 0, __FILE__, __LINE__, NULL);
			goto cleanup;
		}
		strcpy(logFileName, fileName);
	}

	/* Update the context */
	ctx->logFile = logFileName;
	logFileName = NULL;

	ctx->logStream = f;
	f = NULL;

	ctx->logLevel = logLevel;

	KSI_ERR_success(&err);

cleanup:
	KSI_free(logFileName);
	if (f != NULL && f != stdout) fclose(f);

	return KSI_ERR_apply(&err);
}
