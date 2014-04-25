#include <string.h>

#include "ksi_internal.h"

int KSI_ERR_init(KSI_CTX *ctx, KSI_ERR *err) {
	err->ctx = ctx;

	KSI_ERR_fail(err, KSI_UNKNOWN_ERROR, 0, "null", 0, "Internal error: Probably a function returned without a distinctive success or error.");

	return KSI_OK;
}

int KSI_ERR_apply(KSI_ERR *err) {
	KSI_CTX *ctx = err->ctx;
	KSI_ERR *ctxErr = NULL;

	if (ctx != NULL) {
		if (err->statusCode != KSI_OK) {
			ctxErr = ctx->errors + (ctx->errors_count % ctx->errors_size);



			ctxErr->statusCode = err->statusCode;
			ctxErr->extErrorCode = err->extErrorCode;
			ctxErr->lineNr = err->lineNr;
			strncpy(ctxErr->fileName, KSI_strnvl(err->fileName), sizeof(err->fileName));
			strncpy(ctxErr->message, KSI_strnvl(err->message), sizeof(err->message));

			ctx->errors_count++;
		}

		ctx->statusCode = err->statusCode;
	}
	/* Return the result, which does not indicate the result of this method. */
	return err->statusCode;
}

/**
 *
 */
int KSI_ERR_getStatus(KSI_CTX *context) {
	/* Will fail with segfault if context is null. */
	return context->statusCode;
}

void KSI_ERR_success(KSI_ERR *err) {
	err->statusCode = KSI_OK;
	*err->message = '\0';
}

int KSI_ERR_fail(KSI_ERR *err, int statusCode, long extErrorCode, char *fileName, int lineNr, char *message) {
	err->extErrorCode = extErrorCode;
	err->statusCode = statusCode;
	if (message == NULL) {
		strncpy(err->message, KSI_getErrorString(statusCode), sizeof(err->message));
	} else {
		strncpy(err->message, KSI_strnvl(message), sizeof(err->message));
	}
	strncpy(err->fileName, KSI_strnvl(fileName), sizeof(err->fileName));
	err->lineNr = lineNr;

	return KSI_OK;
}

void KSI_ERR_clearErrors(KSI_CTX *ctx) {
	if (ctx != NULL) {
		ctx->statusCode = KSI_UNKNOWN_ERROR;
		ctx->errors_count = 0;
	}
}

int KSI_ERR_statusDump(KSI_CTX *ctx, FILE *f) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ERR *err = NULL;
	int i;

	fprintf(f, "KSI error trace:\n");
	if (ctx->errors_count == 0) {
		printf("  No errors.\n");
		goto cleanup;
	}

	/* List all errors, starting from the most general. */
	for (i = 0; i < ctx->errors_count && i < ctx->errors_size; i++) {
		err = ctx->errors + ((ctx->errors_count - i - 1) % ctx->errors_size);
		fprintf(f, "  %3u) %s:%u - (%d/%ld) %s\n", ctx->errors_count - i, err->fileName, err->lineNr,err->statusCode, err->extErrorCode, err->message);
	}

	/* If there where more errors than buffers for the errors, indicate the fact */
	if (ctx->errors_count > ctx->errors_size) {
		fprintf(f, "  ... (more errors)\n");
	}

	res = KSI_OK;

cleanup:

	return res;
}
