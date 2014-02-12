#include <string.h>

#include "ksi_internal.h"

void KSI_ERR_init(KSI_CTX *ctx, KSI_ERR *err) {
	err->extErrorCode = 0;
	*err->fileName = '\0';
	*err->message = '\0';
	err->lineNr = -1;
	err->statusCode = KSI_UNKNOWN_ERROR;
	err->ctx = ctx;
}

int KSI_ERR_apply(KSI_ERR *err) {
	KSI_CTX *ctx = err->ctx;
	KSI_ERR *ctxErr = NULL;

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

void KSI_ERR_fail(KSI_ERR *err, int statusCode, int extErrorCode, char *fileName, int lineNr, char *message) {
	err->extErrorCode = extErrorCode;
	err->statusCode = statusCode;
	strncpy(err->message, KSI_strnvl(message), sizeof(err->message));
	strncpy(err->fileName, KSI_strnvl(fileName), sizeof(err->fileName));
	err->lineNr = lineNr;
}

void KSI_ERR_clearErrors(KSI_CTX *ctx) {
	ctx->statusCode = KSI_UNKNOWN_ERROR;
	ctx->errors_count = 0;
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
		err = ctx->errors + (ctx->errors_size - i - 1);
		fprintf(f, "  %3u) %s:%u - (%d/%d) %s\n", ctx->errors_count - i, err->fileName, err->lineNr,err->statusCode, err->extErrorCode, err->message);
	}

	/* If there where more errors than buffers for the errors, indicate the fact */
	if (ctx->errors_count > ctx->errors_size) {
		fprintf(f, "  ... (more errors)\n");
	}

	res = KSI_OK;

cleanup:

	return res;
}
