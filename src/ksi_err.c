#include "ksi_internal.h"

/**
 *
 */
int KSI_ERR_getStatus(KSI_CTX *context) {
	/* Will fail with segfault if context is null. */
	return context->statusCode;
}

int KSI_ERR_isOK(KSI_CTX *ctx) {
	return ctx != NULL && ctx->errors_count == NULL && ctx->statusCode == KSI_OK;
}

int KSI_ERR_success(KSI_CTX *ctx) {
	int res = KSI_UNKNOWN_ERROR;
	if (ctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx->statusCode = KSI_OK;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_ERR_fail(KSI_CTX *ctx, int statusCode, int extErrorCode, char *fileName, int lineNr, char *message) {
	int res = KSI_UNKNOWN_ERROR;
	if (ctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx->statusCode = statusCode;
	/* Get pointer to the top of stack. */
	KSI_ERR *err = ctx->errors + (ctx->errors_count % ctx->errors_size);
	ctx->errors_count++;

	err->statusCode = statusCode;
	err->extErrorCode = extErrorCode;
	strncpy(err->message, KSI_strnvl(message), sizeof(err->message));
	strncpy(err->fileName, KSI_strnvl(fileName), sizeof(err->fileName));
	err->lineNr = lineNr;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_ERR_clearErrors(KSI_CTX *ctx) {
	int res = KSI_UNKNOWN_ERROR;
	if (ctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx->statusCode = KSI_UNKNOWN_ERROR;
	ctx->errors_count = 0;

cleanup:

	return res;
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
		fprintf(f, "  %3d) %s:%d - %s\n", ctx->errors_count - i, err->fileName, err->lineNr, err->message);
	}

	/* If there where more errors than buffers for the errors, indicate the fact */
	if (ctx->errors_count > ctx->errors_size) {
		fprintf(f, "  ... (more errors)\n");
	}

	res = KSI_OK;

cleanup:

	return res;
}
