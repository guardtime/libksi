#include <stdlib.h>
#include <string.h>

#include "ksi_internal.h"


#define KSI_ERR_STACK_LEN 16

const char *KSI_getErrorString(int statusCode) {
	switch (statusCode) {
		case KSI_OK:
			return "No errors";
		case KSI_INVALID_ARGUMENT:
			return "Invalid argument";
		case KSI_OUT_OF_MEMORY:
			return "Out of memory";
		case KSI_IO_ERROR:
			return "I/O error";
		default:
			return "Unknown error";
	}
}

int KSI_CTX_new(KSI_CTX **context) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *ctx = NULL;

	ctx = KSI_new(KSI_CTX);
	if (ctx == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* Init error stack */
	ctx->errors_size = KSI_ERR_STACK_LEN;
	ctx->errors = KSI_malloc(sizeof(KSI_ERR) * ctx->errors_size);
	if (ctx->errors == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	ctx->errors_count = 0;

	KSI_ERR_clearErrors(ctx);
	KSI_LOG_init(ctx, NULL, KSI_LOG_NONE);


	*context = ctx;
	ctx = NULL;


	res = KSI_OK;

cleanup:

	KSI_CTX_free(ctx);

	return res;
}

/**
 *
 */
void KSI_CTX_free(KSI_CTX *context) {
	if (context != NULL) {
		KSI_free(context->errors);

		if (context->logStream) fclose(context->logStream);
		KSI_free(context->logFile);

		KSI_free(context);
	}
}
