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
		case KSI_INVALID_FORMAT:
			return "Invalid format";
		case KSI_UNTRUSTED_HASH_ALGORITHM:
			return "The hash algorithm is not trusted";
		case KSI_UNAVAILABLE_HASH_ALGORITHM:
			return "The hash algorith is not implemented or unavailable";
		case KSI_BUFFER_OVERFLOW:
			return "Buffer overflow";
		case KSI_TLV_PAYLOAD_TYPE_MISMATCH:
			return "TLV payload type mismatch";
		case KSI_OUT_OF_MEMORY:
			return "Out of memory";
		case KSI_IO_ERROR:
			return "I/O error";
		case KSI_NETWORK_ERROR:
			return "Network error";
		case KSI_HTTP_ERROR:
			return "HTTP error";
		case KSI_CRYPTO_FAILURE:
			return "Crypto failure";
		case KSI_UNKNOWN_ERROR:
			return "Unknown internal error";
		default:
			return "Unknown status code";
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
	KSI_LOG_init(ctx, NULL, KSI_LOG_DEBUG);

	/* Initialize curl as the net handle. */
	res = KSI_NET_CURL(ctx);
	if (res != KSI_OK) goto cleanup;

	/* Initialize config */
	/* TODO: Perhaps this should come from some external config file */
	ctx->conf.net.connectTimeoutSeconds = 5;
	ctx->conf.net.readTimeoutSeconds = 10;
	ctx->conf.net.urlSigner = "http://localhost:3333/";
	ctx->conf.net.agent = "KSI-C-API";

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

		if (context->netProvider.poviderCtx != NULL && context->netProvider.providerCleanup != NULL) {
			context->netProvider.providerCleanup(context->netProvider.poviderCtx);
		}

		KSI_free(context);
	}
}

/**
 *
 */
int KSI_global_init(void) {
	int res = KSI_UNKNOWN_ERROR;

	res = KSI_NET_global_init();
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

/**
 *
 */
void KSI_global_cleanup(void) {
	KSI_NET_global_cleanup();
}
