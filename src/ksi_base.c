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
		case KSI_ASYNC_NOT_FINISHED:
			return "Asynchronous call not yet finished.";
		case KSI_INVALID_SIGNATURE:
			return "Invalid KSI signature.";
		case KSI_INVALID_PKI_SIGNATURE:
			return "Invalid PKI signature.";
		case KSI_OUT_OF_MEMORY:
			return "Out of memory";
		case KSI_IO_ERROR:
			return "I/O error";
		case KSI_NETWORK_ERROR:
			return "Network error";
		case KSI_HTTP_ERROR:
			return "HTTP error";
		case KSI_AGGREGATOR_ERROR:
			return "Failure from aggregator.";
		case KSI_EXTENDER_ERROR:
			return "Failure from extender.";
		case KSI_EXTEND_WRONG_CAL_CHAIN:
			return "The given calendar chain is not a continuation of the signature calendar chain.";
		case KSI_CRYPTO_FAILURE:
			return "Cryptographic failure";
		case KSI_UNKNOWN_ERROR:
			return "Unknown internal error";
		default:
			return "Unknown status code";
	}
}

int KSI_CTX_new(KSI_CTX **context) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *ctx = NULL;
	KSI_NetProvider *netProvider = NULL;

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
	res = KSI_CurlNetProvider_new(ctx, &netProvider);
	if (res != KSI_OK) goto cleanup;

	/* Configure curl net provider */
	if ((res = KSI_CurlNetProvider_setSignerUrl(netProvider, "192.168.1.36:3333" /*"http://192.168.1.36:3333/signer"*/)) != KSI_OK) goto cleanup;
	if ((res = KSI_CurlNetProvider_setExtenderUrl(netProvider, "192.168.1.36:8010/gt-extendingservice")) != KSI_OK) goto cleanup;
	if ((res = KSI_CurlNetProvider_setPublicationUrl(netProvider, "TODO")) != KSI_OK) goto cleanup;
	if ((res = KSI_CurlNetProvider_setConnectTimeoutSeconds(netProvider, 5)) != KSI_OK) goto cleanup;
	if ((res = KSI_CurlNetProvider_setReadTimeoutSeconds(netProvider, 5)) != KSI_OK) goto cleanup;

	res = KSI_CTX_setNetworkProvider(ctx, netProvider);
	if (res != KSI_OK) goto cleanup;
	netProvider = NULL;

	*context = ctx;
	ctx = NULL;

	res = KSI_OK;

cleanup:

	KSI_CTX_free(ctx);

	return res;
}
int KSI_CTX_setNetworkProvider(KSI_CTX *ctx, KSI_NetProvider *netProvider) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	KSI_NetProvider_free(ctx->netProvider);
	ctx->netProvider = netProvider;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
void KSI_CTX_free(KSI_CTX *context) {
	if (context != NULL) {
		KSI_free(context->errors);

		if (context->logStream) fclose(context->logStream);
		KSI_free(context->logFile);

		KSI_NetProvider_free(context->netProvider);

		KSI_free(context);
	}
}

/**
 *
 */
int KSI_global_init(void) {
	int res = KSI_UNKNOWN_ERROR;

	res = KSI_CurlNetProvider_global_init();
	if (res != KSI_OK) goto cleanup;

	res = KSI_PKITruststore_global_init();
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

/**
 *
 */
void KSI_global_cleanup(void) {
	KSI_CurlNetProvider_global_cleanup();
// TODO	KSI_PKITruststore_global_cleanup()
}

int KSI_sendSignRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle) {
	KSI_ERR err;
	KSI_NetHandle *hndl = NULL;
	int res;
	KSI_NetProvider *netProvider = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, request != NULL) goto cleanup;
	KSI_PRE(&err, request_length > 0) goto cleanup;

	KSI_BEGIN(ctx, &err);

	netProvider = ctx->netProvider;

	res = KSI_NetHandle_new(ctx, request, request_length, &hndl);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_sendSignRequest(netProvider, hndl);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = hndl;
	hndl = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetHandle_free(hndl);

	return KSI_RETURN(&err);
}

int KSI_sendExtendRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle) {
	KSI_ERR err;
	KSI_NetHandle *hndl = NULL;
	int res;
	KSI_NetProvider *netProvider = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, request != NULL) goto cleanup;
	KSI_PRE(&err, request_length > 0) goto cleanup;

	KSI_BEGIN(ctx, &err);

	netProvider = ctx->netProvider;

	res = KSI_NetHandle_new(ctx, request, request_length, &hndl);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_sendExtendRequest(netProvider, hndl);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = hndl;
	hndl = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetHandle_free(hndl);

	return KSI_RETURN(&err);
}
