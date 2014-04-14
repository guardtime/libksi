#include <stdlib.h>
#include <string.h>

#include "ksi_internal.h"

#define KSI_ERR_STACK_LEN 16

struct KSI_Integer_st {
	KSI_CTX *ctx;
	KSI_uint64_t value;
};

void KSI_Integer_free(KSI_Integer *kint) {
	if (kint != NULL) {
		KSI_free(kint);
	}
}

int KSI_Integer_getSize(KSI_Integer *kint, int *size) {
	KSI_ERR err;
	KSI_PRE(&err, kint != NULL) goto cleanup;
	KSI_BEGIN(kint->ctx, &err);

	*size = KSI_UINT64_MINSIZE(kint->value);

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

KSI_uint64_t KSI_Integer_getUInt64(KSI_Integer *kint) {
	return kint != NULL ? kint->value : 0;
}

int KSI_Integer_equals(KSI_Integer *a, KSI_Integer *b) {
	return a != NULL && b != NULL && (a == b || a->value == b->value);
}

int KSI_Integer_equalsUInt(KSI_Integer *o, KSI_uint64_t i) {
	return o != NULL && o->value == i;
}

int KSI_Integer_new(KSI_CTX *ctx, KSI_uint64_t value, KSI_Integer **kint) {
	KSI_ERR err;
	KSI_Integer *tmp = NULL;

	KSI_PRE(&err, ctx != NULL);
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_Integer);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->value = value;

	*kint = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Integer_free(tmp);

	return KSI_RETURN(&err);
}

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
	res = KSI_NET_CURL_new(ctx, &netProvider);
	if (res != KSI_OK) goto cleanup;

	/* Configure curl net provider */
	if ((res = KSI_NET_CURL_setSignerUrl(netProvider, "http://localhost:3333/signer")) != KSI_OK) goto cleanup;
	if ((res = KSI_NET_CURL_setExtenderUrl(netProvider, "TODO")) != KSI_OK) goto cleanup;
	if ((res = KSI_NET_CURL_setPublicationUrl(netProvider, "TODO")) != KSI_OK) goto cleanup;
	if ((res = KSI_NET_CURL_setConnectTimeoutSeconds(netProvider, 5)) != KSI_OK) goto cleanup;
	if ((res = KSI_NET_CURL_setReadTimeoutSeconds(netProvider, 5)) != KSI_OK) goto cleanup;

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
	int res = KSI_UNKNOWN_ERROR;

	KSI_NetProvider_free(ctx->netProvider);
	ctx->netProvider = netProvider;

	res = KSI_OK;

cleanup:

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

		KSI_NetProvider_free(context->netProvider);

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
