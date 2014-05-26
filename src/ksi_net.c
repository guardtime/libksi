#include <string.h>

#include "ksi_internal.h"

struct KSI_NetHandle_st {
	/** KSI context. */
	KSI_CTX *ctx;
	/** Request destination. */
	unsigned char *request;
	/** Length of the original request. */
	int request_length;
	/** Response for the request. NULL if not yet present. */
	unsigned char *response;
	/** Length of the response. */
	int response_length;

	void (*netCtx_free)(void *);

	int (*readResponse)(KSI_NetHandle *);

	/** Addidtional context for the trasnport layer. */
	void *handleCtx;
};

struct KSI_NetProvider_st {
	KSI_CTX *ctx;

	/** Cleanup for the provider, gets the #providerCtx as parameter. */
	void (*providerCtx_free)(void *);

	int (*sendSignRequest)(KSI_NetProvider *, KSI_NetHandle *);
	int (*sendExtendRequest)(KSI_NetProvider *, KSI_NetHandle *);
	int (*sendPublicationRequest)(KSI_NetProvider *, KSI_NetHandle *);

	/** Dedicated context for the net provider */
	void *poviderCtx;
};

KSI_IMPLEMENT_GET_CTX(KSI_NetProvider);
KSI_IMPLEMENT_GET_CTX(KSI_NetHandle);

/**
 *
 */
int KSI_NetHandle_new(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle) {
	KSI_ERR err;
	KSI_NetHandle *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_NetHandle);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->handleCtx = NULL;
	tmp->request = NULL;
	tmp->request_length = 0;
	if (request != NULL && request_length > 0) {
		tmp->request = KSI_calloc(request_length, 1);
		if (tmp->request == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}
		memcpy(tmp->request, request, request_length);
		tmp->request_length = request_length;
	}

	tmp->response = NULL;
	tmp->response_length = 0;

	*handle = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetHandle_free(tmp);

	return KSI_RETURN(&err);
}

void *KSI_NetHandle_getNetContext(KSI_NetHandle *handle) {
	return handle->handleCtx;
}

/**
 *
 */
void KSI_NetHandle_free(KSI_NetHandle *handle) {
	if (handle != NULL) {
		if (handle->netCtx_free != NULL) {
			handle->netCtx_free(handle->handleCtx);
		}
		KSI_free(handle->request);
		KSI_free(handle->response);
		KSI_free(handle);
	}
}

int KSI_NetProvider_sendSignRequest(KSI_NetProvider *provider, KSI_NetHandle *handle) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(provider->ctx, &err);

	if (provider->sendSignRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Signed request sender not initialized.");
		goto cleanup;
	}
	res = provider->sendSignRequest(provider, handle);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetProvider_sendExtendRequest(KSI_NetProvider *provider, KSI_NetHandle *handle) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(provider->ctx, &err);

	if (provider->sendExtendRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Extend request sender not initialized.");
		goto cleanup;
	}
	res = provider->sendExtendRequest(provider, handle);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetProvider_sendPublicationsFileRequest(KSI_NetProvider *provider, KSI_NetHandle *handle) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(provider->ctx, &err);

	if (provider->sendPublicationRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Publications file request sender not initialized.");
		goto cleanup;
	}
	res = provider->sendPublicationRequest(provider, handle);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

void KSI_NetProvider_free(KSI_NetProvider *provider) {
	if (provider != NULL) {
		if (provider->providerCtx_free != NULL) {
			provider->providerCtx_free(provider->poviderCtx);
		}
		KSI_free(provider);
	}
}

int KSI_NetHandle_setResponse(KSI_NetHandle *handle, const unsigned char *response, int response_len) {
	KSI_ERR err;
	unsigned char *resp = NULL;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	resp = KSI_calloc(response_len, 1);
	if (resp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	memcpy(resp, response, response_len);

	if (handle->response != NULL) {
		KSI_free(handle->response);
	}
	handle->response = resp;
	handle->response_length = response_len;

	resp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(resp);

	return KSI_RETURN(&err);
}

int KSI_NetHandle_setNetContext(KSI_NetHandle *handle, void *netCtx, void (*netCtx_free)(void *)) {
	KSI_ERR err;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	if (handle->handleCtx != netCtx && handle->handleCtx != NULL && handle->netCtx_free != NULL) {
		handle->netCtx_free(handle->handleCtx);
	}
	handle->handleCtx = netCtx;
	handle->netCtx_free = netCtx_free;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

void *KSI_NetProvider_getNetContext(KSI_NetProvider *provider) {
	return provider->poviderCtx;
}

int KSI_NetHandle_setReadResponseFn(KSI_NetHandle *handle, int fn(KSI_NetHandle *)) {
	KSI_ERR err;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	handle->readResponse = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetHandle_getRequest(KSI_NetHandle *handle, const unsigned char **response, int *response_len) {
	KSI_ERR err;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	*response = handle->request;
	*response_len = handle->request_length;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetHandle_receive(KSI_NetHandle *handle) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(KSI_NetHandle_getCtx(handle), &err);

	if (handle->readResponse == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, NULL);
		goto cleanup;
	}

	res = handle->readResponse(handle);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetHandle_getResponse(KSI_NetHandle *handle, const unsigned char **response, int *response_len) {
	KSI_ERR err;
	int res;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	KSI_PRE(&err, handle != NULL);
	KSI_BEGIN(handle->ctx, &err);

	*response = handle->response;
	*response_len = handle->response_length;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetProvider_new(KSI_CTX *ctx, KSI_NetProvider **provider) {
	KSI_ERR err;
	KSI_NetProvider *pr = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, provider != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	pr = KSI_new(KSI_NetProvider);
	if (pr == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	pr->ctx = ctx;
	pr->poviderCtx = NULL;
	pr->providerCtx_free = NULL;
	pr->sendSignRequest = NULL;
	pr->sendExtendRequest = NULL;
	pr->sendPublicationRequest = NULL;

	*provider = pr;
	pr = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetProvider_free(pr);
	return KSI_RETURN(&err);
}

int KSI_NetProvider_setNetCtx(KSI_NetProvider *provider, void *netCtx, void (*netCtx_free)(void *)) {
	KSI_ERR err;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_BEGIN(provider->ctx, &err);

	if (provider->poviderCtx != NULL && provider->providerCtx_free != NULL) {
		provider->providerCtx_free(provider->poviderCtx);
	}
	provider->poviderCtx = netCtx;
	provider->providerCtx_free = netCtx_free;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetProvider_setSendSignRequestFn(KSI_NetProvider *provider, int (*fn)(KSI_NetProvider *, KSI_NetHandle *)) {
	KSI_ERR err;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_BEGIN(provider->ctx, &err);

	provider->sendSignRequest = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetProvider_setSendExtendRequestFn(KSI_NetProvider *provider, int (*fn)(KSI_NetProvider *, KSI_NetHandle *)) {
	KSI_ERR err;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_BEGIN(provider->ctx, &err);

	provider->sendExtendRequest = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetProvider_setSendPublicationRequestFn(KSI_NetProvider *provider, int (*fn)(KSI_NetProvider *, KSI_NetHandle *)) {
	KSI_ERR err;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_BEGIN(provider->ctx, &err);

	provider->sendPublicationRequest = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}
