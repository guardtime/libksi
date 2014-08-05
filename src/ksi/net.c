#include <string.h>

#include "internal.h"
#include "net_impl.h"

KSI_IMPLEMENT_GET_CTX(KSI_NetworkClient);
KSI_IMPLEMENT_GET_CTX(KSI_RequestHandle);

/**
 *
 */
int KSI_RequestHandle_new(KSI_CTX *ctx, const unsigned char *request, unsigned request_length, KSI_RequestHandle **handle) {
	KSI_ERR err;
	KSI_RequestHandle *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_RequestHandle);
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

	KSI_RequestHandle_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_RequestHandle_getNetContext(KSI_RequestHandle *handle, void **c) {
	KSI_ERR err;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, c != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	*c = handle->handleCtx;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
void KSI_RequestHandle_free(KSI_RequestHandle *handle) {
	if (handle != NULL) {
		if (handle->handleCtx_free != NULL) {
			handle->handleCtx_free(handle->handleCtx);
		}
		KSI_free(handle->request);
		KSI_free(handle->response);
		KSI_free(handle);
	}
}

int KSI_NetworkClient_sendSignRequest(KSI_NetworkClient *provider, KSI_RequestHandle *handle) {
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

int KSI_NetworkClient_sendExtendRequest(KSI_NetworkClient *provider, KSI_RequestHandle *handle) {
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

int KSI_NetworkClient_sendPublicationsFileRequest(KSI_NetworkClient *provider, KSI_RequestHandle *handle) {
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

void KSI_NetworkClient_free(KSI_NetworkClient *provider) {
	if (provider != NULL) {
		if (provider->providerCtx_free != NULL) {
			provider->providerCtx_free(provider->poviderCtx);
		}
		KSI_free(provider);
	}
}

int KSI_RequestHandle_setResponse(KSI_RequestHandle *handle, const unsigned char *response, unsigned response_len) {
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

int KSI_RequestHandle_setNetContext(KSI_RequestHandle *handle, void *netCtx, void (*netCtx_free)(void *)) {
	KSI_ERR err;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	if (handle->handleCtx != netCtx && handle->handleCtx != NULL && handle->handleCtx_free != NULL) {
		handle->handleCtx_free(handle->handleCtx);
	}
	handle->handleCtx = netCtx;
	handle->handleCtx_free = netCtx_free;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetworkClient_getNetContext(KSI_NetworkClient *provider, void **netCtx) {
	KSI_ERR err;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_PRE(&err, netCtx != NULL) goto cleanup;
	KSI_BEGIN(provider->ctx, &err);

	*netCtx = provider->poviderCtx;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_RequestHandle_setReadResponseFn(KSI_RequestHandle *handle, int (*fn)(KSI_RequestHandle *)) {
	KSI_ERR err;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	handle->readResponse = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_RequestHandle_getRequest(KSI_RequestHandle *handle, const unsigned char **response, unsigned *response_len) {
	KSI_ERR err;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	*response = handle->request;
	*response_len = handle->request_length;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int receiveResponse(KSI_RequestHandle *handle) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(KSI_RequestHandle_getCtx(handle), &err);

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

int KSI_RequestHandle_getResponse(KSI_RequestHandle *handle, const unsigned char **response, unsigned *response_len) {
	KSI_ERR err;
	int res;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, response != NULL) goto cleanup;
	KSI_PRE(&err, response_len != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	if (handle->response == NULL) {
		KSI_LOG_debug(handle->ctx, "Waiting for response.");
		res = receiveResponse(handle);
		KSI_CATCH(&err, res) goto cleanup;
	}

	*response = handle->response;
	*response_len = handle->response_length;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetworkClient_new(KSI_CTX *ctx, KSI_NetworkClient **provider) {
	KSI_ERR err;
	KSI_NetworkClient *pr = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, provider != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	pr = KSI_new(KSI_NetworkClient);
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

	KSI_NetworkClient_free(pr);
	return KSI_RETURN(&err);
}

int KSI_NetworkClient_setNetCtx(KSI_NetworkClient *provider, void *netCtx, void (*netCtx_free)(void *)) {
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

int KSI_NetworkClient_setSendSignRequestFn(KSI_NetworkClient *provider, int (*fn)(KSI_NetworkClient *, KSI_RequestHandle *)) {
	KSI_ERR err;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_BEGIN(provider->ctx, &err);

	provider->sendSignRequest = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetworkClient_setSendExtendRequestFn(KSI_NetworkClient *provider, int (*fn)(KSI_NetworkClient *, KSI_RequestHandle *)) {
	KSI_ERR err;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_BEGIN(provider->ctx, &err);

	provider->sendExtendRequest = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_NetworkClient_setSendPublicationRequestFn(KSI_NetworkClient *provider, int (*fn)(KSI_NetworkClient *, KSI_RequestHandle *)) {
	KSI_ERR err;

	KSI_PRE(&err, provider != NULL) goto cleanup;
	KSI_BEGIN(provider->ctx, &err);

	provider->sendPublicationRequest = fn;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}
