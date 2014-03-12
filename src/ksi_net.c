#include <string.h>

#include "ksi_internal.h"
#include "ksi_net.h"

/**
 *
 */
static int KSI_NET_Handle_new(KSI_CTX *ctx, KSI_NET_Handle **handle) {
	KSI_ERR err;
	KSI_NET_Handle *tmp = NULL;

	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_NET_Handle);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->netCtx = NULL;
	tmp->request = NULL;
	tmp->request_length = 0;
	tmp->response = NULL;
	tmp->response_length = 0;
	tmp->url = NULL;

	*handle = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NET_Handle_free(tmp);

	return KSI_RETURN(&err);
}

/**
 *
 */
void KSI_NET_Handle_free(KSI_NET_Handle *handle) {
	if (handle != NULL) {
		handle->netCtx_free(handle->netCtx);
		KSI_free(handle->request);
		KSI_free(handle->response);
		KSI_free(handle->url);
		KSI_free(handle);
	}
}

/**
 *
 */
int KSI_Transport_sendRequest(KSI_CTX *ctx, const char *url, const unsigned char *request, int request_length, KSI_NET_Handle **handle) {
	KSI_ERR err;
	KSI_NET_Handle *tmp = NULL;
	int res;
	int len;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, url != NULL) goto cleanup;
	KSI_PRE(&err, request != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	/* Create handle */
	res = KSI_NET_Handle_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	/* Copy url. */
	tmp->url = KSI_calloc(len = strlen(url) + 1, 1);
	if (tmp->url == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	strncpy(tmp->url, url, len);

	/* Copy request */
	tmp->request = KSI_calloc(request_length, 1);
	if (tmp->request == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	memcpy(tmp->request, request, request_length);
	tmp->request_length = request_length;

	res = ctx->netProvider.sendRequest(tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NET_Handle_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_Transport_getResponse(KSI_NET_Handle *handle, unsigned char **response, int *response_length, int copy) {
	KSI_ERR err;
	unsigned char *tmp = NULL;
	int res;

	KSI_PRE(&err, handle != NULL);

	KSI_BEGIN(handle->ctx, &err);

	res = handle->readResponse(handle);

	KSI_CATCH(&err, res) goto cleanup;

	if (copy) {
		tmp = KSI_calloc(handle->response_length, 1);
		if (tmp == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}
		memcpy(tmp, handle->response, handle->response_length);
	} else {
		tmp = handle->response;
	}

	*response = tmp;
	*response_length = handle->response_length;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

void KSI_NET_Provider_free(KSI_CTX *ctx) {
	if (ctx->netProvider.providerCleanup != NULL) {
		ctx->netProvider.providerCleanup(ctx->netProvider.poviderCtx);
	}
}

