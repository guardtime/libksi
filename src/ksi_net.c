#include <string.h>

#include "ksi_internal.h"
#include "ksi_net.h"

/**
 *
 */
static int KSI_NetHandle_new(KSI_CTX *ctx, KSI_NetHandle **handle) {
	KSI_ERR err;
	KSI_NetHandle *tmp = NULL;

	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_NetHandle);
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

	KSI_NetHandle_free(tmp);

	return KSI_RETURN(&err);
}

/**
 *
 */
void KSI_NetHandle_free(KSI_NetHandle *handle) {
	if (handle != NULL) {
		if (handle->netCtx_free != NULL) {
			handle->netCtx_free(handle->netCtx);
		}
		KSI_free(handle->request);
		KSI_free(handle->response);
		KSI_free(handle->url);
		KSI_free(handle);
	}
}

/**
 *
 */
int KSI_NET_sendRequest(KSI_CTX *ctx, const char *url, const unsigned char *request, int request_length, KSI_NetHandle **handle) {
	KSI_ERR err;
	KSI_NetHandle *tmp = NULL;
	int res;
	int len;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, url != NULL) goto cleanup;
	KSI_PRE(&err, request != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	/* Create handle */
	res = KSI_NetHandle_new(ctx, &tmp);
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

	KSI_NetHandle_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_NET_getResponse(KSI_NetHandle *handle, unsigned char **response, int *response_length, int copy) {
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

void KSI_NetProvider_free(KSI_CTX *ctx) {
	if (ctx->netProvider.providerCleanup != NULL) {
		ctx->netProvider.providerCleanup(ctx->netProvider.poviderCtx);
	}
}

int KSI_NET_extractPDU(KSI_CTX *ctx, unsigned char *data, int data_len, unsigned char **payload, int *payload_length) {
	KSI_ERR err;
	int res;
	KSI_TLV *pdu = NULL;

	/* Parse the PDU */
	res = KSI_TLV_parseBlob(ctx, data, data_len, &pdu);

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}


