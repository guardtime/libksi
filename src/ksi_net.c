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
	tmp->handleCtx = NULL;
	tmp->request = NULL;
	tmp->request_length = 0;
	tmp->response = NULL;
	tmp->response_length = 0;

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
			handle->netCtx_free(handle->handleCtx);
		}
		KSI_free(handle->request);
		KSI_free(handle->response);
		KSI_free(handle);
	}
}

int KSI_NET_sendSignRequest(KSI_NetProvider *netProvider, const unsigned char *request, int request_length, KSI_NetHandle **handle) {
	KSI_ERR err;
	KSI_NetHandle *hndl = NULL;
	int res;

	KSI_PRE(&err, netProvider != NULL) goto cleanup;
	KSI_BEGIN(netProvider->ctx, &err);

	res = KSI_NetHandle_new(netProvider->ctx, &hndl);
	KSI_CATCH(&err, res) goto cleanup;

	hndl->request = KSI_calloc(request_length, 1);
	if (hndl->request == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	memcpy(hndl->request, request, request_length);
	hndl->request_length = request_length;

	res = netProvider->sendSignRequest(netProvider, hndl);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = hndl;
	hndl = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetHandle_free(hndl);

	return KSI_RETURN(&err);
}


int KSI_NET_getResponse(KSI_NetHandle *handle, unsigned char **response, int *response_length, int copy) {
	KSI_ERR err;
	unsigned char *tmp = NULL;
	int res;

	KSI_PRE(&err, handle != NULL);
	KSI_BEGIN(handle->ctx, &err);

	if (handle->readResponse == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, NULL);
		goto cleanup;
	}
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

void KSI_NetProvider_free(KSI_NetProvider *provider) {
	if (provider != NULL) {
		if (provider->providerCtx_free != NULL) {
			provider->providerCtx_free(provider->poviderCtx);
		}
		KSI_free(provider);
	}
}

int KSI_NET_extractPDU(KSI_CTX *ctx, unsigned char *data, int data_len, unsigned char **payload, int *payload_length) {
	KSI_ERR err;
	KSI_TLV *pdu = NULL;
	int res;
	unsigned char *pl = NULL;
	int pl_len;

	/* Parse the PDU */
	res = KSI_TLV_parseBlob(ctx, data, data_len, &pdu);
	KSI_CATCH(&err, res) goto cleanup;

	/* Assert PDU tag */
	if (KSI_TLV_getTag(pdu) != KSI_TLV_TAG_PDU_AGGREGATION) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	/* Extract the contents */
	res = KSI_TLV_getRawValue(pdu, &pl, &pl_len, 1);
	KSI_CATCH(&err, res) goto cleanup;

	*payload = pl;
	*payload_length = pl_len;

	pl = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(pl);

	return KSI_RETURN(&err);
}


