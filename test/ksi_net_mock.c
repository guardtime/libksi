#include <string.h>

#include "../src/ksi_internal.h"
#include "../src/ksi_net.h"

unsigned char KSI_NET_MOCK_request[0xfffff];
int KSI_NET_MOCK_request_len;
unsigned char KSI_NET_MOCK_response[0xfffff];
int KSI_NET_MOCK_response_len;

static int mockReceive(KSI_NetHandle *handle) {

	KSI_LOG_debug(handle->ctx, "Connecting to MOCK service");

	handle->response = KSI_calloc(KSI_NET_MOCK_response_len, 1);
	memcpy(handle->response, KSI_NET_MOCK_response, KSI_NET_MOCK_response_len);

	handle->response_length = KSI_NET_MOCK_response_len;

cleanup:

		return KSI_OK;
}

static int mockSend(KSI_NetHandle *handle) {
	handle->netCtx_free = NULL;

	memcpy(KSI_NET_MOCK_request, handle->request, handle->request_length);
	KSI_NET_MOCK_request_len = handle->request_length;

	handle->readResponse = mockReceive;

cleanup:

	return KSI_OK;
}

static int mockSendSignRequest(KSI_NetProvider *netProvider, void *data, int data_len, KSI_NetHandle **handle) {
	return KSI_UNKNOWN_ERROR;
}


int KSI_NET_MOCK_new(KSI_CTX *ctx, KSI_NetProvider **provider) {
	KSI_ERR err;
	KSI_NetProvider *pr = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	KSI_NET_MOCK_request_len = 0;
	KSI_NET_MOCK_response_len = 0;

	pr = KSI_new(KSI_NetProvider);
	if (pr == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	pr->ctx = ctx;
	pr->poviderCtx = NULL;
	pr->providerCtx_free = NULL;
	pr->sendSignRequest = mockSendSignRequest;
	pr->sendExtendRequest = NULL;
	pr->sendPublicationRequest = NULL;

	*provider = pr;
	pr = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(pr);

	return KSI_RETURN(&err);
}
