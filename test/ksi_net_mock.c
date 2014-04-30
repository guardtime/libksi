#include <string.h>

#include "../src/ksi_internal.h"

const unsigned char *KSI_NET_MOCK_request = NULL;
int KSI_NET_MOCK_request_len;
const unsigned char *KSI_NET_MOCK_response = NULL;
int KSI_NET_MOCK_response_len;

static int mockReceive(KSI_NetHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;

	if (handle == NULL) goto cleanup;

	KSI_LOG_debug(KSI_NetHandle_getCtx(handle), "Connecting to MOCK service");

	res = KSI_NetHandle_setResponse(handle, KSI_NET_MOCK_response, KSI_NET_MOCK_response_len);
	if (res != KSI_OK) goto cleanup;

cleanup:

		return res;
}

static int mockSend(KSI_NetHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	const unsigned char *req = NULL;
	int req_len;

	KSI_LOG_debug(KSI_NetHandle_getCtx(handle), "Initiate MOCK request.");

	res = KSI_NetHandle_setReadResponseFn(handle, mockReceive);
	if (res != KSI_OK) goto cleanup;

	res = KSI_NetHandle_getRequest(handle, &req, &req_len);
	if (res != KSI_OK) goto cleanup;

	if (KSI_NET_MOCK_request != NULL) KSI_free((unsigned char *)KSI_NET_MOCK_request);

	KSI_NET_MOCK_request = KSI_calloc(req_len, 1);
	memcpy((unsigned char *)KSI_NET_MOCK_request, req, req_len);

	KSI_NET_MOCK_request_len = req_len;
	res = KSI_OK;
cleanup:

	return res;
}

static int mockSendSignRequest(KSI_NetProvider *netProvider, KSI_NetHandle *handle) {
	return mockSend(handle);
}

static int mockSendExtendRequest(KSI_NetProvider *netProvider, KSI_NetHandle *handle) {
	return mockSend(handle);
}

int KSI_NET_MOCK_new(KSI_CTX *ctx, KSI_NetProvider **provider) {
	KSI_ERR err;
	int res;
	KSI_NetProvider *pr = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	KSI_NET_MOCK_request_len = 0;
	KSI_NET_MOCK_response_len = 0;

	res = KSI_NetProvider_new(ctx, &pr);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_setSendSignRequestFn(pr, mockSendSignRequest);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_setSendExtendRequestFn(pr, mockSendExtendRequest);
	KSI_CATCH(&err, res) goto cleanup;

	*provider = pr;
	pr = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(pr);

	return KSI_RETURN(&err);
}
