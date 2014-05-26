#include <limits.h>
#include <string.h>

#include "../src/ksi_internal.h"

const unsigned char *KSI_NET_MOCK_request = NULL;
int KSI_NET_MOCK_request_len;
const unsigned char *KSI_NET_MOCK_response = NULL;
int KSI_NET_MOCK_response_len;

static int mockPublicationsFileReceive(KSI_NetHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	FILE *f = NULL;
	unsigned char *raw = NULL;
	int len;
	long int raw_size = 0;

	if (handle == NULL) goto cleanup;

	KSI_LOG_debug(KSI_NetHandle_getCtx(handle), "Connecting to MOCK publications file service");

	f = fopen("test/resource/tlv/publications-4.tlv", "rb");
	if (f == NULL) {
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	res = fseek(f, 0, SEEK_END);
	if (res != 0) {
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	raw_size = ftell(f);
	if (raw_size < 0) {
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	if (raw_size > INT_MAX) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	res = fseek(f, 0, SEEK_SET);
	if (res != 0) {
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	raw = KSI_calloc(raw_size, 1);
	if (raw == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	len = fread(raw, 1, raw_size, f);
	if (len != raw_size) {
		res = KSI_IO_ERROR;
		goto cleanup;
	}


	res = KSI_NetHandle_setResponse(handle, raw, len);
	if (res != KSI_OK) goto cleanup;

cleanup:
		KSI_free(raw);
		if (f != NULL) fclose(f);

		return res;
}



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

static int mockSendPublicationsFileRequest(KSI_NetProvider *netProvider, KSI_NetHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	const unsigned char *req = NULL;
	int req_len;

	KSI_LOG_debug(KSI_NetHandle_getCtx(handle), "Initiate MOCK request.");

	res = KSI_NetHandle_setReadResponseFn(handle, mockPublicationsFileReceive);
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

	res = KSI_NetProvider_setSendPublicationRequestFn(pr, mockSendPublicationsFileRequest);
	KSI_CATCH(&err, res) goto cleanup;

	*provider = pr;
	pr = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(pr);

	return KSI_RETURN(&err);
}
