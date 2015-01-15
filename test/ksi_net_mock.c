#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <ksi/ksi.h>

#include "all_tests.h"
#include "ksi_net_mock.h"
#include "../src/ksi/net_http_impl.h"

extern KSI_CTX *ctx;

unsigned char *KSI_NET_MOCK_request = NULL;
unsigned KSI_NET_MOCK_request_len = 0;
unsigned char *KSI_NET_MOCK_response = NULL;
unsigned KSI_NET_MOCK_response_len = 0;

static size_t mockInitCount = 0;

static int mockPublicationsFileReceive(KSI_RequestHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	FILE *f = NULL;
	unsigned char *raw = NULL;
	unsigned len;
	long unsigned int raw_size = 0;
	
	if (handle == NULL) goto cleanup;

	KSI_LOG_debug(ctx, "Connecting to MOCK publications file service");
	
	f = fopen(getFullResourcePath("resource/tlv/publications.tlv"), "rb");
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

	raw = KSI_calloc((unsigned)raw_size, 1);
	if (raw == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	len = (unsigned)fread(raw, 1, (unsigned)raw_size, f);
	if (len != raw_size) {
		res = KSI_IO_ERROR;
		goto cleanup;
	}


	res = KSI_RequestHandle_setResponse(handle, raw, len);
	if (res != KSI_OK) goto cleanup;

cleanup:
		KSI_free(raw);
		if (f != NULL) fclose(f);

		return res;
}



static int mockReceive(KSI_RequestHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;

	if (handle == NULL) goto cleanup;

	KSI_LOG_debug(ctx, "Connecting to MOCK service");

	res = KSI_RequestHandle_setResponse(handle, KSI_NET_MOCK_response, KSI_NET_MOCK_response_len);
	if (res != KSI_OK) goto cleanup;

cleanup:

		return res;
}

static int sendRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *url) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_LOG_debug(ctx, "Initiate MOCK request.");

	handle->readResponse = mockReceive;
	handle->client = client;

	memcpy((unsigned char *)KSI_NET_MOCK_request, handle->request, handle->request_length);

	KSI_NET_MOCK_request_len = handle->request_length;
	res = KSI_OK;

	return res;
}

static int mockInit(void) {
	if (mockInitCount++ > 0) return KSI_OK;

	KSI_NET_MOCK_response = KSI_calloc(MOCK_BUFFER_SIZE, 1);
	if (KSI_NET_MOCK_response == NULL) return KSI_OUT_OF_MEMORY;

	KSI_NET_MOCK_request = KSI_calloc(MOCK_BUFFER_SIZE, 1);
	if (KSI_NET_MOCK_request == NULL) return KSI_OUT_OF_MEMORY;

	return KSI_OK;
}

static void mockCleanup(void) {
	if (--mockInitCount > 0) return;
	KSI_free(KSI_NET_MOCK_response);
	KSI_free(KSI_NET_MOCK_request);
}

static int mockSendPublicationsFileRequest(KSI_NetworkClient *netProvider, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RequestHandle *tmp = NULL;

	KSI_LOG_debug(ctx, "Initiate MOCK request.");

	res = KSI_RequestHandle_new(ctx, NULL, 0, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_RequestHandle_setReadResponseFn(tmp, mockPublicationsFileReceive);
	if (res != KSI_OK) goto cleanup;

	KSI_NET_MOCK_request_len = 0;
	*handle = tmp;

	res = KSI_OK;
cleanup:

	return res;
}

int KSI_NET_MOCK_new(KSI_CTX *ctx, KSI_NetworkClient **client) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HttpClient *http = NULL;

	if (ctx == NULL || client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_HttpClient_new(ctx, &http);
	if (res != KSI_OK) goto cleanup;

	res = KSI_HttpClient_setAggregator(http, "mock-aggregator", "anon", "anon");
	if (res != KSI_OK) goto cleanup;

	res = KSI_HttpClient_setExtender(http, "mock-extender", "anon", "anon");
	if (res != KSI_OK) goto cleanup;

	http->sendRequest = sendRequest;

	res = KSI_CTX_registerGlobals(ctx, mockInit, mockCleanup);
	if (res != KSI_OK) goto cleanup;

	http->parent.sendPublicationRequest = mockSendPublicationsFileRequest;

	*client = (KSI_NetworkClient *)http;
	http = NULL;

	res = KSI_OK;

cleanup:

	KSI_HttpClient_free(http);

	return res;
}
