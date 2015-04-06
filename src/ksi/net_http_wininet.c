/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#include "internal.h"

#if KSI_NET_HTTP_IMPL==KSI_IMPL_WININET

#include <windows.h>
#include <wininet.h>

#include "net_http_impl.h"
#include "net_impl.h"

typedef struct wininetNetHandleCtx_st {
	KSI_CTX *ctx;
	HINTERNET session_handle;
	HINTERNET request_handle;
} wininetNetHandleCtx;


static void wininetNetHandleCtx_free(wininetNetHandleCtx *handleCtx) {
	if (handleCtx != NULL) {
		InternetCloseHandle(handleCtx->session_handle);
		InternetCloseHandle(handleCtx->request_handle);
		KSI_free(handleCtx);
	}
}

static int wininetNetHandleCtx_new(wininetNetHandleCtx **handleCtx){
	wininetNetHandleCtx *nhc = NULL;
	int res = KSI_OK;

	nhc = KSI_new(wininetNetHandleCtx);
	if (nhc == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	nhc->ctx = NULL;
	nhc->session_handle = NULL;
	nhc->request_handle = NULL;

	*handleCtx = nhc;
	nhc = NULL;

cleanup:

	wininetNetHandleCtx_free(nhc);

	return res;
}


#define WININET_ERROR(_ctx, _error, _ksier, _msg) \
		KSI_LOG_error(_ctx, "WinINet returned error %i at line %i in file %s.", _error, __LINE__, __FILE__); \
		KSI_ERR_push(_ctx, res = _ksier, _error, __FILE__, __LINE__, _msg); \
		goto cleanup;

#define WININET_ERROR_1(_ctx, _winer, _ksier, _msg) { \
	DWORD _error = GetLastError(); \
	if(_winer == _error){ \
		WININET_ERROR(_ctx, _error, _ksier, _msg) \
	}

#define WININET_ERROR_m(_ctx, _winer, _ksier, _msg) \
	else if(_winer == _error){ \
		WININET_ERROR(_ctx, _error, _ksier, _msg) \
	}

#define WININET_ERROR_N(_ctx, _ksier, _msg) \
	else{ \
		WININET_ERROR(_ctx, _error, _ksier, _msg) \
	}}

static int winINet_ReadFromHandle(KSI_RequestHandle *reqHandle, unsigned char **buf, DWORD *len){
	int res = KSI_UNKNOWN_ERROR;
	HINTERNET handle;
	KSI_HttpClient *http = NULL;
	DWORD dwordLen;
	DWORD http_payload_len = 0;
	DWORD http_status;
	DWORD tmp_len = 0;
	unsigned char *tmp = NULL;
	KSI_CTX *ctx = NULL;

	if (reqHandle == NULL || buf == NULL || len == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = reqHandle->ctx;
	KSI_ERR_clearErrors(ctx);


	handle = ((wininetNetHandleCtx*)reqHandle->implCtx)->request_handle;
	http = (KSI_HttpClient*)reqHandle->client;

	/*Get HTTP status code*/
	dwordLen = sizeof(DWORD);
	if (!HttpQueryInfo(handle, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &http_status, &dwordLen, 0)) {
		WININET_ERROR_1(ctx, ERROR_INSUFFICIENT_BUFFER, KSI_INVALID_ARGUMENT, "WinINet: Insufficient buffer.")
		WININET_ERROR_m(ctx, ERROR_HTTP_HEADER_NOT_FOUND, KSI_NETWORK_ERROR, "WinINet: HTTP status code header not found.")
		WININET_ERROR_N(ctx, KSI_UNKNOWN_ERROR, "WinINet: Unable to get HTTP status code.")
	}

	http->httpStatus = http_status;

	/*Get the length of the payload*/
	dwordLen = sizeof(DWORD);
	if (!HttpQueryInfo(handle, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &http_payload_len, &dwordLen, 0)){
		WININET_ERROR_1(ctx, ERROR_INSUFFICIENT_BUFFER, KSI_INVALID_ARGUMENT, "WinINet: Insufficient buffer.")
		WININET_ERROR_m(ctx, ERROR_HTTP_HEADER_NOT_FOUND, KSI_NETWORK_ERROR, "WinINet: HTTP content length not found.")
		WININET_ERROR_N(ctx, KSI_UNKNOWN_ERROR, "WinINet: Unable to get HTTP content length.")
	}

	/*Get memory for the HTTP payload*/
	tmp_len = http_payload_len;
	tmp = (unsigned char*)KSI_malloc(tmp_len);
	if (tmp == NULL){
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	/*Read data*/
	if (!InternetReadFile(handle, tmp, tmp_len, &tmp_len)) {
		WININET_ERROR_1(ctx, ERROR_INSUFFICIENT_BUFFER, KSI_INVALID_ARGUMENT, "WinINet: Insufficient buffer.")
		WININET_ERROR_N(ctx, KSI_UNKNOWN_ERROR, "WinINet: HTTP Internet read error.")
	}

	if (tmp_len != http_payload_len){
		KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "WinINet: Unable to read all bytes.");
		goto cleanup;
	}

	*buf = tmp;
	*len = tmp_len;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);

	return res;
}

static int wininetReceive(KSI_RequestHandle *handle) {
	int res;
	KSI_CTX *ctx = NULL;
	wininetNetHandleCtx *wininetHandle = NULL;
	unsigned char *resp = NULL;
	unsigned resp_len = 0;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = KSI_RequestHandle_getCtx(handle);
	KSI_ERR_clearErrors(ctx);


	wininetHandle = handle->implCtx;

	if (!HttpSendRequestA(wininetHandle->request_handle, NULL, 0, (LPVOID) handle->request, handle->request_length)) {
		WININET_ERROR_1(ctx, ERROR_INTERNET_CANNOT_CONNECT, KSI_NETWORK_ERROR, "WinINet: Unable to resolve host.")
		WININET_ERROR_m(ctx, ERROR_INTERNET_NAME_NOT_RESOLVED, KSI_NETWORK_ERROR, "WinINet: HTTP status code header not found.")
		WININET_ERROR_m(ctx, ERROR_INTERNET_TIMEOUT, KSI_NETWORK_SEND_TIMEOUT, NULL)
		WININET_ERROR_N(ctx, KSI_UNKNOWN_ERROR, "WinINet: Unable to send request.")
	}

	res = winINet_ReadFromHandle(handle, &resp, &resp_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_RequestHandle_setResponse(handle, resp, resp_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

    KSI_free(resp);

	return res;
}


/**
 * Prepares request and opens a session handle.
 */
static int wininetSendRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *url) {
	int res;
	KSI_CTX *ctx = NULL;
	wininetNetHandleCtx *wininetHandle = NULL;
	KSI_HttpClient *http = (KSI_HttpClient *)client;
	HINTERNET internetHandle;
	char msg[1024];
	char *scheme = NULL;
	char *hostName = NULL;
	char *query = NULL;
	int port = 0;


	if (client == NULL || handle == NULL || url == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = handle->ctx;
	KSI_ERR_clearErrors(ctx);

	if (http->implCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		KSI_pushError(ctx, res, "Network client http implementation context not set.");
		goto cleanup;
	}

	/*Initializing of wininet helper struct*/
	res = wininetNetHandleCtx_new(&wininetHandle);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	wininetHandle->ctx = ctx;
	internetHandle = http->implCtx;

	res = KSI_UriSplitBasic(url, &scheme, &hostName, &port, &query);
	if(res != KSI_OK){
		KSI_snprintf(msg, sizeof(msg), "WinINet: Unable to crack url '%s'.", url);
		KSI_pushError(ctx, res, msg);
		goto cleanup;
	}

	if(scheme == NULL || strcmp("http", scheme) != 0 && strcmp("https", scheme) != 0){
		KSI_snprintf(msg, sizeof(msg), "WinINet: unknown Internet scheme '%s'.", scheme);
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, msg);
		goto cleanup;
	}

	if(hostName == NULL || query == NULL){
		KSI_snprintf(msg, sizeof(msg), "WinINet: Invalid url '%s'.", url);
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, msg);
		goto cleanup;
	}

	if (handle->request_length > LONG_MAX) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "WinINet: Request too long.");
		goto cleanup;
	}

	KSI_LOG_debug(ctx, "WinINet: Sending request to: %s.", url);
	/*Preparing session handle*/
	//Opens an HTTP session for a given site
	wininetHandle->session_handle = InternetConnectA(internetHandle, hostName, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (wininetHandle->session_handle == NULL) {
		WININET_ERROR(ctx, GetLastError(), KSI_NETWORK_ERROR, "WinINet: Unable to initialize connection handle.");
	}

	wininetHandle->request_handle = HttpOpenRequestA(wininetHandle->session_handle,
		(handle->request == NULL ? "GET" : "POST"),
		query, NULL, NULL, NULL,
		(strcmp("https", scheme) == 0 ? INTERNET_FLAG_SECURE : 0),
		0);

	if (wininetHandle->request_handle == NULL){
		WININET_ERROR(ctx, GetLastError(), KSI_NETWORK_ERROR, "WinINet: Unable to initialize request handle.");
	}

	/*TODO Timeout is set, but seems to have no effect*/
	if (http->connectionTimeoutSeconds >= 0) {
		DWORD dw = (http->connectionTimeoutSeconds == 0 ? 0xFFFFFFFF : http->connectionTimeoutSeconds * 1000);
		if (!InternetSetOption(wininetHandle->request_handle, INTERNET_OPTION_CONNECT_TIMEOUT, &dw, sizeof(dw))){
			WININET_ERROR(ctx, GetLastError(), KSI_NETWORK_ERROR, "WinINet: Unable to set connection timeout.");
		}
	}

	if (http->readTimeoutSeconds >= 0) {
		DWORD dw = (http->readTimeoutSeconds == 0 ? 0xFFFFFFFF : http->readTimeoutSeconds * 1000);
		if (!InternetSetOption(wininetHandle->request_handle, INTERNET_OPTION_SEND_TIMEOUT, &dw, sizeof(dw))){
			WININET_ERROR(ctx, GetLastError(), KSI_NETWORK_ERROR, "WinINet: Unable to set send timeout.");
		}
		if (!InternetSetOption(wininetHandle->request_handle, INTERNET_OPTION_RECEIVE_TIMEOUT, &dw, sizeof(dw))){
			WININET_ERROR(ctx, GetLastError(), KSI_NETWORK_ERROR, "WinINet: Unable to set receive timeout.");
		}
	}

	handle->readResponse = wininetReceive;
	handle->client = client;

    res = KSI_RequestHandle_setImplContext(handle, wininetHandle, (void (*)(void *))wininetNetHandleCtx_free);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

    wininetHandle = NULL;
	res = KSI_OK;

cleanup:

	wininetNetHandleCtx_free(wininetHandle);

	KSI_free(query);
	KSI_free(hostName);
	KSI_free(scheme);

	return res;
}

static void implCtx_free(void * hInternet){
	InternetCloseHandle((HINTERNET)hInternet);
}

int KSI_HttpClientImpl_init(KSI_HttpClient *client) {
	KSI_HttpClient *http = (KSI_HttpClient *)client;
	HINTERNET internet_handle;
	ULONG buf;
	KSI_CTX *ctx = NULL;
	int res;

	if (client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	ctx = client->parent.ctx;
	KSI_ERR_clearErrors(ctx);



	//Initializes an application's use of the Win32 Internet functions.
	internet_handle = InternetOpenA(http->agentName, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (internet_handle == NULL) {
		WININET_ERROR(ctx, GetLastError(), KSI_NETWORK_ERROR, "WinINet: Unable to init.");
	}

	/* By default WinINet allows just two simultaneous connections to one server. */
	buf = 1024;
	res = InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		WININET_ERROR(ctx, GetLastError(), KSI_UNKNOWN_ERROR, "WinINet: Unable to init.");
	}

	res = InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		WININET_ERROR(ctx, GetLastError(), KSI_UNKNOWN_ERROR, "WinINet: Unable to init.");
	}

	http->implCtx = internet_handle;
	http->implCtx_free = implCtx_free;
	internet_handle = NULL;
	http->sendRequest = wininetSendRequest;

	res = KSI_OK;

cleanup:

	if (internet_handle) InternetCloseHandle(internet_handle);

	return res;
}

#endif
