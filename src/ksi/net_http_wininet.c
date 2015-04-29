/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
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
		KSI_FAIL_EXT(&err, _ksier, _error, _msg); \
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
	KSI_ERR err;
	HINTERNET handle;
	KSI_HttpClient *http = NULL;
	DWORD dwordLen;
	DWORD http_payload_len = 0;
	DWORD http_status;
	DWORD tmp_len = 0;
	unsigned char *tmp = NULL;

	KSI_PRE(&err, reqHandle != NULL) goto cleanup;
	KSI_PRE(&err, buf != NULL) goto cleanup;
	KSI_PRE(&err, len != NULL) goto cleanup;
	KSI_BEGIN(reqHandle->ctx, &err);


	handle = ((wininetNetHandleCtx*)reqHandle->implCtx)->request_handle;
	http = (KSI_HttpClient*)reqHandle->client;

	/*Get HTTP status code*/
	dwordLen = sizeof(DWORD);
	if (!HttpQueryInfo(handle, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &http_status, &dwordLen, 0)) {
		WININET_ERROR_1(reqHandle->ctx, ERROR_INSUFFICIENT_BUFFER, KSI_INVALID_ARGUMENT, "WinINet: Insufficient buffer.")
		WININET_ERROR_m(reqHandle->ctx, ERROR_HTTP_HEADER_NOT_FOUND, KSI_NETWORK_ERROR, "WinINet: HTTP status code header not found.")
		WININET_ERROR_N(reqHandle->ctx, KSI_UNKNOWN_ERROR, "WinINet: Unable to get HTTP status code.")
	}

	http->httpStatus = http_status;

	/*Get the length of the payload*/
	dwordLen = sizeof(DWORD);
	if (!HttpQueryInfo(handle, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &http_payload_len, &dwordLen, 0)){
			WININET_ERROR_1(reqHandle->ctx, ERROR_INSUFFICIENT_BUFFER, KSI_INVALID_ARGUMENT, "WinINet: Insufficient buffer.")
			WININET_ERROR_m(reqHandle->ctx, ERROR_HTTP_HEADER_NOT_FOUND, KSI_NETWORK_ERROR, "WinINet: HTTP content length not found.")
			WININET_ERROR_N(reqHandle->ctx, KSI_UNKNOWN_ERROR, "WinINet: Unable to get HTTP content length.")
		}

	/*Get memory for the HTTP payload*/
	tmp_len = http_payload_len;
	tmp = (unsigned char*)KSI_malloc(tmp_len);
	if (tmp == NULL){
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	/*Read data*/
	if (!InternetReadFile(handle, tmp, tmp_len, &tmp_len)) {
		WININET_ERROR_1(reqHandle->ctx, ERROR_INSUFFICIENT_BUFFER, KSI_INVALID_ARGUMENT, "WinINet: Insufficient buffer.")
		WININET_ERROR_N(reqHandle->ctx, KSI_UNKNOWN_ERROR, "WinINet: HTTP Internet read error.")
	}

	if (tmp_len != http_payload_len){
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "WinINet: Unable to read all bytes.");
		goto cleanup;
	}

	*buf = tmp;
	*len = tmp_len;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp);

	return KSI_RETURN(&err);
}

static int wininetReceive(KSI_RequestHandle *handle) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL;
	wininetNetHandleCtx *wininetHandle = NULL;
	unsigned char *resp = NULL;
	unsigned resp_len = 0;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, handle->client != NULL) goto cleanup;
	KSI_PRE(&err, handle->implCtx != NULL) goto cleanup;
	ctx = KSI_RequestHandle_getCtx(handle);
	KSI_BEGIN(ctx, &err);

	wininetHandle = handle->implCtx;

	if (!HttpSendRequestA(wininetHandle->request_handle, NULL, 0, (LPVOID) handle->request, handle->request_length)) {
		WININET_ERROR_1(ctx, ERROR_INTERNET_CANNOT_CONNECT, KSI_NETWORK_ERROR, "WinINet: Unable to resolve host.")
		WININET_ERROR_m(ctx, ERROR_INTERNET_NAME_NOT_RESOLVED, KSI_NETWORK_ERROR, "WinINet: HTTP status code header not found.")
		WININET_ERROR_m(ctx, ERROR_INTERNET_TIMEOUT, KSI_NETWORK_SEND_TIMEOUT, NULL)
		WININET_ERROR_N(ctx, KSI_UNKNOWN_ERROR, "WinINet: Unable to send request.")
	}

	res = winINet_ReadFromHandle(handle, &resp, &resp_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_RequestHandle_setResponse(handle, resp, resp_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

    KSI_free(resp);

	return KSI_RETURN(&err);
}


/**
 * Prepares request and opens a session handle.
 */
static int wininetSendRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *url) {
	KSI_ERR err;
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


	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_PRE(&err, http->implCtx != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	ctx = handle->ctx;
	KSI_BEGIN(ctx, &err);


	/*Initializing of wininet helper struct*/
	res = wininetNetHandleCtx_new(&wininetHandle);
	KSI_CATCH(&err, res) goto cleanup;

	wininetHandle->ctx = ctx;
	internetHandle = http->implCtx;

	res = KSI_UriSplitBasic(url, &scheme, &hostName, &port, &query);
	if(res != KSI_OK){
		KSI_snprintf(msg, sizeof(msg), "WinINet: Unable to crack url '%s'.", url);
		KSI_FAIL(&err, res, msg);
		goto cleanup;
	}

	if(scheme == NULL || strcmp("http", scheme) != 0 && strcmp("https", scheme) != 0){
		KSI_snprintf(msg, sizeof(msg), "WinINet: unknown Internet scheme '%s'.", scheme);
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, msg);
		goto cleanup;
	}

	if(hostName == NULL || query == NULL){
		KSI_snprintf(msg, sizeof(msg), "WinINet: Invalid url '%s'.", url);
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, msg);
		goto cleanup;
	}

	if (handle->request_length > LONG_MAX) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "WinINet: Request too long.");
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
    KSI_CATCH(&err, res) goto cleanup;

    wininetHandle = NULL;
	KSI_SUCCESS(&err);

cleanup:

	wininetNetHandleCtx_free(wininetHandle);

	KSI_free(query);
	KSI_free(hostName);
	KSI_free(scheme);

	return KSI_RETURN(&err);
}

static void implCtx_free(void * hInternet){
	InternetCloseHandle((HINTERNET)hInternet);
}

int KSI_HttpClientImpl_init(KSI_HttpClient *client) {
	KSI_ERR err;
	KSI_HttpClient *http = (KSI_HttpClient *)client;
	HINTERNET internet_handle;
	ULONG buf;
	int res;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_BEGIN(client->parent.ctx, &err);

	if (http == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "HttpClient network client context not initialized.");
		goto cleanup;
	}

	//Initializes an application's use of the Win32 Internet functions.
	internet_handle = InternetOpenA(http->agentName, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (internet_handle == NULL) {
		WININET_ERROR(client->parent.ctx, GetLastError(), KSI_NETWORK_ERROR, "WinINet: Unable to init.");
	}

	/* By default WinINet allows just two simultaneous connections to one server. */
	buf = 1024;
	res = InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		WININET_ERROR(client->parent.ctx, GetLastError(), KSI_UNKNOWN_ERROR, "WinINet: Unable to init.");
	}

	res = InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		WININET_ERROR(client->parent.ctx, GetLastError(), KSI_UNKNOWN_ERROR, "WinINet: Unable to init.");
	}

	http->implCtx = internet_handle;
	http->implCtx_free = implCtx_free;
	internet_handle = NULL;
	http->sendRequest = wininetSendRequest;

	KSI_SUCCESS(&err);

cleanup:

	if (internet_handle) InternetCloseHandle(internet_handle);

	return KSI_RETURN(&err);
}

#endif
