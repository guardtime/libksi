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
	/*A internet handle object for handling a HTTP session*/
	HINTERNET session_handle;
	/*A internet handle object for handling a HTTP request*/
	HINTERNET request_handle;
	/*Object for holding pointers to url components*/
	URL_COMPONENTS uc;	
	/*A copy of host name (copied from uc)*/
	char *hostName;
	/*A copy of URL path + extras (copied from uc)*/
	char *query;
	/*Network scheme: 3 for http://, 5 for file:// */
	INTERNET_SCHEME scheme;
} wininetNetHandleCtx;


static void wininetNetHandleCtx_free(wininetNetHandleCtx *handleCtx) {
	if (handleCtx != NULL) {
		if (handleCtx->session_handle != NULL){
			InternetCloseHandle(handleCtx->session_handle);
			handleCtx->session_handle = NULL;
		}
		
		if (handleCtx->request_handle != NULL){
			InternetCloseHandle(handleCtx->request_handle);
			handleCtx->request_handle = NULL;
		}
		
		KSI_free(handleCtx->hostName);
		KSI_free(handleCtx->query);
		KSI_free(handleCtx);
	}
}

static int wininetNetHandleCtx_new(wininetNetHandleCtx **handleCtx){
	wininetNetHandleCtx *nhc = NULL;
	int res = KSI_UNKNOWN_ERROR;

	nhc = KSI_new(wininetNetHandleCtx);
	if (nhc == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	nhc->ctx = NULL;
	nhc->session_handle = NULL;
	nhc->request_handle = NULL;
	nhc->hostName = NULL;
	nhc->query = NULL;
	nhc->scheme = INTERNET_SCHEME_DEFAULT;
	memset(&(nhc->uc), 0, sizeof(nhc->uc));
	nhc->uc.dwStructSize = sizeof(nhc->uc);
	
	*handleCtx = nhc;
	nhc = NULL;
	
	res = KSI_OK;
	
cleanup:

	wininetNetHandleCtx_free(nhc);

	return res;
}

static int wininetReceive(KSI_RequestHandle *handle) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL; 
	KSI_HttpClient *http = NULL;
	wininetNetHandleCtx *wininetHandle = NULL;
	DWORD http_response;
	DWORD http_response_len = 0;
	unsigned char *resp = NULL;
	unsigned resp_len = 0;
	char err_msg[128];
	
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, handle->client != NULL) goto cleanup;
	KSI_PRE(&err, handle->implCtx != NULL) goto cleanup;
	ctx = KSI_RequestHandle_getCtx(handle);
	KSI_BEGIN(ctx, &err);

	
	http = (KSI_HttpClient *)handle->client;
	wininetHandle = handle->implCtx;
	
	if (wininetHandle->scheme == INTERNET_SCHEME_HTTP){
		/*Send request*/
		if (!HttpSendRequestA(wininetHandle->request_handle, NULL, 0, (LPVOID) handle->request, handle->request_length)) {
			DWORD error = GetLastError();
			KSI_LOG_debug(ctx, "WinINet: Send error %i.", error);

			if (error == ERROR_INTERNET_NAME_NOT_RESOLVED){
				KSI_snprintf(err_msg, sizeof(err_msg), "WinINet: Could not resolve host: '%s'.", wininetHandle->hostName);
				KSI_FAIL(&err, KSI_NETWORK_ERROR, err_msg);
			}
			else if (error == ERROR_INTERNET_CANNOT_CONNECT)
				KSI_FAIL(&err, KSI_NETWORK_ERROR, "WinINet: Unable to connect.");
			else if (error = ERROR_INTERNET_TIMEOUT)
				KSI_FAIL(&err, KSI_NETWORK_SEND_TIMEOUT, NULL);
			else
				KSI_FAIL_EXT(&err, KSI_NETWORK_ERROR, error, "WinINet: Unable to send request.");
			
			goto cleanup;
		}

		http_response_len = sizeof(http_response);
		/* Receive the response information. */
		if (!HttpQueryInfo(wininetHandle->request_handle, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &http_response, &http_response_len, 0)) {
			DWORD error = GetLastError();
			if (error == ERROR_HTTP_HEADER_NOT_FOUND)
				KSI_FAIL(&err, KSI_HTTP_ERROR, "WinINet: HTTP header not found.");
			else if (error == ERROR_INSUFFICIENT_BUFFER)
				KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "WinINet: Insufficient buffer.");
			else if (error = ERROR_INTERNET_TIMEOUT)
				KSI_FAIL(&err, KSI_NETWORK_RECIEVE_TIMEOUT, NULL);
			else
				KSI_FAIL_EXT(&err, KSI_NETWORK_ERROR, error, "WinINet: Unable to get HTTP response.");
			
			goto cleanup;
		}

		if (http_response >= 400){
			KSI_snprintf(err_msg, sizeof(err_msg), "WinINet: Http error %i.", http_response);
			KSI_FAIL(&err, KSI_HTTP_ERROR, err_msg);
			goto cleanup;
		}
	}
	else{
		KSI_FAIL(&err, KSI_NETWORK_ERROR, "WinINet: Internet scheme is not 'HTTP/HTTPS'.");
		goto cleanup;
		}
	
	while (1) {
		DWORD add_len = 0x2000; /* Download in 8K increments. */
		resp = KSI_realloc(resp, resp_len + add_len);
		if (resp == NULL) {
			KSI_FAIL(&err,KSI_OUT_OF_MEMORY ,NULL);
			goto cleanup;
		}

		if (!InternetReadFile(wininetHandle->request_handle, resp + resp_len, add_len, &add_len)) {
			DWORD error = GetLastError();
			if (error == ERROR_INSUFFICIENT_BUFFER)
				KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "WinINet: Insufficient buffer.");
			else
				KSI_FAIL_EXT(&err, KSI_UNKNOWN_ERROR, error, "WinINet: Unable to read response.");
			
			goto cleanup;
		}
		
		if (add_len == 0) {
			break;
		}
		resp_len += add_len;
	}

	/*Put Received data no requesthandle*/
    res = KSI_RequestHandle_setResponse(handle, resp, resp_len);
    KSI_CATCH(&err, res) goto cleanup;
		
	
    /* Cleanup on success.*/
	KSI_SUCCESS(&err);

cleanup:

    KSI_free(resp);

	return KSI_RETURN(&err);
}


/**
 * Prepares request and opens a session handle.
 * 
 * \param client Pointer to KSI_NetworkClient object.
 * \param handle Pointer to KSI_RequestHandle object.
 * \param url Pointer to url string.
 * 
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
static int wininetSendRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *url) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL;
	HINTERNET internetHandle;
	KSI_HttpClient *http = (KSI_HttpClient *)client;
	wininetNetHandleCtx *wininetHandle = NULL;
	
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

	/*Cracking URL*/
	wininetHandle->uc.dwHostNameLength = 1;
	wininetHandle->uc.dwUrlPathLength = 1;
	wininetHandle->uc.dwExtraInfoLength = 1;
	
	if (!InternetCrackUrlA(url, 0, 0, &(wininetHandle->uc))) {
		char err_msg[128];
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "WinINet:  Url crack error: %i", error);
		
		if (error == ERROR_INTERNET_INVALID_URL){
			KSI_snprintf(err_msg, 128, "WinINet: Invalid URL: '%s'", url);
			KSI_FAIL(&err, KSI_NETWORK_ERROR, err_msg);
		}
		else{
			KSI_FAIL_EXT(&err, KSI_NETWORK_ERROR, error, "WinInet: Unable to crack URL.");
		}
		goto cleanup;
	}
	
	wininetHandle->scheme = wininetHandle->uc.nScheme;
	
	/*Open different request handles for http and file scheme*/
	if (wininetHandle->scheme == INTERNET_SCHEME_HTTP){
		/*Extracting host name*/
		if (wininetHandle->uc.lpszHostName == NULL || wininetHandle->uc.dwHostNameLength == 0){
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "WinINet: Invalid host name.");
			goto cleanup;
		}

		wininetHandle->hostName = KSI_malloc(wininetHandle->uc.dwHostNameLength + 1);
		if (wininetHandle->hostName == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		KSI_strncpy(wininetHandle->hostName, wininetHandle->uc.lpszHostName, wininetHandle->uc.dwHostNameLength + 1);
		if (wininetHandle->uc.lpszUrlPath == NULL || wininetHandle->uc.dwUrlPathLength == 0) {
			wininetHandle->query = KSI_calloc(2,1);
			if (wininetHandle->query == NULL)
				KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			wininetHandle->query[0] = '/';
		}
		else{
			/*Extracting query string*/
			wininetHandle->query = KSI_malloc(wininetHandle->uc.dwUrlPathLength + wininetHandle->uc.dwExtraInfoLength + 1);
			if (wininetHandle->query == NULL) {
				KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
				goto cleanup;
			}

			KSI_strncpy(wininetHandle->query, wininetHandle->uc.lpszUrlPath, wininetHandle->uc.dwUrlPathLength + 1);
			if (!(wininetHandle->uc.lpszExtraInfo == NULL || wininetHandle->uc.dwExtraInfoLength == 0)) {
				KSI_strncpy(wininetHandle->query + wininetHandle->uc.dwUrlPathLength, wininetHandle->uc.lpszExtraInfo, wininetHandle->uc.dwExtraInfoLength + 1);
			}
		}


		/*Preparing request*/

		KSI_LOG_debug(ctx, "WinINet: Sending request to: %s.", url);

		if (handle->request_length > LONG_MAX) {
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "WinINet: Request too long.");
			goto cleanup;
		}


		/*Preparing session handle*/
		//Opens an HTTP session for a given site
		wininetHandle->session_handle = InternetConnectA(internetHandle, wininetHandle->hostName, wininetHandle->uc.nPort, NULL, NULL, wininetHandle->uc.nScheme, 0, 0);
		if (wininetHandle->session_handle == NULL) {
			KSI_FAIL(&err, KSI_NETWORK_ERROR, "WinINet: Unable to initialize connection handle.");
			goto cleanup;
		}

		wininetHandle->request_handle = HttpOpenRequestA(wininetHandle->session_handle,
			(handle->request == NULL ? "GET" : "POST"),
			wininetHandle->query, NULL, NULL, NULL,
			(wininetHandle->uc.nScheme == INTERNET_SCHEME_HTTPS ? INTERNET_FLAG_SECURE : 0),
			0);

		if (wininetHandle->request_handle == NULL){
			DWORD error = GetLastError();
			KSI_LOG_debug(ctx, "WinINet: Open request error %i.", error);
			KSI_FAIL(&err, KSI_NETWORK_ERROR, "WinINet: Unable to initialize request handle.");
			goto cleanup;
		}

		/*TODO Timeout is set, but seems to have no effect*/
		if (http->connectionTimeoutSeconds >= 0) {
			DWORD dw = (http->connectionTimeoutSeconds == 0 ? 0xFFFFFFFF : http->connectionTimeoutSeconds * 1000);
			if (!InternetSetOption(wininetHandle->request_handle, INTERNET_OPTION_CONNECT_TIMEOUT, &dw, sizeof(dw))){
				KSI_FAIL_EXT(&err, KSI_NETWORK_ERROR, GetLastError(),"WinINet: Unable to set connection timeout.");
				goto cleanup;	
			}
		}

		if (http->readTimeoutSeconds >= 0) {
			DWORD dw = (http->readTimeoutSeconds == 0 ? 0xFFFFFFFF : http->readTimeoutSeconds * 1000);
			if (!InternetSetOption(wininetHandle->request_handle, INTERNET_OPTION_SEND_TIMEOUT, &dw, sizeof(dw))){
				KSI_FAIL_EXT(&err, KSI_NETWORK_ERROR, GetLastError(),"WinINet: Unable to set send timeout.");
				goto cleanup;
			}
			if (!InternetSetOption(wininetHandle->request_handle, INTERNET_OPTION_RECEIVE_TIMEOUT, &dw, sizeof(dw))){
				KSI_FAIL_EXT(&err, KSI_NETWORK_ERROR, GetLastError(), "WinINet: Unable to set receive timeout.");
				goto cleanup;
			}
		}
	}
	else if (wininetHandle->scheme == INTERNET_SCHEME_FILE){
		wininetHandle->request_handle = InternetOpenUrl(internetHandle, url, NULL, 0, 0,0);
		if (wininetHandle->request_handle == NULL){
			KSI_FAIL_EXT(&err, KSI_INVALID_ARGUMENT, GetLastError(), "WinINet: Unable to open Url.");
			goto cleanup;
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
		KSI_FAIL_EXT(&err, KSI_UNKNOWN_ERROR, GetLastError(), "WinINet: Unable to init.");
		goto cleanup;
	}
	
	/* By default WinINet allows just two simultaneous connections to one server. */
	buf = 1024;
	res = InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		KSI_FAIL_EXT(&err, KSI_UNKNOWN_ERROR, GetLastError(), "WinINet: Unable to init.");
		goto cleanup;
	}
	
	res = InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		KSI_FAIL_EXT(&err, KSI_UNKNOWN_ERROR, GetLastError(), "WinINet: Unable to init.");
		goto cleanup;
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
