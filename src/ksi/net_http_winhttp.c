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

#if KSI_NET_HTTP_IMPL==KSI_IMPL_WINHTTP

#include <windows.h>
#include <Winhttp.h>

#include "net_http_impl.h"
#include "net_impl.h"


typedef struct winhttpNetHandleCtx_st {
	KSI_CTX *ctx;
	/* Internet handle for WinHTTP*/
	HINTERNET session_handle;
	/*A internet handle object for handling a HTTP connection*/
	HINTERNET connection_handle;
	/*A internet handle object for handling a HTTP request*/
	HINTERNET request_handle;
	/*Object for holding pointers to url components*/
	URL_COMPONENTS uc;	
	/*A copy of host name (copied from uc)*/
	wchar_t *hostName;
	/*A copy of URL path + extras (copied from uc)*/
	wchar_t *query;
} winhttpNetHandleCtx;

/**
 * Function for releasing KSI_NetHandle helper struct. 
 * Called by net.c -> KSI_RequestHandle_free   
 */
static void winhttpNetHandleCtx_free(winhttpNetHandleCtx *handleCtx) {
	if (handleCtx != NULL) {
		if (handleCtx->connection_handle != NULL){
			WinHttpCloseHandle(handleCtx->connection_handle);
			handleCtx->connection_handle = NULL;
		}
		
		if (handleCtx->request_handle != NULL){
			WinHttpCloseHandle(handleCtx->request_handle);
			handleCtx->request_handle = NULL;
		}
		
		KSI_free(handleCtx->hostName);
		KSI_free(handleCtx->query);
		KSI_free(handleCtx);
	}
}

static int winhttpNetHandleCtx_new(winhttpNetHandleCtx **handleCtx){
	winhttpNetHandleCtx *nhc = NULL;
	int res = KSI_UNKNOWN_ERROR;
	
	nhc = KSI_new(winhttpNetHandleCtx);
	if (nhc == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	nhc->ctx = NULL;
	nhc->session_handle = NULL;
	nhc->connection_handle = NULL;
	nhc->request_handle = NULL;
	nhc->hostName = NULL;
	nhc->query = NULL;
	memset(&(nhc->uc), 0, sizeof(nhc->uc));
	nhc->uc.dwStructSize = sizeof(nhc->uc);

	*handleCtx = nhc;
	nhc = NULL;
	
	res = KSI_OK;
	
cleanup:

	winhttpNetHandleCtx_free(nhc);

return res;
}

/**
 * Create a 16-bit Unicode character string from C string.
 * 
 * \param[in] cstr Pointer to source string. 
 * 
 * \return Pointer to output string.
 * 
 * \Note Object belongs to the caller and must be freed. 
 */
static LPWSTR LPWSTR_new(const char * cstr){
	int lenInChars =0;
	wchar_t * p_wchar = NULL;
	//Get chracater count.
	lenInChars = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, cstr, -1, NULL,0);
	p_wchar = (wchar_t *)KSI_malloc(lenInChars*sizeof(wchar_t));
	if (p_wchar == NULL) return NULL;
	MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, cstr, -1, p_wchar,lenInChars);
	return p_wchar;
}

static void LPWSTR_free(LPWSTR wstr){
	KSI_free(wstr);
}

static int winhttpReceive(KSI_RequestHandle *handle) {
	KSI_ERR err;
	int res;
	winhttpNetHandleCtx *nhc = NULL;
	unsigned char *request = NULL;
	unsigned request_len = 0;
	unsigned char *resp = NULL;
	unsigned resp_len = 0;
	char err_msg[128];
	DWORD http_response;
	DWORD http_response_len = sizeof(http_response);
	KSI_CTX *ctx = KSI_RequestHandle_getCtx(handle);
	
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_RequestHandle_getNetContext(handle, (void **)&nhc);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_RequestHandle_getRequest(handle, &request, &request_len);
	KSI_CATCH(&err, res) goto cleanup;
	
	/*Send request*/
	if (!WinHttpSendRequest(nhc->request_handle, WINHTTP_NO_ADDITIONAL_HEADERS,0, (LPVOID) request, request_len, request_len,0)) {
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "WinHTTP: send error %i.", error);
		
		if (error == ERROR_WINHTTP_CANNOT_CONNECT)
			KSI_FAIL(&err, KSI_NETWORK_ERROR, "WinHTTP: Unable to connect.");
		else if (error == ERROR_WINHTTP_TIMEOUT)
			KSI_FAIL(&err, KSI_NETWORK_SEND_TIMEOUT, NULL);
		else if (error == ERROR_WINHTTP_NAME_NOT_RESOLVED){
			KSI_snprintf(err_msg, sizeof(err_msg), "WinHTTP: Could not resolve host: '%ws'.", nhc->hostName);
			KSI_FAIL(&err, KSI_NETWORK_ERROR, err_msg);
		}
		else
			KSI_FAIL_EXT(&err, KSI_NETWORK_ERROR, error, "WinHTTP: Unable to send request.");
		
		goto cleanup;
	}

	if (!WinHttpReceiveResponse(nhc->request_handle, NULL)){
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "WinHTTP: Receive error %i.", error);

		if (error == ERROR_WINHTTP_TIMEOUT)
			KSI_FAIL(&err, KSI_NETWORK_RECIEVE_TIMEOUT, NULL);
		else
			KSI_FAIL_EXT(&err, KSI_NETWORK_ERROR, error, "WinHTTP: Unable to get HTTP response.");
			
		goto cleanup;
	}
	
	/* Receive the response information. */
	if (!WinHttpQueryHeaders(nhc->request_handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &http_response, &http_response_len, 0)) {
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "WinHTTP: Query error %i.", error);
		
		if (error == ERROR_INSUFFICIENT_BUFFER)
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "WinHTTP: Insufficient buffer.");
		else
			KSI_FAIL_EXT(&err, KSI_UNKNOWN_ERROR, error, "WinHTTP: Unable to get HTTP response.");

		goto cleanup;
	}

	if (http_response >= 400){
		KSI_snprintf(err_msg, sizeof(err_msg), "WinHTTP: Http error %i.", http_response);
		KSI_FAIL(&err, KSI_HTTP_ERROR, err_msg);
		goto cleanup;
	}

	while (1) {
		DWORD add_len = 0x2000; /* Download in 8K increments. */
		resp = KSI_realloc(resp, resp_len + add_len);
		
		if (resp == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		if (!WinHttpReadData(nhc->request_handle, resp + resp_len, add_len, &add_len)) {
			DWORD error = GetLastError();
			KSI_LOG_debug(ctx, "WinHTTP: Dada read error %i.", error);

			if (error == ERROR_INSUFFICIENT_BUFFER)
				KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "WinHTTP: Insufficient buffer.");
			else
				KSI_FAIL_EXT(&err, KSI_UNKNOWN_ERROR, error, "WinHTTP: Unable to read response.");			

			goto cleanup;
		}
		
		if (add_len == 0) break;
		
		resp_len += add_len;
	}

	/*Put Received data no requesthandle*/
    res = KSI_RequestHandle_setResponse(handle, resp, resp_len);
    KSI_CATCH(&err, res) goto cleanup;
	
	KSI_SUCCESS(&err);

cleanup:

    KSI_free(resp);

	return KSI_RETURN(&err);
}

/**
 * Prepares request and opens a session handle.
 * 
 * \param handle Pointer to KSI_RequestHandle object.
 * \param agent
 * \param url Pointer to url string.
 * 
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
static int winhttpSendRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *url) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL;
	unsigned char *request = NULL;
	unsigned request_len = 0;
	char err_msg[128];
	winhttpNetHandleCtx *implCtx = NULL;
	KSI_HttpClient *http = (KSI_HttpClient *)client;
	LPWSTR w_url = NULL;
	
	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_PRE(&err, http->implCtx != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	ctx = handle->ctx;
	KSI_BEGIN(ctx, &err);

	/*Initializing of winhttp helper struct*/
	res = winhttpNetHandleCtx_new(&implCtx);
	KSI_CATCH(&err, res) goto cleanup;
	ctx = KSI_RequestHandle_getCtx(handle);
	implCtx->ctx = ctx;
	implCtx->session_handle = http->implCtx;
	
	/*Cracking URL*/
	implCtx->uc.dwHostNameLength = 1;
	implCtx->uc.dwUrlPathLength = 1;
	implCtx->uc.dwExtraInfoLength = 1;
	w_url = LPWSTR_new(url);

	if (!WinHttpCrackUrl(w_url, 0, 0, &(implCtx->uc))) {
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "WinHTTP: Url crack error: %i.", error);
		
		if (error == ERROR_WINHTTP_UNRECOGNIZED_SCHEME)
			KSI_FAIL(&err, KSI_NETWORK_ERROR, "WinHTTP: Internet scheme is not 'HTTP/HTTPS'.");
		else if (error == ERROR_WINHTTP_INVALID_URL){
			KSI_snprintf(err_msg, sizeof(err_msg), "WinHTTP: Invalid URL: '%s'.", url);
			KSI_FAIL(&err, KSI_NETWORK_ERROR, err_msg);
		}
		else
			KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "WinHTTP: Unable to crack url.");
		
		goto cleanup;
	}

	/*Extracting host name*/
	if (implCtx->uc.lpszHostName == NULL || implCtx->uc.dwHostNameLength == 0){
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "WinHTTP: Invalid host name.");
		goto cleanup;
	}

	implCtx->hostName = KSI_malloc(implCtx->uc.dwHostNameLength*2 + 2);
	if (implCtx->hostName == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	wcsncpy_s(implCtx->hostName, implCtx->uc.dwHostNameLength + 1, implCtx->uc.lpszHostName, implCtx->uc.dwHostNameLength);
	if (implCtx->uc.lpszUrlPath == NULL || implCtx->uc.dwUrlPathLength == 0) {
		implCtx->query = LPWSTR_new("/");
	}
	else{
		/*Extracting query string*/
		implCtx->query = KSI_malloc((implCtx->uc.dwUrlPathLength + implCtx->uc.dwExtraInfoLength)*2 + 2);
		if (implCtx->query == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		wcsncpy_s(implCtx->query, implCtx->uc.dwUrlPathLength + 1, implCtx->uc.lpszUrlPath, implCtx->uc.dwUrlPathLength);
		if (!(implCtx->uc.lpszExtraInfo == NULL || implCtx->uc.dwExtraInfoLength == 0)) {
			wcsncpy_s(implCtx->query + implCtx->uc.dwUrlPathLength, implCtx->uc.dwExtraInfoLength + 1, implCtx->uc.lpszExtraInfo, implCtx->uc.dwExtraInfoLength);
		}
	}

	/*Preparing request*/
	KSI_LOG_debug(ctx, "WinHTTP: Sending request to: %s.", url);

	res = KSI_RequestHandle_getRequest(handle, &request, &request_len);
	KSI_CATCH(&err, res) goto cleanup;

	if (request_len > LONG_MAX) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "WinHTTP: Request too long.");
		goto cleanup;
	}

	handle->readResponse = winhttpReceive;
	handle->client = client;
	
	/*Preparing session handle. Opens an HTTP session for a given site*/
	implCtx->connection_handle = WinHttpConnect(implCtx->session_handle, implCtx->hostName, implCtx->uc.nPort, 0);
	if (implCtx->connection_handle == NULL) {
		DWORD error = GetLastError();

		if (error == ERROR_WINHTTP_INVALID_URL){
			KSI_snprintf(err_msg, sizeof(err_msg), "WinHTTP: Could not resolve host: '%ws'.", implCtx->hostName);
			KSI_FAIL(&err, KSI_NETWORK_ERROR, err_msg);
			}
		else	
			KSI_FAIL(&err, KSI_NETWORK_ERROR, "WinHTTP: Unable to initialize connection handle.");

		goto cleanup;
	}

	implCtx->request_handle = WinHttpOpenRequest(implCtx->connection_handle,
			(request == NULL ? L"GET" : L"POST"),
			implCtx->query, 
			NULL, NULL, NULL,0);
	
	if (implCtx->request_handle == NULL){
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "WinHTTP: Open request error %i.", error);
		KSI_FAIL(&err, KSI_NETWORK_ERROR, "WinHTTP: Unable to initialize request handle.");
		goto cleanup;
	}
	
	if (!WinHttpSetTimeouts(implCtx->request_handle,0, http->connectionTimeoutSeconds*1000, 0, http->readTimeoutSeconds*1000)){
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "WinHTTP: Set timeout error %i.", error);
		KSI_FAIL(&err, KSI_NETWORK_ERROR, "WinHTTP: Unable to set timeouts.");
		goto cleanup;
	}
	
    res = KSI_RequestHandle_setImplContext(handle, implCtx, (void (*)(void *))winhttpNetHandleCtx_free);
    KSI_CATCH(&err, res) goto cleanup;

    implCtx = NULL;
	KSI_SUCCESS(&err);

cleanup:

	LPWSTR_free(w_url);
	winhttpNetHandleCtx_free(implCtx);

	return KSI_RETURN(&err);
}

static void implCtx_free(void * hInternet){
	WinHttpCloseHandle((HINTERNET)hInternet);
}

int KSI_HttpClientImpl_init(KSI_HttpClient *http) {
	KSI_ERR err;
	HINTERNET session_handle = NULL;
	ULONG buf;
	LPWSTR agent_name = NULL;
	int res;

	KSI_PRE(&err, http != NULL) goto cleanup;
	KSI_BEGIN(http->parent.ctx, &err);

	if (http == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "HttpClient network client context not initialized.");
		goto cleanup;
	}

	agent_name = LPWSTR_new(http->agentName);
	//Initializes an application's use of the Win32 Internet functions. 
	session_handle = WinHttpOpen(agent_name, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (session_handle == NULL) {
		KSI_FAIL_EXT(&err, KSI_UNKNOWN_ERROR, GetLastError(), "WinHTTP: Unable to send request.");
		goto cleanup;
	}
	
	buf = 1024;
	res = WinHttpSetOption(session_handle, WINHTTP_OPTION_MAX_CONNS_PER_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		KSI_FAIL_EXT(&err, KSI_UNKNOWN_ERROR, GetLastError(), "WinHTTP: Unable to send request.");
		goto cleanup;
	}

	res = WinHttpSetOption(session_handle, WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		KSI_FAIL_EXT(&err, KSI_UNKNOWN_ERROR, GetLastError(), "WinHTTP: Unable to send request.");
		goto cleanup;
	}
	
	http->implCtx = session_handle;
	http->implCtx_free = implCtx_free;
	session_handle = NULL;
	http->sendRequest = winhttpSendRequest;

	KSI_SUCCESS(&err);

cleanup:

	if (session_handle) WinHttpCloseHandle(session_handle);
	if (agent_name) LPWSTR_free(agent_name);
	
	return KSI_RETURN(&err);
}

#endif
