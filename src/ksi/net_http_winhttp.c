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
	HINTERNET session_handle;
	HINTERNET connection_handle;
	HINTERNET request_handle;
} winhttpNetHandleCtx;


static void winhttpNetHandleCtx_free(winhttpNetHandleCtx *handleCtx) {
	if (handleCtx != NULL) {
		WinHttpCloseHandle(handleCtx->connection_handle);
		WinHttpCloseHandle(handleCtx->request_handle);
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

	*handleCtx = nhc;
	nhc = NULL;
	
	res = KSI_OK;
	
cleanup:

	winhttpNetHandleCtx_free(nhc);

return res;
}

#define WINHTTP_ERROR(_ctx, _error, _ksier, _msg) \
		KSI_LOG_error(_ctx, "WinHTTP returned error %i at line %i in file %s.", _error, __LINE__, __FILE__); \
		KSI_FAIL_EXT(&err, _ksier, _error, _msg); \
		goto cleanup;

#define WINHTTP_ERROR_1(_ctx, _winer, _ksier, _msg) { \
	DWORD _error = GetLastError(); \
	if(_winer == _error){ \
		WINHTTP_ERROR(_ctx, _error, _ksier, _msg) \
	}

#define WINHTTP_ERROR_m(_ctx, _winer, _ksier, _msg) \
	else if(_winer == _error){ \
		WINHTTP_ERROR(_ctx, _error, _ksier, _msg) \
	}

#define WINHTTP_ERROR_N(_ctx, _ksier, _msg) \
	else{ \
		WINHTTP_ERROR(_ctx, _error, _ksier, _msg) \
	}}

static int LPWSTR_new(const char * cstr, LPWSTR *new){
	int res = KSI_UNKNOWN_ERROR;
	int lenInChars = 0;
	wchar_t * p_wchar = NULL;
	
	if(cstr == NULL || new == NULL) return KSI_INVALID_ARGUMENT;
	
	lenInChars = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, cstr, -1, NULL,0);
	p_wchar = (wchar_t *)KSI_malloc(lenInChars*sizeof(wchar_t));
	if (p_wchar == NULL) return KSI_OUT_OF_MEMORY;

	MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, cstr, -1, p_wchar,lenInChars);
	*new = p_wchar;
	
	return KSI_OK;
}

static void LPWSTR_free(LPWSTR wstr){
	KSI_free(wstr);
}

static int winHTTP_ReadFromHandle(KSI_RequestHandle *reqHandle, unsigned char **buf, DWORD *len){
	KSI_ERR err;
	KSI_HttpClient *http = NULL;
	HINTERNET handle;
	DWORD dwordLen;
	DWORD http_payload_len = 0;
	DWORD http_status;
	DWORD tmp_len = 0;
	unsigned char *tmp = NULL;
	
	
	KSI_PRE(&err, reqHandle != NULL) goto cleanup;
	KSI_PRE(&err, buf != NULL) goto cleanup;
	KSI_PRE(&err, len != NULL) goto cleanup;
	KSI_BEGIN(reqHandle->ctx, &err);
	
	handle = ((winhttpNetHandleCtx*)reqHandle->implCtx)->request_handle;
	http = (KSI_HttpClient*)reqHandle->client;

	
	if (!WinHttpReceiveResponse(handle, NULL)){
		WINHTTP_ERROR_1(reqHandle->ctx, ERROR_WINHTTP_TIMEOUT, KSI_NETWORK_RECIEVE_TIMEOUT, NULL)
		WINHTTP_ERROR_N(reqHandle->ctx, KSI_NETWORK_ERROR, "WinHTTP: Unable to get HTTP response.")
		goto cleanup;
	}

	/*Get HTTP status code*/
	dwordLen = sizeof(DWORD);
	if (!WinHttpQueryHeaders(handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &http_status, &dwordLen, 0)) {
		WINHTTP_ERROR_1(reqHandle->ctx, ERROR_INSUFFICIENT_BUFFER, KSI_INVALID_ARGUMENT, "WinHTTP: Insufficient buffer.")
		WINHTTP_ERROR_N(reqHandle->ctx, KSI_NETWORK_ERROR, "WinHTTP: Unable to get HTTP status.")
	}

	http->httpStatus = http_status;
	
	/*Get response length*/
	dwordLen = sizeof(DWORD);
	if (!WinHttpQueryHeaders(handle, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &http_payload_len, &dwordLen, 0)) {
		WINHTTP_ERROR_1(reqHandle->ctx, ERROR_INSUFFICIENT_BUFFER, KSI_INVALID_ARGUMENT, "WinHTTP: Insufficient buffer.")
		WINHTTP_ERROR_N(reqHandle->ctx, KSI_NETWORK_ERROR, "WinHTTP: Unable to get HTTP content length.")
	}
	
	/*Get memory for the HTTP payload*/
	tmp_len = http_payload_len;
	tmp = (unsigned char*)KSI_malloc(tmp_len);
	if (tmp == NULL){
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	/*Read data*/
	if (!WinHttpReadData(handle, tmp, tmp_len, &tmp_len)) {
		WINHTTP_ERROR_1(reqHandle->ctx, ERROR_INSUFFICIENT_BUFFER, KSI_INVALID_ARGUMENT, "WinHTTP: Insufficient buffer.")
		WINHTTP_ERROR_N(reqHandle->ctx, KSI_UNKNOWN_ERROR, "WinHTTP: Unable to read response.")
	}

	if (tmp_len != http_payload_len){
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "WinHTTP: Unable to read all bytes.");
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


static int winhttpReceive(KSI_RequestHandle *handle) {
	KSI_ERR err;
	int res;
	winhttpNetHandleCtx *nhc = NULL;
	unsigned char *request = NULL;
	unsigned request_len = 0;
	unsigned char *resp = NULL;
	unsigned resp_len = 0;
	KSI_CTX *ctx = KSI_RequestHandle_getCtx(handle);
	
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_RequestHandle_getNetContext(handle, (void **)&nhc);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_RequestHandle_getRequest(handle, &request, &request_len);
	KSI_CATCH(&err, res) goto cleanup;
	
	/*Send request*/
	if (!WinHttpSendRequest(nhc->request_handle, WINHTTP_NO_ADDITIONAL_HEADERS,0, (LPVOID) request, request_len, request_len,0)) {
		WINHTTP_ERROR_1(ctx, ERROR_WINHTTP_CANNOT_CONNECT, KSI_NETWORK_ERROR, "WinHTTP: Unable to connect.")
		WINHTTP_ERROR_m(ctx, ERROR_WINHTTP_TIMEOUT, KSI_NETWORK_SEND_TIMEOUT, NULL)
		WINHTTP_ERROR_m(ctx, ERROR_WINHTTP_NAME_NOT_RESOLVED, KSI_NETWORK_ERROR, "WinHTTP: Could not resolve host.")
		WINHTTP_ERROR_N(ctx, KSI_NETWORK_ERROR, "WinHTTP: Unable to send request.")
	}

	res = winHTTP_ReadFromHandle(handle, &resp, &resp_len);
    KSI_CATCH(&err, res) goto cleanup;
	
    res = KSI_RequestHandle_setResponse(handle, resp, resp_len);
    KSI_CATCH(&err, res) goto cleanup;
	
	KSI_SUCCESS(&err);

cleanup:

    KSI_free(resp);

	return KSI_RETURN(&err);
}

static int winhttpSendRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *url) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL;
	winhttpNetHandleCtx *implCtx = NULL;
	KSI_HttpClient *http = (KSI_HttpClient *)client;
	char msg[128];
	char *scheme = NULL;
	char *hostName = NULL;
	char *query = NULL;
	int port = 0;
	LPWSTR W_host = NULL;
	LPWSTR W_query = NULL;
	unsigned char *request = NULL;
	unsigned request_len = 0;

	
	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_PRE(&err, http->implCtx != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	ctx = handle->ctx;
	KSI_BEGIN(ctx, &err);

	/*Initializing of winhttp helper struct*/
	res = winhttpNetHandleCtx_new(&implCtx);
	KSI_CATCH(&err, res) goto cleanup;

	implCtx->ctx = ctx;
	implCtx->session_handle = http->implCtx;

	res = KSI_UriSplitBasic(url, &scheme, &hostName, &port, &query);
	if(res != KSI_OK){
		KSI_snprintf(msg, sizeof(msg), "WinHTTP: Unable to crack url '%s'.", url);
		KSI_FAIL(&err, res, msg);
		goto cleanup;
	}
	
	if(scheme == NULL || strcmp("http", scheme) != 0 && strcmp("https", scheme) != 0){
		KSI_snprintf(msg, sizeof(msg), "WinHTTP: unknown Internet scheme '%s'.", scheme);
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, msg);
		goto cleanup;
	}
	
	if(hostName == NULL || query == NULL){
		KSI_snprintf(msg, sizeof(msg), "WinHTTP: Invalid url '%s'.", url);
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, msg);
		goto cleanup;
	}
	
	res = LPWSTR_new(hostName, &W_host);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = LPWSTR_new(query, &W_query);
	KSI_CATCH(&err, res) goto cleanup;
	

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
	implCtx->connection_handle = WinHttpConnect(implCtx->session_handle, W_host, port, 0);
	if (implCtx->connection_handle == NULL) {
		WINHTTP_ERROR_1(ctx, ERROR_WINHTTP_INVALID_URL, KSI_NETWORK_ERROR, "WinHTTP: Could not resolve host.")
		WINHTTP_ERROR_N(ctx, KSI_NETWORK_ERROR, "WinHTTP: Unable to initialize connection handle.")
	}

	implCtx->request_handle = WinHttpOpenRequest(implCtx->connection_handle,
			(request == NULL ? L"GET" : L"POST"),
			W_query, 
			NULL, NULL, NULL,0);
	
	if (implCtx->request_handle == NULL){
		WINHTTP_ERROR(ctx, GetLastError(), KSI_NETWORK_ERROR, "WinHTTP: Unable to initialize request handle.");
	}
	
	if (!WinHttpSetTimeouts(implCtx->request_handle,0, http->connectionTimeoutSeconds*1000, 0, http->readTimeoutSeconds*1000)){
		WINHTTP_ERROR(ctx, GetLastError(), KSI_NETWORK_ERROR, "WinHTTP: Unable to set timeouts.");
	}
	
    res = KSI_RequestHandle_setImplContext(handle, implCtx, (void (*)(void *))winhttpNetHandleCtx_free);
    KSI_CATCH(&err, res) goto cleanup;

    implCtx = NULL;
	KSI_SUCCESS(&err);

cleanup:

	winhttpNetHandleCtx_free(implCtx);
	KSI_free(scheme);
	KSI_free(hostName);
	KSI_free(query);
	LPWSTR_free(W_host);
	LPWSTR_free(W_query);

	return KSI_RETURN(&err);
}

static void implCtx_free(void *hInternet){
	WinHttpCloseHandle((HINTERNET)hInternet);
}

int KSI_HttpClientImpl_init(KSI_HttpClient *http) {
	KSI_ERR err;
	int res;
	LPWSTR agent_name = NULL;
	HINTERNET session_handle = NULL;
	ULONG buf;

	KSI_PRE(&err, http != NULL) goto cleanup;
	KSI_BEGIN(http->parent.ctx, &err);

	if (http == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "HttpClient network client context not initialized.");
		goto cleanup;
	}

	res = LPWSTR_new(http->agentName, &agent_name);
	KSI_CATCH(&err, res) goto cleanup;
		
	//Initializes an application's use of the Win32 Internet functions. 
	session_handle = WinHttpOpen(agent_name, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (session_handle == NULL) {
		WINHTTP_ERROR(http->parent.ctx, GetLastError(), KSI_UNKNOWN_ERROR, "WinHTTP: Unable to init.");
	}
	
	buf = 1024;
	res = WinHttpSetOption(session_handle, WINHTTP_OPTION_MAX_CONNS_PER_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		WINHTTP_ERROR(http->parent.ctx, GetLastError(), KSI_UNKNOWN_ERROR, "WinHTTP: Unable to init.");
	}

	res = WinHttpSetOption(session_handle, WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		WINHTTP_ERROR(http->parent.ctx, GetLastError(), KSI_UNKNOWN_ERROR, "WinHTTP: Unable to init.");
	}
	
	http->implCtx = session_handle;
	http->implCtx_free = implCtx_free;
	session_handle = NULL;
	http->sendRequest = winhttpSendRequest;

	KSI_SUCCESS(&err);

cleanup:

	WinHttpCloseHandle(session_handle);
	LPWSTR_free(agent_name);
	
	return KSI_RETURN(&err);
}

#endif
