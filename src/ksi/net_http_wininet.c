#include "internal.h"

#if KSI_NET_HTTP_IMPL==KSI_IMPL_WININET

#include <windows.h>
#include <wininet.h>

#include "net_http_impl.h"
#include "net_impl.h"

static size_t wininetGlobal_initCount = 0;

/* Global internet handle for Wininet*/
static HINTERNET internet_handle = NULL;

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
} wininetNetHandleCtx;

static int wininetGlobal_init(void) {
	int res = KSI_UNKNOWN_ERROR;
	ULONG buf;
	
	if (wininetGlobal_initCount++ > 0) {
		/* Nothing to do */
		return KSI_OK;
	}
	
	//Initializes an application's use of the Win32 Internet functions. 
	internet_handle = InternetOpenA("TODO", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (internet_handle == NULL) {
		/*TODO res = map_impl(GetLastError());*/
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	
	/* By default WinINet allows just two simultaneous connections to one server. */
	buf = 1024;
	res = InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		res = KSI_HTTP_ERROR;
		goto cleanup;
	}
	res = InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		res = KSI_HTTP_ERROR;
		goto cleanup;
	}
	
	res = KSI_OK;

cleanup:

	return res;
}

static void wininetGlobal_cleanup(void) {
	if (--wininetGlobal_initCount > 0) {
		/* Nothing to do. */
		return;
	}
	
	if (internet_handle!= NULL){
		InternetCloseHandle(internet_handle);
		internet_handle = NULL;
	}
}

/**
 * Function for releasing KSI_NetHandle helper struct. 
 * Called by net.c -> KSI_RequestHandle_free   
 */
static void wininetNetHandleCtx_free(wininetNetHandleCtx *handleCtx) {
	if (handleCtx != NULL) {
		if(handleCtx->session_handle != NULL){
			InternetCloseHandle(handleCtx->session_handle);
			handleCtx->session_handle = NULL;
		}
		if(handleCtx->request_handle != NULL){
			InternetCloseHandle(handleCtx->request_handle);
			handleCtx->request_handle = NULL;
		}
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
	nhc->uc.dwStructSize = sizeof(nhc->uc);

	*handleCtx = nhc;
	nhc = NULL;
	
	res = KSI_OK;
	
cleanup:

	wininetNetHandleCtx_free(nhc);

return res;
}

/**
 * Sends request defined in handle and waits for response.
 * Response is written into handle.
 * 
 * \param[in/out] handle Pointer to KSI_RequestHandle object
 * 
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
static int wininetReceive(KSI_RequestHandle *handle) {
	KSI_ERR err;
	int res;
	wininetNetHandleCtx *nhc = NULL;
	const unsigned char *request = NULL;
	unsigned request_len = 0;
	unsigned char *resp = NULL;
	size_t resp_len = 0;
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
	if (!HttpSendRequestA(nhc->request_handle, NULL, 0, (LPVOID) request, request_len)) {
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "Wininet: Send error %i\n", error);

		if(error == ERROR_INTERNET_NAME_NOT_RESOLVED)
			KSI_FAIL(&err, KSI_INVALID_FORMAT, "Wininet: Invalid host name");
		else if(error == ERROR_INTERNET_CANNOT_CONNECT)
			KSI_FAIL(&err, KSI_NETWORK_ERROR, "Wininet: Unable to connect");
		else
			KSI_FAIL(&err, KSI_UNKNOWN_ERROR, NULL);
		goto cleanup;
	}

	/* Receive the response information. */
	if (!HttpQueryInfo(nhc->request_handle, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &http_response, &http_response_len, 0)) {
		DWORD error = GetLastError();
		if(error == ERROR_HTTP_HEADER_NOT_FOUND)
			KSI_FAIL(&err, KSI_HTTP_ERROR, "HTTP header not found");
		else if(error == ERROR_INSUFFICIENT_BUFFER)
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Wininet: Insufficient buffer");
		else
			KSI_FAIL(&err, KSI_UNKNOWN_ERROR, NULL);
		res = KSI_HTTP_ERROR;
		goto cleanup;
	}

	if(http_response >= 400){
		char err_msg[64];
		snprintf(err_msg, 64, "Http error %i.", http_response);
		KSI_FAIL(&err, KSI_HTTP_ERROR, err_msg);
		goto cleanup;
	}

	while (1) {
		DWORD add_len = 0x2000; /* Download in 8K increments. */
		resp = KSI_realloc(resp, resp_len + add_len);
		if (resp == NULL) {
			KSI_FAIL(&err,KSI_OUT_OF_MEMORY ,NULL);
			goto cleanup;
		}

		if (!InternetReadFile(nhc->request_handle, resp + resp_len, add_len, &add_len)) {
			DWORD error = GetLastError();
			if(error == ERROR_INSUFFICIENT_BUFFER)
				KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Wininet: Insufficient buffer");
			else
				KSI_FAIL(&err, KSI_UNKNOWN_ERROR, NULL);
			
			res = KSI_HTTP_ERROR;
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
	KSI_nofree(state);

	return KSI_RETURN(&err);
}


/**
 * Prepares request and opens a session handle.
 * 
 * \param handle Pointer to KSI_RequestHandle object.
 * \param agent
 * \param url Pointer to url string.
 * \param connectionTimeout Connection timeout.
 * \param readTimeout Read timeout.
 * 
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
static int wininetSendRequest(KSI_RequestHandle *handle, char *agent, char *url, int connectionTimeout, int readTimeout ) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL;
	const unsigned char *request = NULL;
	unsigned request_len = 0;
	wininetNetHandleCtx *nhc = NULL;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(KSI_RequestHandle_getCtx(handle), &err);

	/*Initializing of wininet helper struct*/
	res = wininetNetHandleCtx_new(&nhc);
	KSI_CATCH(&err, res) goto cleanup;
	ctx = KSI_RequestHandle_getCtx(handle);
	nhc->ctx = ctx;

	/*Cracking URL*/
	nhc->uc.dwHostNameLength = 1;
	nhc->uc.dwUrlPathLength = 1;
	nhc->uc.dwExtraInfoLength = 1;

	if (!InternetCrackUrlA(url, 0, 0, &(nhc->uc))) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Wininet: Unable to crack url");
		goto cleanup;
	}

	/*Extracting host name*/
	if (nhc->uc.lpszHostName == NULL || nhc->uc.dwHostNameLength == 0){
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Wininet: Invalid host name");
		goto cleanup;
	}
	
	nhc->hostName = KSI_malloc(nhc->uc.dwHostNameLength + 1);
	if (nhc->hostName == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	strncpy_s(nhc->hostName, nhc->uc.dwHostNameLength + 1, nhc->uc.lpszHostName, nhc->uc.dwHostNameLength);
	if (nhc->uc.lpszUrlPath == NULL || nhc->uc.dwUrlPathLength == 0) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Wininet: Invalid url path");
		goto cleanup;
	}

	/*Extracting query string*/
	nhc->query = KSI_malloc(nhc->uc.dwUrlPathLength + nhc->uc.dwExtraInfoLength + 1);
	if (nhc->query == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	strncpy_s(nhc->query, nhc->uc.dwUrlPathLength + 1, nhc->uc.lpszUrlPath, nhc->uc.dwUrlPathLength);
	if (!(nhc->uc.lpszExtraInfo == NULL || nhc->uc.dwExtraInfoLength == 0)) {
		strncpy_s(nhc->query + nhc->uc.dwUrlPathLength, nhc->uc.dwExtraInfoLength + 1, nhc->uc.lpszExtraInfo, nhc->uc.dwExtraInfoLength);
	}
	
	/*Preparing request*/

	KSI_LOG_debug(ctx, "Wininet: Sending request to: %s", url);

	res = KSI_RequestHandle_getRequest(handle, &request, &request_len);
	KSI_CATCH(&err, res) goto cleanup;

	if (request_len > LONG_MAX) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Wininet: Request too long");
		goto cleanup;
	}

	res = KSI_RequestHandle_setReadResponseFn(handle, wininetReceive);
	KSI_CATCH(&err, res) goto cleanup;

	/*Preparing session handle*/
	//Opens an HTTP session for a given site
	nhc->session_handle = InternetConnectA(internet_handle, nhc->hostName, nhc->uc.nPort, NULL, NULL, nhc->uc.nScheme, 0, 0);
	if (nhc->session_handle == NULL) {
		KSI_FAIL(&err, KSI_NETWORK_ERROR, "Wininet: Unable to init connection handle");
		goto cleanup;
	}
	
	/*Preparing HTTP request handle*/
	/*Should it use:
	 INTERNET_FLAG_RELOAD
	 INTERNET_FLAG_NO_CACHE_WRITE
	 */
	nhc->request_handle = HttpOpenRequestA(nhc->session_handle,
		(request == NULL ? "GET" : "POST"),
		nhc->query, NULL, NULL, NULL,
		(nhc->uc.nScheme == INTERNET_SCHEME_HTTPS ? INTERNET_FLAG_SECURE : 0),
		0);

	if(nhc->request_handle == NULL){
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "Wininet: Open request error %i\n", error);
		KSI_FAIL(&err, KSI_NETWORK_ERROR, "Wininet: Unable to init request handle");
		goto cleanup;
	}
	
	if (connectionTimeout >= 0) {
		DWORD dw = (connectionTimeout == 0 ? 0xFFFFFFFF : connectionTimeout * 1000);
		InternetSetOption(nhc->request_handle, INTERNET_OPTION_CONNECT_TIMEOUT, &dw, sizeof(dw));
	}
	if (readTimeout >= 0) {
		DWORD dw = (readTimeout == 0 ? 0xFFFFFFFF : readTimeout * 1000);
		InternetSetOption(nhc->request_handle, INTERNET_OPTION_SEND_TIMEOUT, &dw, sizeof(dw));
		InternetSetOption(nhc->request_handle, INTERNET_OPTION_RECEIVE_TIMEOUT, &dw, sizeof(dw));
	}

    res = KSI_RequestHandle_setNetContext(handle, nhc, (void (*)(void *))wininetNetHandleCtx_free);
    KSI_CATCH(&err, res) goto cleanup;

    nhc = NULL;
	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(request);
	KSI_nofree(state);

	wininetNetHandleCtx_free(nhc);

	return KSI_RETURN(&err);
}

int KSI_HttpClient_init(KSI_NetworkClient *client) {
	KSI_ERR err;
	KSI_HttpClientCtx *http = NULL;
	int res;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	http = client->poviderCtx;
	if (http == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "HttpClient network client context not initialized.");
		goto cleanup;
	}

	http->sendRequest = wininetSendRequest;

	/* Register global init and cleanup methods. */
	res = KSI_CTX_registerGlobals(client->ctx, wininetGlobal_init, wininetGlobal_cleanup);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);

}

#endif
