#ifdef _WIN32
#	include <windows.h>
#	include <Winhttp.h>
#endif

#include "internal.h"
#include "net_http.h"


#ifdef NETPROVIDER_WINHTTP
static size_t winhttpGlobal_initCount = 0;
/* Global internet handle for Wininet*/
/*tegelikult peaks olema session, connect ja rquest handelid*/
static HINTERNET session_handle = NULL;

typedef struct winhttpNetProviderCtx_st {
	int connectionTimeoutSeconds;
	int readTimeoutSeconds;
	char *urlSigner;
	char *urlExtender;
	char *urlPublication;
} winhttpNetProviderCtx;

typedef struct winhttpNetHandleCtx_st {
	KSI_CTX *ctx;
	/*A internet handle object for handling a HTTP session*/
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

static int winhttpNetHandleCtx_new(winhttpNetHandleCtx **handleCtx){
	winhttpNetHandleCtx *nhc = NULL;
	int res = KSI_UNKNOWN_ERROR;
	
	nhc = KSI_new(winhttpNetHandleCtx);
	if (nhc == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	nhc->ctx = NULL;
	nhc->connection_handle = NULL;
	nhc->request_handle = NULL;
	nhc->hostName = NULL;
	nhc->query = NULL;
	nhc->uc.dwStructSize = sizeof(nhc->uc);

	*handleCtx = nhc;
	nhc = NULL;
	
	res = KSI_OK;
	
cleanup:

	KSI_nofree(nhc);

return res;
}

/**
 * Function for releasing KSI_NetHandle helper struct. 
 * Called by net.c -> KSI_RequestHandle_free   
 */
static void winhttpNetHandleCtx_free(winhttpNetHandleCtx *handleCtx) {
	if (handleCtx != NULL) {
		if(handleCtx->connection_handle != NULL){
			WinHttpCloseHandle(handleCtx->connection_handle);
			handleCtx->connection_handle = NULL;
			}
		if(handleCtx->request_handle != NULL){
			WinHttpCloseHandle(handleCtx->request_handle);
			handleCtx->request_handle = NULL;
			}
		
		KSI_free(handleCtx->hostName);
		KSI_free(handleCtx->query);
		KSI_free(handleCtx);
		
	}
}

static int winhttpNetProviderCtx_new(winhttpNetProviderCtx **providerCtx) {
	winhttpNetProviderCtx *pctx = NULL;
	int res;

	pctx = KSI_new (winhttpNetProviderCtx);
	if (pctx == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	pctx->connectionTimeoutSeconds = 0;
	pctx->readTimeoutSeconds = 0;
	pctx->urlSigner = NULL;
	pctx->urlPublication = NULL;
	pctx->urlExtender = NULL;

	*providerCtx = pctx;
	pctx = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(pctx);

	return res;
}

/**
 * Function for releasing KSI_NetworkClient helper struct. 
 * Called by net.c -> KSI_NetworkClient_free   
 */
static void winhttpNetProviderCtx_free(winhttpNetProviderCtx *providerCtx) {
	if (providerCtx != NULL) {
		KSI_free(providerCtx->urlExtender);
		KSI_free(providerCtx->urlPublication);
		KSI_free(providerCtx->urlSigner);
		KSI_free(providerCtx);
	}
}


static LPWSTR LPWSTR_new(const char * cstr){
	int lenInChars =0;
	wchar_t * p_wchar = NULL;
	//Get chracater count.
	lenInChars = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, cstr, -1, NULL,0);
	p_wchar = (wchar_t *)malloc(lenInChars*sizeof(wchar_t));
	if(p_wchar == NULL) return NULL;
	MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, cstr, -1, p_wchar,lenInChars);
	return p_wchar;
	}

static void LPWSTR_free(LPWSTR wstr){
	free(wstr);
	}



/**
 * Sends request defined in handle and waits for response.
 * Response is written into handle.
 * 
 * \param[in/out] handle Pointer to KSI_RequestHandle object
 * 
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
static int winhttpReceive(KSI_RequestHandle *handle) {
	KSI_ERR err;
	int res;
	winhttpNetHandleCtx *nhc = NULL;
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
	if (!WinHttpSendRequest(nhc->request_handle, WINHTTP_NO_ADDITIONAL_HEADERS,0, (LPVOID) request, request_len, request_len,0)) {
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "Winhttp send error %i\n", error);

		if(error = ERROR_WINHTTP_CANNOT_CONNECT)
			KSI_FAIL(&err, KSI_NETWORK_ERROR, "Winhttp: Unable to connect");
		else
			KSI_FAIL(&err, KSI_NETWORK_ERROR, NULL);
		goto cleanup;
		}

	if(!WinHttpReceiveResponse(nhc->request_handle, NULL)){
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "Winhttp: Receive error %i\n", error);

		KSI_FAIL(&err, KSI_NETWORK_ERROR, NULL);
		goto cleanup;
		}
	
	/* Receive the response information. */
	if (!WinHttpQueryHeaders(nhc->request_handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &http_response, &http_response_len, 0)) {
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "Winhttp: Query error %i\n", error);
		
		if(error == ERROR_INSUFFICIENT_BUFFER)
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Insufficient buffer");
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

		if (!WinHttpReadData(nhc->request_handle, resp + resp_len, add_len, &add_len)) {
			DWORD error = GetLastError();
			KSI_LOG_debug(ctx, "Winhttp: Read data error %i\n", error);

			if(error == ERROR_INSUFFICIENT_BUFFER)
				KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Insufficient buffer");
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
 * Prepares request a opens a session handle.
 * 
 * \param handle Pointer to KSI_RequestHandle object.
 * \param agent
 * \param url Pointer to url string.
 * \param connectionTimeout Connection timeout.
 * \param readTimeout Read timeout.
 * 
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
static int winhttpSendRequest(KSI_RequestHandle *handle, char *agent, char *url, int connectionTimeout, int readTimeout ) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL;
	const unsigned char *request = NULL;
	unsigned request_len = 0;
	winhttpNetHandleCtx *nhc = NULL;
	LPWSTR w_url = NULL;
	
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(KSI_RequestHandle_getCtx(handle), &err);

		
	
	/*Initializing of winhttp helper struct*/
	res = winhttpNetHandleCtx_new(&nhc);
	KSI_CATCH(&err, res) goto cleanup;
	ctx = KSI_RequestHandle_getCtx(handle);
	nhc->ctx = ctx;

	/*Cracking URL*/
	nhc->uc.dwHostNameLength = 1;
	nhc->uc.dwUrlPathLength = 1;
	nhc->uc.dwExtraInfoLength = 1;
	w_url = LPWSTR_new(url);
	if (!WinHttpCrackUrl(w_url, 0, 0, &(nhc->uc))) {
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "Winhttp: Crack url error %i\n", error);
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Winhttp: Unable to crack url");
		goto cleanup;
		}

	/*Extracting host name*/
	if (nhc->uc.lpszHostName == NULL || nhc->uc.dwHostNameLength == 0){
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Winhttp: Invalid host name");
		goto cleanup;
		}

	nhc->hostName = KSI_malloc(nhc->uc.dwHostNameLength*10 + 1);
	if (nhc->hostName == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
		}

	wcsncpy_s(nhc->hostName, nhc->uc.dwHostNameLength + 1, nhc->uc.lpszHostName, nhc->uc.dwHostNameLength);
	if (nhc->uc.lpszUrlPath == NULL || nhc->uc.dwUrlPathLength == 0) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Winhttp: Invalid url path");
		goto cleanup;
	}

	/*Extracting query string*/
	nhc->query = KSI_malloc((nhc->uc.dwUrlPathLength + nhc->uc.dwExtraInfoLength)*10 + 1);
	if (nhc->query == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
		}

	wcsncpy_s(nhc->query, nhc->uc.dwUrlPathLength + 1, nhc->uc.lpszUrlPath, nhc->uc.dwUrlPathLength);
	if (!(nhc->uc.lpszExtraInfo == NULL || nhc->uc.dwExtraInfoLength == 0)) {
		wcsncpy_s(nhc->query + nhc->uc.dwUrlPathLength, nhc->uc.dwExtraInfoLength + 1, nhc->uc.lpszExtraInfo, nhc->uc.dwExtraInfoLength);
		}

	/*Preparing request*/
	KSI_LOG_debug(ctx, "Winhttp: Sending request to: %s", url);

	res = KSI_RequestHandle_getRequest(handle, &request, &request_len);
	KSI_CATCH(&err, res) goto cleanup;

	if (request_len > LONG_MAX) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Winhttp: Request too long");
		goto cleanup;
	}

	res = KSI_RequestHandle_setReadResponseFn(handle, winhttpReceive);
	KSI_CATCH(&err, res) goto cleanup;

	/*Preparing session handle. Opens an HTTP session for a given site*/
	nhc->connection_handle = WinHttpConnect(session_handle, nhc->hostName, nhc->uc.nPort, 0);
	if (nhc->connection_handle == NULL) {
		//error koodid http://msdn.microsoft.com/en-us/library/windows/desktop/aa384091%28v=vs.85%29.aspx
		KSI_FAIL(&err, KSI_NETWORK_ERROR, "Winhttp: Unable to init connection handle");
		goto cleanup;
		}

	/*Preparing HTTP request handle*/
	/*Should it use:
	 INTERNET_FLAG_RELOAD
	 INTERNET_FLAG_NO_CACHE_WRITE
	 */
	
	nhc->request_handle = WinHttpOpenRequest(nhc->connection_handle,
			(request == NULL ? L"GET" : L"POST"),
			nhc->query, 
			NULL, NULL, NULL,0);
	
	if(nhc->request_handle == NULL){
		DWORD error = GetLastError();
		KSI_LOG_debug(ctx, "Winhttp: Open request error %i\n", error);
		KSI_FAIL(&err, KSI_NETWORK_ERROR, "Wininet: Unable to init request handle");
		goto cleanup;
		}
	
	//error codes http://msdn.microsoft.com/en-us/library/windows/desktop/aa384099%28v=vs.85%29.aspx
	/*
	if (connectionTimeout >= 0) {
		DWORD dw = (connectionTimeout == 0 ? 0xFFFFFFFF : connectionTimeout * 1000);
		WinHttpSetOption(nhc->request_handle, INTERNET_OPTION_CONNECT_TIMEOUT, &dw, sizeof(dw));
	}
	if (readTimeout >= 0) {
		DWORD dw = (readTimeout == 0 ? 0xFFFFFFFF : readTimeout * 1000);
		WinHttpSetOption(nhc->request_handle, INTERNET_OPTION_SEND_TIMEOUT, &dw, sizeof(dw));
		WinHttpSetOption(nhc->request_handle, INTERNET_OPTION_RECEIVE_TIMEOUT, &dw, sizeof(dw));
	}
*/
	
    res = KSI_RequestHandle_setNetContext(handle, nhc, (void (*)(void *))winhttpNetHandleCtx_free);
    KSI_CATCH(&err, res) goto cleanup;

    nhc = NULL;
	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(request);
	KSI_nofree(state);
	
	LPWSTR_free(w_url);
	
	winhttpNetHandleCtx_free(nhc);

	return KSI_RETURN(&err);
}


#define IMPL_X_REQUEST(providerName, requestType, urlName)																	\
	static int providerName##Send##requestType##Request(KSI_NetworkClient *netProvider, KSI_RequestHandle *handle){				\
		providerName##NetProviderCtx *npc = NULL;																				\
		int res;																												\
		res = KSI_NetworkClient_getNetContext(netProvider, (void **)&npc);														\
		if (res != KSI_OK) goto cleanup;																						\
		res = providerName##SendRequest(handle, "TODO", npc->urlName, npc->connectionTimeoutSeconds, npc->readTimeoutSeconds);	\
		if (res != KSI_OK) goto cleanup;																						\
		res = KSI_OK;																											\
	cleanup:																													\
		return res;																												\
	}																							

#define IMPL_SIGN_REQUEST(providerName) IMPL_X_REQUEST(providerName, Sign, urlSigner)
#define IMPL_EXTEND_REQUEST(providerName) IMPL_X_REQUEST(providerName, Extend, urlExtender)
#define IMPL_PUBLICATIONSFILE_REQUEST(providerName) IMPL_X_REQUEST(providerName, PublicationsFile, urlPublication)

IMPL_SIGN_REQUEST(winhttp)
IMPL_EXTEND_REQUEST(winhttp)
IMPL_PUBLICATIONSFILE_REQUEST(winhttp)


static int winhttpGlobal_init(void) {
	int res = KSI_UNKNOWN_ERROR;
	ULONG buf;

	if (winhttpGlobal_initCount++ > 0) {
		/* Nothing to do */
		return KSI_OK;
		}
	
	//Initializes an application's use of the Win32 Internet functions. 
	session_handle = WinHttpOpen(L"TODO", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
	if (session_handle == NULL) {
		/*TODO res = map_impl(GetLastError());*/
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	/* By default WinINet allows just two simultaneous connections to one server. */
	
	buf = 1024;
	res = WinHttpSetOption(session_handle, WINHTTP_OPTION_MAX_CONNS_PER_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		res = KSI_HTTP_ERROR;
		goto cleanup;
	}

	res = WinHttpSetOption(session_handle, WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER, &buf, sizeof(buf));
	if (res != TRUE) {
		res = KSI_HTTP_ERROR;
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

static void winhttpGlobal_cleanup(void) {
	if (--winhttpGlobal_initCount > 0) {
		/* Nothing to do. */
		return;
		}
	
	if (session_handle!= NULL){
		WinHttpCloseHandle(session_handle);
		session_handle = NULL;
		}
}

int KSI_HttpClient_new(KSI_CTX *ctx, KSI_NetworkClient **netProvider) {
	KSI_ERR err;
	KSI_NetworkClient *pr = NULL;
	winhttpNetProviderCtx *pctx = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	/* Register global init and cleanup methods. */
	res = KSI_CTX_registerGlobals(ctx, winhttpGlobal_init, winhttpGlobal_cleanup);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_NetworkClient_new(ctx, &pr);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetworkClient_setSendSignRequestFn(pr, winhttpSendSignRequest);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetworkClient_setSendExtendRequestFn(pr, winhttpSendExtendRequest);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetworkClient_setSendPublicationRequestFn(pr, winhttpSendPublicationsFileRequest);
	KSI_CATCH(&err, res) goto cleanup;

	res = winhttpNetProviderCtx_new(&pctx);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetworkClient_setNetCtx(pr, pctx, (void (*)(void*))winhttpNetProviderCtx_free);
	KSI_CATCH(&err, res) goto cleanup;
	pctx = NULL;

	res = KSI_HttpClient_setSignerUrl(pr, KSI_DEFAULT_URI_AGGREGATOR);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HttpClient_setExtenderUrl(pr, KSI_DEFAULT_URI_EXTENDER);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HttpClient_setPublicationUrl(pr, KSI_DEFAULT_URI_PUBLICATIONS_FILE);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HttpClient_setReadTimeoutSeconds(pr, 5);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HttpClient_setConnectTimeoutSeconds(pr, 5);
	KSI_CATCH(&err, res) goto cleanup;

	*netProvider = pr;
	pr = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetworkClient_free(pr);
	winhttpNetProviderCtx_free(pctx);

	return KSI_RETURN(&err);
}

static int setStringParam(char **param, char *urlSigner) {
	char *val = NULL;
	int res = KSI_UNKNOWN_ERROR;


	val = KSI_calloc(strlen(urlSigner) + 1, 1);
	if (val == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	memcpy(val, urlSigner, strlen(urlSigner) + 1);

	if (*param != NULL) {
		KSI_free(*param);
	}

	*param = val;
	val = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(pctx);
	KSI_free(val);

	return res;
}

static int setIntParam(int *param, int val) {
	*param = val;
	return KSI_OK;
}

#define KSI_NET_WININET_SETTER(name, type, var, fn) 														\
		int KSI_HttpClient_set##name(KSI_NetworkClient *client, type val) {								\
			int res = KSI_UNKNOWN_ERROR;																\
			winhttpNetProviderCtx *pctx = NULL;															\
			if (client == NULL) {																		\
				res = KSI_INVALID_ARGUMENT;																\
				goto cleanup;																			\
			}																							\
			res = KSI_NetworkClient_getNetContext(client, (void **)&pctx);								\
			if (res != KSI_OK) goto cleanup;															\
			res = (fn)(&pctx->var, val);																\
		cleanup:																						\
			return res;																					\
		}																								\

KSI_NET_WININET_SETTER(SignerUrl, char *, urlSigner, setStringParam);
KSI_NET_WININET_SETTER(ExtenderUrl, char *, urlExtender, setStringParam);
KSI_NET_WININET_SETTER(PublicationUrl, char *, urlPublication, setStringParam);
KSI_NET_WININET_SETTER(ConnectTimeoutSeconds, int, connectionTimeoutSeconds, setIntParam);
KSI_NET_WININET_SETTER(ReadTimeoutSeconds, int, readTimeoutSeconds, setIntParam);

#endif
