#ifdef _WIN32
#	include <windows.h>
#	include <wininet.h>
#endif

#include "internal.h"
#include "net_http.h"

#ifndef NETPROVIDER_WININET
#	ifndef NETPROVIDER_CURL
#		ifndef NETPROVIDER_WINHTTP
#			ifdef _WIN32
#				define NETPROVIDER_WININET
#			endif
#		endif
#	endif
#endif

#ifdef NETPROVIDER_WININET
static size_t wininetGlobal_initCount = 0;

/* Global internet handle for Wininet*/
static HINTERNET internet_handle = NULL;

typedef struct wininetNetProviderCtx_st {
	int connectionTimeoutSeconds;
	int readTimeoutSeconds;
	char *urlSigner;
	char *urlExtender;
	char *urlPublication;
} wininetNetProviderCtx;

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

	KSI_nofree(nhc);

return res;
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

static int wininetNetProviderCtx_new(wininetNetProviderCtx **providerCtx) {
	wininetNetProviderCtx *pctx = NULL;
	int res;

	pctx = KSI_new (wininetNetProviderCtx);
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
static void wininetNetProviderCtx_free(wininetNetProviderCtx *providerCtx) {
	if (providerCtx != NULL) {
		KSI_free(providerCtx->urlExtender);
		KSI_free(providerCtx->urlPublication);
		KSI_free(providerCtx->urlSigner);
		KSI_free(providerCtx);
	}
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
//TODO:error control
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

IMPL_SIGN_REQUEST(wininet)
IMPL_EXTEND_REQUEST(wininet)
IMPL_PUBLICATIONSFILE_REQUEST(wininet)


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

int KSI_HttpClient_new(KSI_CTX *ctx, KSI_NetworkClient **netProvider) {
	KSI_ERR err;
	KSI_NetworkClient *pr = NULL;
	wininetNetProviderCtx *pctx = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	/* Register global init and cleanup methods. */
	res = KSI_CTX_registerGlobals(ctx, wininetGlobal_init, wininetGlobal_cleanup);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_NetworkClient_new(ctx, &pr);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetworkClient_setSendSignRequestFn(pr, wininetSendSignRequest);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetworkClient_setSendExtendRequestFn(pr, wininetSendExtendRequest);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetworkClient_setSendPublicationRequestFn(pr, wininetSendPublicationsFileRequest);
	KSI_CATCH(&err, res) goto cleanup;

	res = wininetNetProviderCtx_new(&pctx);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetworkClient_setNetCtx(pr, pctx, (void (*)(void*))wininetNetProviderCtx_free);
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
	wininetNetProviderCtx_free(pctx);

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
			wininetNetProviderCtx *pctx = NULL;															\
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