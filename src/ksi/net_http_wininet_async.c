/*
 * Copyright 2013-2017 Guardtime, Inc.
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

#pragma comment(lib, "wininet.lib")

#include "tlv.h"
#include "fast_tlv.h"

#include "impl/net_http_impl.h"
#include "impl/net_impl.h"



typedef struct WinAsyncReq_st WinAsyncReq;

KSI_DEFINE_LIST(WinAsyncReq);
#define WinAsyncReqList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define WinAsyncReqList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define WinAsyncReqList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define WinAsyncReqList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define WinAsyncReqList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define WinAsyncReqList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define WinAsyncReqList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define WinAsyncReqList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define WinAsyncReqList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

typedef struct {
	KSI_CTX *ctx;

	/* For keeping track of the global critical section initilialization state. */
	bool criticalSecInitialized;
	/* Session handle. */
	HINTERNET sessionHandle;
	/* Connect handle. */
	HINTERNET connectHandle;

	/* Output queue. */
	KSI_LIST(KSI_AsyncHandle) *reqQueue;
	/* Pending in WinINet API queue. */
	KSI_LIST(WinAsyncReq) *httpQueue;
	/* Input queue. */
	KSI_LIST(KSI_OctetString) *respQueue;

	/* HTTP header fields. */
	char *userAgent;
	char *mimeType;

	/* Round throttling. */
	time_t roundStartAt;
	size_t roundCount;

	/* Poiter to the async options. */
	size_t *options;

	/* Endpoint data. */
	char *ksi_user;
	char *ksi_pass;
	char *host;
	char *path;
	int port;
	bool isSecure;
} HttpAsyncCtx;

struct WinAsyncReq_st {
	/* WinINet request handle. */
	HINTERNET requestHandle;

	/* KSI context. */
	KSI_CTX *ctx;

	/* Request context. */
	KSI_AsyncHandle *reqCtx;
	/* Receive buffer. */
	unsigned char *raw;
	size_t len;
	bool dataComplete;
	bool dataRcving;
	DWORD contentLen;

	/* Synchronization event for resource cleanup. */
	HANDLE closedEvent;
	/* Status handling. */
	bool reqComplete;
	int status;
	DWORD errExt;
};

/* Global lock for resource use synchronization. */
static CRITICAL_SECTION CriticalSection;
static int csCount = 0;

static void WinAsyncReq_free(WinAsyncReq *o) {
	if (o != NULL) {
		EnterCriticalSection(&CriticalSection);
			if (o->requestHandle) InternetCloseHandle(o->requestHandle);
			o->requestHandle = NULL;
		LeaveCriticalSection(&CriticalSection);

		if (o->closedEvent) {
			WaitForSingleObject(o->closedEvent, INFINITE);
			CloseHandle(o->closedEvent);
		}
		KSI_AsyncHandle_free(o->reqCtx);
		KSI_free(o->raw);

		KSI_free(o);
	}
}

static int WinAsyncReq_new(KSI_CTX *ctx, WinAsyncReq **o) {
	int res = KSI_UNKNOWN_ERROR;
	WinAsyncReq *tmp = NULL;

	if (ctx == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(WinAsyncReq);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->reqCtx = NULL;
	tmp->requestHandle = NULL;
	tmp->len = 0;
	tmp->raw = NULL;
	tmp->dataComplete = false;
	tmp->dataRcving = false;
	tmp->contentLen = 0;

	tmp->closedEvent = NULL;

	tmp->reqComplete = false;
	tmp->status = KSI_ASYNC_NOT_FINISHED;
	tmp->errExt = 0;

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	WinAsyncReq_free(tmp);
	return res;
}

KSI_IMPLEMENT_LIST(WinAsyncReq, WinAsyncReq_free);

/*#define KSI_DEBUG_WININET_STATUS_CALLBACK*/
#ifdef KSI_DEBUG_WININET_STATUS_CALLBACK

#define WININET_STATUS_CALLBACK_LIST\
	_(CLOSING_CONNECTION   )\
	_(CONNECTED_TO_SERVER  )\
	_(CONNECTING_TO_SERVER )\
	_(CONNECTION_CLOSED	   )\
	_(COOKIE_HISTORY	   )\
	_(COOKIE_RECEIVED	   )\
	_(COOKIE_SENT          )\
	_(CTL_RESPONSE_RECEIVED)\
	_(DETECTING_PROXY	   )\
	_(HANDLE_CLOSING	   )\
	_(HANDLE_CREATED	   )\
	_(INTERMEDIATE_RESPONSE)\
	_(NAME_RESOLVED		   )\
	_(P3P_HEADER		   )\
	_(P3P_POLICYREF		   )\
	_(PREFETCH			   )\
	_(PRIVACY_IMPACTED	   )\
	_(RECEIVING_RESPONSE   )\
	_(REDIRECT			   )\
	_(REQUEST_COMPLETE	   )\
	_(REQUEST_SENT		   )\
	_(RESOLVING_NAME	   )\
	_(RESPONSE_RECEIVED	   )\
	_(SENDING_REQUEST	   )\
	_(STATE_CHANGE		   )\


static char *WinINetCallbackStatus_toString(DWORD status) {
	switch (status) {
#define _(sta) case INTERNET_STATUS_##sta: return #sta;
		WININET_STATUS_CALLBACK_LIST
#undef _
		default: return "UNKNOWN";
	}
}

#endif

static void CALLBACK WinINet_asyncCallback(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus,
			LPVOID lpvStatusInformation, DWORD dwStatusInformationLength) {

	EnterCriticalSection(&CriticalSection);

	UNREFERENCED_PARAMETER(hInternet);
	UNREFERENCED_PARAMETER(dwStatusInformationLength);

	if ((void*)dwContext != NULL) {
		DWORD dwError = ERROR_SUCCESS;
		WinAsyncReq *request = (WinAsyncReq*)dwContext;

#ifdef KSI_DEBUG_WININET_STATUS_CALLBACK
		KSI_LOG_debug(request->ctx, "Async WinINet: request %p: thread %d: status %d (%s)", request, GetCurrentThreadId(), dwInternetStatus, WinINetCallbackStatus_toString(dwInternetStatus));
#endif
		switch (dwInternetStatus) {

			/* INTERNET_STATUS_REQUEST_COMPLETE
			 *   An asynchronous operation has been completed.
			 *   The lpvStatusInformation parameter contains the address of an INTERNET_ASYNC_RESULT structure:
			 *     dwResult - Boolean return code from the asynchronous function.
			 *     dwError - Error code, if dwResult indicates that the function failed. If the operation succeeded, this member usually contains ERROR_SUCCESS.
			 */
			case INTERNET_STATUS_REQUEST_COMPLETE: {
					LPINTERNET_ASYNC_RESULT asyncResult = (LPINTERNET_ASYNC_RESULT)lpvStatusInformation;
					DWORD infoLen = sizeof(DWORD);
					DWORD httpStatus = 0;
					BYTE rcvBuff[2048];

					if (request->status != KSI_ASYNC_NOT_FINISHED) {
						KSI_LOG_debug(request->ctx, "Async WinINet: %p Request has completed.", request);
						goto cleanup;
					}

					if (!asyncResult->dwResult) {
						dwError = asyncResult->dwError;
						goto cleanup;
					}

					/* Get the HTTP status code. */
					if (!HttpQueryInfo(request->requestHandle, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
							&httpStatus, &infoLen, 0)) {
						KSI_LOG_error(request->ctx, "Async WinINet: Unable to get HTTP status. Error %d", (dwError = GetLastError()));
						goto cleanup;
					}

					if (httpStatus >= 400 && httpStatus < 600) {
						KSI_LOG_error(request->ctx, "Async WinINet: received HTTP code %d.", httpStatus);
						request->status = KSI_HTTP_ERROR;
						request->errExt = httpStatus;
						/* We are finished with the request. Close handle and wait for INTERNET_STATUS_HANDLE_CLOSING. */
						InternetCloseHandle(request->requestHandle);
						request->requestHandle = NULL;
						goto cleanup;
					}

					for (;;) {
						INTERNET_BUFFERS ib = { sizeof(INTERNET_BUFFERS) };
						unsigned char *tmp_buffer = NULL;

						ib.Next           = NULL;
						ib.lpvBuffer      = rcvBuff;
						ib.dwBufferLength = sizeof(rcvBuff);

						if (!InternetReadFileEx(request->requestHandle, &ib, IRF_ASYNC | IRF_USE_CONTEXT, (LPARAM)dwContext)) {
							dwError = GetLastError();
							if (dwError == ERROR_IO_PENDING) {
								/* Wait for INTERNET_STATUS_REQUEST_COMPLETE.  */
								KSI_LOG_debug(request->ctx, "Async WinINet: %p IO pending.", request);
							} else {
								KSI_LOG_error(request->ctx, "Async WinINet: Unable to read data. Error %d.", dwError);
							}
							goto cleanup;
						}

						if (ib.dwBufferLength == 0) break;

						tmp_buffer = KSI_calloc(ib.dwBufferLength + request->len, sizeof(unsigned char));
						if (tmp_buffer == NULL) {
							request->status = KSI_OUT_OF_MEMORY;
							/* We are finished with the request. Close handle and wait for INTERNET_STATUS_HANDLE_CLOSING. */
							InternetCloseHandle(request->requestHandle);
							request->requestHandle = NULL;
							goto cleanup;
						}
						memcpy(tmp_buffer, request->raw, request->len);
						memcpy(tmp_buffer + request->len, ib.lpvBuffer, ib.dwBufferLength);

						KSI_free(request->raw);
						request->raw = tmp_buffer;
						request->len += ib.dwBufferLength;
						tmp_buffer = NULL;

						KSI_LOG_debug(request->ctx, "Async WinINet: %p Received %lu bytes (%lu total)",
								request, ib.dwBufferLength, request->len);
					}

					KSI_LOG_debug(request->ctx, "Async WinINet: %p Complete (%lu bytes received)", request, request->len);

					request->dataRcving = false;
					request->dataComplete = true;
					request->status = KSI_OK;
					/* Close request handle and wait for INTERNET_STATUS_HANDLE_CLOSING. */
					InternetCloseHandle(request->requestHandle);
					request->requestHandle = NULL;
				}
				break;

			/* INTERNET_STATUS_HANDLE_CLOSING
			 *   This handle value has been terminated.
			 *   The lpvStatusInformation parameter contains the address of the handle being closed.
			 */
			case INTERNET_STATUS_HANDLE_CLOSING:
				/* Garanteed last callback this context will ever receive. */
				request->reqComplete = true;
				/* Now it is save to free the context. */
				SetEvent(request->closedEvent);
				break;

			default:
				/* Do nothing. We do not care about other statuses. */
				goto cleanup;
		}

cleanup:
		if (dwError != ERROR_SUCCESS && dwError != ERROR_IO_PENDING) {
			KSI_LOG_error(request->ctx, "Async WinINet: %p Status %d: Error %d.", request, dwInternetStatus, dwError);
			/* Set error. */
			request->status = KSI_NETWORK_ERROR;
			request->errExt = dwError;
			/* Close handle and wait for INTERNET_STATUS_HANDLE_CLOSING. */
			if (request->requestHandle) {
				InternetCloseHandle(request->requestHandle);
				request->requestHandle = NULL;
			}
		}
	}

	LeaveCriticalSection(&CriticalSection);
}

static void reqQueue_clearWithError(KSI_AsyncHandleList *reqQueue, int err, long ext) {
	size_t size = 0;

	if (reqQueue == NULL) return;

	while ((size = KSI_AsyncHandleList_length(reqQueue)) > 0) {
		int res;
		KSI_AsyncHandle *req = NULL;

		res = KSI_AsyncHandleList_elementAt(reqQueue, size - 1, &req);
		if (res != KSI_OK || req == NULL) return;

		/* Update request state. */
		req->state = KSI_ASYNC_STATE_ERROR;
		req->err = err;
		req->errExt = ext;

		KSI_AsyncHandle_free(req);
	}
}

static int WinINet_init(HttpAsyncCtx *clientCtx) {
	int res = KSI_UNKNOWN_ERROR;
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;
	DWORD opt = 0;
	DWORD optSize = sizeof(DWORD);

	if (clientCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}


	/* Obtain session handle. */
	hSession = InternetOpen(clientCtx->userAgent,
			INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL,
			INTERNET_FLAG_ASYNC);
	if (hSession == NULL) {
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}


	/* Set timeouts (in millisec). Only set connect timeout, as other timeouts are handled internally. */
	opt = (DWORD)clientCtx->options[KSI_ASYNC_OPT_CON_TIMEOUT] * 1000 * 2;
	if (!InternetSetOption(hSession, INTERNET_OPTION_CONNECT_TIMEOUT, &opt, sizeof(opt))) {
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	/* Obtain connect handle. */
	hConnect = InternetConnect(hSession, clientCtx->host, (INTERNET_PORT)clientCtx->port,
			NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (hConnect == NULL) {
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	/* Set status callback. */
	if (InternetSetStatusCallback(hConnect, WinINet_asyncCallback) == INTERNET_INVALID_STATUS_CALLBACK)	{
		KSI_LOG_error(clientCtx->ctx, "Async WinINet: Unable to set callback. Error %d", GetLastError());
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	/* Limit the total amount of connections.
	 * WinInet limits connections to a single HTTP 1.0 server to four simultaneous connections.
	 * Connections to a single HTTP 1.1 server are limited to two simultaneous connections.
	 * The only evidence of this limitation to your application is that calls such as HttpSendRequest
	 * appear to take longer to complete because they wait for previous connections to be freed up
	 * before their requests are sent.
	 */
	/* However, it seems that the max possible value is set to 128, regardles of the requested value. */
	opt = (DWORD)clientCtx->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE];
	if (!InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_SERVER, (LPVOID)&opt, optSize) ||
			!InternetSetOption(NULL, INTERNET_OPTION_MAX_CONNS_PER_1_0_SERVER, (LPVOID)&opt, optSize)) {
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	clientCtx->sessionHandle = hSession;
	hSession = NULL;
	clientCtx->connectHandle = hConnect;
	hConnect = NULL;

	res = KSI_OK;
cleanup:
	if (hSession != NULL) InternetCloseHandle(hSession);
	if (hConnect != NULL) InternetCloseHandle(hConnect);

	return res;
}

static int WinINet_sendRequest(HttpAsyncCtx *clientCtx, KSI_AsyncHandle *req, DWORD *error) {
	int res = KSI_UNKNOWN_ERROR;
	WinAsyncReq *httpReq = NULL;
	bool locked = false;
	DWORD opt = 0;
	DWORD reqFlags = 0;

	if (clientCtx == NULL || req == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Verify the length on the raw data. */
	if (req->len > DWORD_MAX) {
		KSI_LOG_error(clientCtx->ctx, "Async WinINet: Request length larger than DWORD_MAX %d", req->len);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = WinAsyncReq_new(clientCtx->ctx, &httpReq);
	if (res != KSI_OK) {
		KSI_pushError(clientCtx->ctx, res, NULL);
		goto cleanup;
	}
	httpReq->reqCtx = KSI_AsyncHandle_ref(req);

	/* Use secure connection if requested. */
	reqFlags = (clientCtx->isSecure ? INTERNET_FLAG_SECURE : 0);
	/* Make sure we get the response from the server and not the cache. */
	/* Also ask WinInet not to store the response in the cache. */
	reqFlags |= INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
	/* Disables the cookie dialog box. */
	reqFlags |= INTERNET_FLAG_NO_UI;
	/* Obtain request handle. */
	httpReq->requestHandle = HttpOpenRequest(clientCtx->connectHandle,
			(httpReq->reqCtx->raw == NULL ? "GET" : "POST"),
			clientCtx->path, NULL, NULL, NULL,
			reqFlags,
			(DWORD_PTR)httpReq);
	if (httpReq->requestHandle == NULL) {
		KSI_LOG_error(clientCtx->ctx, "Async WinINet: Unable to initialize request handle. Error %d", GetLastError());
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	/* Create events. */
	httpReq->closedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (httpReq->closedEvent == NULL) {
		KSI_LOG_error(httpReq->ctx, "Async WinINet: failed to create event handle. Error %d", GetLastError());
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* Set timeouts (in millisec). */
	opt = (DWORD)clientCtx->options[KSI_ASYNC_OPT_CON_TIMEOUT] * 1000 * 2;
	if (!InternetSetOption(httpReq->requestHandle, INTERNET_OPTION_CONNECT_TIMEOUT, &opt, sizeof(opt))) {
		KSI_LOG_error(clientCtx->ctx, "Async WinINet: Unable to set connect timeout. Error %d", GetLastError());
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	opt = (DWORD)clientCtx->options[KSI_ASYNC_OPT_SND_TIMEOUT] * 1000 * 2;
	if (!InternetSetOption(httpReq->requestHandle, INTERNET_OPTION_SEND_TIMEOUT, &opt, sizeof(opt))) {
		KSI_LOG_error(clientCtx->ctx, "Async WinINet: Unable to set send timeout. Error %d", GetLastError());
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	opt = (DWORD)clientCtx->options[KSI_ASYNC_OPT_RCV_TIMEOUT] * 1000 * 2;
	if (!InternetSetOption(httpReq->requestHandle, INTERNET_OPTION_RECEIVE_TIMEOUT, &opt, sizeof(opt))) {
		KSI_LOG_error(clientCtx->ctx, "Async WinINet: Unable to set receive timeout. Error %d", GetLastError());
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	/* Add MIME type header. */
	if (clientCtx->mimeType) {
		if (!HttpAddRequestHeaders(httpReq->requestHandle, clientCtx->mimeType, -1L,
				HTTP_ADDREQ_FLAG_ADD | HTTP_ADDREQ_FLAG_REPLACE)) {
			KSI_LOG_error(clientCtx->ctx, "Async WinINet: Unable to set MIME type. Error %d", GetLastError());
			res = KSI_NETWORK_ERROR;
			goto cleanup;
		}
	}

	EnterCriticalSection(&CriticalSection);
	locked = true;

	/* Send request. */
	if (!HttpSendRequest(httpReq->requestHandle, NULL, 0,
				(LPVOID)httpReq->reqCtx->raw, (DWORD)httpReq->reqCtx->len)) {
		DWORD dwError = GetLastError();
		if (dwError != ERROR_IO_PENDING) {
			KSI_LOG_error(clientCtx->ctx, "Async WinINet: failed to send request. Error %d.", dwError);
			res = KSI_NETWORK_ERROR;
			if (error) *error = dwError;
			goto cleanup;
		}
	}
	KSI_LOG_debug(clientCtx->ctx, "Async WinINet: request %p sent.", httpReq);

	res = WinAsyncReqList_append(clientCtx->httpQueue, httpReq);
	if (res != KSI_OK) goto cleanup;
	httpReq = NULL;

cleanup:
	if (locked)	LeaveCriticalSection(&CriticalSection);

	WinAsyncReq_free(httpReq);

	return res;
}

static int WinINet_handleResponse(HttpAsyncCtx *clientCtx) {
	int res = KSI_UNKNOWN_ERROR;
	WinAsyncReq *httpReq = NULL;
	KSI_OctetString *resp = NULL;
	bool locked = false;
	size_t i;

	if (clientCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}


	for (i = 0; i < WinAsyncReqList_length(clientCtx->httpQueue); i++) {
		KSI_AsyncHandle *handle = NULL;

		res = WinAsyncReqList_elementAt(clientCtx->httpQueue, i, &httpReq);
		if (res != KSI_OK) goto cleanup;

		if (httpReq == NULL) {
			res = KSI_INVALID_STATE;
			goto cleanup;
		}
		handle = httpReq->reqCtx;

		if (handle->state != KSI_ASYNC_STATE_WAITING_FOR_RESPONSE) {
			WinAsyncReqList_remove(clientCtx->httpQueue, i, NULL);
			break;
		}

		/* Try to acquire the resource lock. */
		if (!TryEnterCriticalSection(&CriticalSection)) {
			res = KSI_OK;
			goto cleanup;
		}
		locked = true;

		if (!httpReq->reqComplete) {
			LeaveCriticalSection(&CriticalSection);
			locked = false;
			continue;
		}

		if (httpReq->status != KSI_OK) {
			KSI_LOG_debug(clientCtx->ctx, "Async WinINet: error result %x:%d.", httpReq->status, httpReq->errExt);
			handle->state = KSI_ASYNC_STATE_ERROR;
			handle->err = httpReq->status;
			handle->errExt = httpReq->errExt;
		} else {
			size_t count = 0;

			KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG, "Async WinINet: received stream", httpReq->raw, httpReq->len);

			while (count < httpReq->len) {
				KSI_FTLV ftlv;
				size_t tlvSize = 0;

				/* Traverse through the input stream and verify that a complete TLV is present. */
				memset(&ftlv, 0, sizeof(KSI_FTLV));
				res = KSI_FTLV_memRead(httpReq->raw + count, httpReq->len - count, &ftlv);
				if (res != KSI_OK) {
					KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_ERROR,
							"Async WinINet: Unable to extract TLV from input stream",
							httpReq->raw, httpReq->len);
					handle->state = KSI_ASYNC_STATE_ERROR;
					handle->err = KSI_NETWORK_ERROR;
					break;
				}
				tlvSize = ftlv.hdr_len + ftlv.dat_len;

				KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG, "Async WinINet: received response", httpReq->raw + count, tlvSize);

				res = KSI_OctetString_new(clientCtx->ctx, httpReq->raw + count,  tlvSize, &resp);
				if (res != KSI_OK) {
					KSI_LOG_error(clientCtx->ctx, "Async WinINet: unable to create new KSI_OctetString object. Error: %x.", res);
					res = KSI_OK;
					goto cleanup;
				}

				res = KSI_OctetStringList_append(clientCtx->respQueue, resp);
				if (res != KSI_OK) {
					KSI_LOG_error(clientCtx->ctx, "Async WinINet: unable to add new response to queue. Error: %x.", res);
					res = KSI_OK;
					goto cleanup;
				}
				resp = NULL;

				count += tlvSize;
			}
		}
		LeaveCriticalSection(&CriticalSection);
		locked = false;

		WinAsyncReqList_remove(clientCtx->httpQueue, i, NULL);
		break;
	}

	res = KSI_OK;
cleanup:
	if (locked) LeaveCriticalSection(&CriticalSection);
	KSI_OctetString_free(resp);

	return res;
}

static int dispatch(HttpAsyncCtx *clientCtx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncHandle *req = NULL;

	if (clientCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(clientCtx->ctx);

	/* Check connection. */
	if (clientCtx->sessionHandle == NULL) {
		/* Only open connection if there is anything in request queue. */
		if (KSI_AsyncHandleList_length(clientCtx->reqQueue) == 0) {
			KSI_LOG_debug(clientCtx->ctx, "Async WinINet not ready: request is queue empty.");
			res = KSI_OK;
			goto cleanup;
		}

		res = WinINet_init(clientCtx);
		if (res != KSI_OK) {
			reqQueue_clearWithError(clientCtx->reqQueue, res, GetLastError());
			KSI_pushError(clientCtx->ctx, res, "Failed to init WinINet.");
			res = KSI_OK;
			goto cleanup;
		}
	}

	/* Handle output. */
	while (KSI_AsyncHandleList_length(clientCtx->reqQueue) > 0 &&
				KSI_AsyncHandleList_elementAt(clientCtx->reqQueue, 0, &req) == KSI_OK && req != NULL) {
		DWORD error = 0;
		time_t curTime = time(NULL);

		/* Verify that the request is still to be sent. */
		if (req->state != KSI_ASYNC_STATE_WAITING_FOR_DISPATCH) {
			/* The state could have been changed in application layer. Just remove the request from the queue. */
			KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
			continue;
		}

		/* Verify that the send timeout has not elapsed. */
		if (clientCtx->options[KSI_ASYNC_OPT_SND_TIMEOUT] == 0 ||
					(difftime(curTime, req->reqTime) > clientCtx->options[KSI_ASYNC_OPT_SND_TIMEOUT])) {
			/* Set error. */
			req->state = KSI_ASYNC_STATE_ERROR;
			req->err = KSI_NETWORK_SEND_TIMEOUT;
			/* Just remove the request from the request queue. */
			KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
			continue;
		}

		/* Check if the request count can be restarted. */
		if (difftime(curTime, clientCtx->roundStartAt) >= clientCtx->options[KSI_ASYNC_PRIVOPT_ROUND_DURATION]) {
			KSI_LOG_info(clientCtx->ctx, "Async WinINet round request count: %u", clientCtx->roundCount);
			clientCtx->roundCount = 0;
			clientCtx->roundStartAt = curTime;
		}
		/* Check if more requests can be sent within the given timeframe. */
		if (!(clientCtx->roundCount < clientCtx->options[KSI_ASYNC_OPT_MAX_REQUEST_COUNT])) {
			KSI_LOG_debug(clientCtx->ctx, "Async WinINet round max request count reached.");
			break;
		}

		KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG, "Async WinINet: Preparing request", req->raw, req->len);

		res = WinINet_sendRequest(clientCtx, req, &error);
		if (res != KSI_OK) {
			KSI_LOG_debug(clientCtx->ctx, "Async WinINet: Failed to send request. Error %x:%d.", res, error);
			KSI_pushError(clientCtx->ctx, res, "Failed to send request.");
			/* Set error. */
			req->state = KSI_ASYNC_STATE_ERROR;
			req->err = res;
			req->errExt = error;
			/* Just remove the request from the request queue. */
			KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
			continue;
		}

		/* Update state. */
		req->state = KSI_ASYNC_STATE_WAITING_FOR_RESPONSE;
		/* Start receive timeout. */
		req->sndTime = curTime;

		/* The request has been successfully dispatched. Remove it from the request queue. */
		KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
		clientCtx->roundCount++;
	}

	/* Handle input. */
	res = WinINet_handleResponse(clientCtx);
	if (res != KSI_OK) {
		KSI_LOG_debug(clientCtx->ctx, "Async WinINet: Failed to handle response. Error %x.", res);
		KSI_pushError(clientCtx->ctx, res, "Failed to handle response.");
		res = KSI_OK;
		goto cleanup;
	}

	res = KSI_OK;
cleanup:

	return res;
}

static int addToSendQueue(HttpAsyncCtx *clientCtx, KSI_AsyncHandle *request) {
	int res = KSI_UNKNOWN_ERROR;

	if (clientCtx == NULL || clientCtx->reqQueue == NULL || request == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	request->state = KSI_ASYNC_STATE_WAITING_FOR_DISPATCH;
	/* Start send timeout. */
	time(&request->reqTime);

	res = KSI_AsyncHandleList_append(clientCtx->reqQueue, request);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;
cleanup:
	return res;
}

static int getResponse(HttpAsyncCtx *clientCtx, KSI_OctetString **response, size_t *left) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_OctetString *tmp = NULL;

	if (clientCtx == NULL || clientCtx->respQueue == NULL || response == NULL || left == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (KSI_OctetStringList_length(clientCtx->respQueue)) {
		/* Responses should be processed in the same order as received. */
		res = KSI_OctetStringList_remove(clientCtx->respQueue, 0, &tmp);
		if (res != KSI_OK) goto cleanup;
	}

	*response = tmp;
	*left = KSI_OctetStringList_length(clientCtx->respQueue);

	res = KSI_OK;
cleanup:
	return res;
}

static int setService(HttpAsyncCtx *clientCtx, const char *url, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;
	char *scheme = NULL;
	char *host = NULL;
	char *path = NULL;
	int port = 0;

	if (clientCtx == NULL || url == NULL || user == NULL || pass == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_UriSplitBasic(url, &scheme, &host, &port, &path);
	if (res != KSI_OK) goto cleanup;

	if (host == NULL || scheme == NULL || strcmp("http", scheme) != 0 && strcmp("https", scheme) != 0){
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (clientCtx->host) KSI_free(clientCtx->host);
	clientCtx->host = NULL;
	res = KSI_strdup(host, &clientCtx->host);
	if (res != KSI_OK) goto cleanup;

	if (clientCtx->path) KSI_free(clientCtx->path);
	clientCtx->path = NULL;
	if (path) {
		res = KSI_strdup(path, &clientCtx->path);
		if (res != KSI_OK) goto cleanup;
	}

	clientCtx->port = port;
	clientCtx->isSecure = (strcmp("https", scheme) == 0);

	if (clientCtx->ksi_user) KSI_free(clientCtx->ksi_user);
	clientCtx->ksi_user = NULL;
	res = KSI_strdup(user, &clientCtx->ksi_user);
	if (res != KSI_OK) goto cleanup;

	if (clientCtx->ksi_pass) KSI_free(clientCtx->ksi_pass);
	clientCtx->ksi_pass = NULL;
	res = KSI_strdup(pass, &clientCtx->ksi_pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;
cleanup:
	KSI_free(path);
	KSI_free(host);
	KSI_free(scheme);

	return res;
}

static int getCredentials(HttpAsyncCtx *clientCtx, const char **user, const char **pass) {
	if (clientCtx == NULL) return KSI_INVALID_ARGUMENT;
	if (user != NULL) *user = clientCtx->ksi_user;
	if (pass != NULL) *pass = clientCtx->ksi_pass;
	return KSI_OK;
}

static void HttpAsyncCtx_free(HttpAsyncCtx *o) {
	if (o != NULL) {
		/* Cleanup WinINet handles. */
		if (o->connectHandle != NULL) InternetCloseHandle(o->connectHandle);
		if (o->sessionHandle != NULL) InternetCloseHandle(o->sessionHandle);

		/* Cleanup queues. */
		KSI_AsyncHandleList_free(o->reqQueue);
		WinAsyncReqList_free(o->httpQueue);
		KSI_OctetStringList_free(o->respQueue);

		/* Now it is safe to delete the synchronization lock. */
		if (o->criticalSecInitialized) DeleteCriticalSection(&CriticalSection);

		/* Cleanup headers. */
		KSI_free(o->userAgent);
		KSI_free(o->mimeType);

		/* Cleanup endpoint data. */
		KSI_free(o->ksi_user);
		KSI_free(o->ksi_pass);
		KSI_free(o->host);
		KSI_free(o->path);

		KSI_free(o);
	}
}

static int HttpAsyncCtx_new(KSI_CTX *ctx, HttpAsyncCtx **clientCtx) {
	int res = KSI_UNKNOWN_ERROR;
	HttpAsyncCtx *tmp = NULL;

	if (ctx == NULL || clientCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_malloc(sizeof(HttpAsyncCtx));
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	tmp->ctx = ctx;
	tmp->sessionHandle = NULL;
	tmp->connectHandle = NULL;

	tmp->options = NULL;
	tmp->roundStartAt = 0;
	tmp->roundCount = 0;

	/* Queues */
	tmp->reqQueue = NULL;
	tmp->httpQueue = NULL;
	tmp->respQueue = NULL;
	/* Header fields. */
	tmp->userAgent = NULL;
	tmp->mimeType = NULL;
	/* Endpoint. */
	tmp->ksi_user = NULL;
	tmp->ksi_pass = NULL;
	tmp->host = NULL;
	tmp->path = NULL;
	tmp->isSecure = false;

	tmp->criticalSecInitialized = false;
	if (!InitializeCriticalSectionAndSpinCount(&CriticalSection, 1000)) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}
	tmp->criticalSecInitialized = true;

	/* Initialize io queues. */
	res = KSI_AsyncHandleList_new(&tmp->reqQueue);
	if (res != KSI_OK) goto cleanup;
	res = WinAsyncReqList_new(&tmp->httpQueue);
	if (res != KSI_OK) goto cleanup;
	res = KSI_OctetStringList_new(&tmp->respQueue);
	if (res != KSI_OK) goto cleanup;

	/* TODO: move to options. */
	res = KSI_strdup("KSI HTTP Client", &tmp->userAgent);
	if (res != KSI_OK) goto cleanup;
	res = KSI_strdup("Content-Type: application/ksi-request", &tmp->mimeType);
	if (res != KSI_OK) goto cleanup;

	*clientCtx = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	HttpAsyncCtx_free(tmp);
	return res;
}

int KSI_HttpAsyncClient_new(KSI_CTX *ctx, KSI_AsyncClient **c) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncClient *tmp = NULL;
	HttpAsyncCtx *netImpl = NULL;

	if (ctx == NULL || c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_AbstractAsyncClient_new(ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	tmp->addRequest = (int (*)(void *, KSI_AsyncHandle *))addToSendQueue;
	tmp->getResponse = (int (*)(void *, KSI_OctetString **, size_t *))getResponse;
	tmp->dispatch = (int (*)(void *))dispatch;
	tmp->getCredentials = (int (*)(void *, const char **, const char **))getCredentials;

	res = HttpAsyncCtx_new(ctx, &netImpl);
	if (res != KSI_OK) goto cleanup;

	netImpl->options = tmp->options;

	tmp->clientImpl_free = (void (*)(void*))HttpAsyncCtx_free;
	tmp->clientImpl = netImpl;
	netImpl = NULL;

	*c = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	HttpAsyncCtx_free(netImpl);
	KSI_AsyncClient_free(tmp);

	return res;
}

int KSI_HttpAsyncClient_setService(KSI_AsyncClient *c, const char *url, const char *user, const char *pass) {
	if (c == NULL || c->clientImpl == NULL) return KSI_INVALID_ARGUMENT;
	return setService(c->clientImpl, url, user, pass);
}


#endif /* KSI_NET_HTTP_IMPL */
