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

#if KSI_NET_HTTP_IMPL==KSI_IMPL_WINHTTP

#include <windows.h>
#include <winhttp.h>

#include "tlv.h"
#include "fast_tlv.h"

#include "impl/net_http_impl.h"
#include "impl/net_async_impl.h"

typedef struct WinHTTPAsyncReq_st  WinHTTPAsyncReq;

KSI_DEFINE_LIST(WinHTTPAsyncReq);
#define WinHTTPAsyncReqList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define WinHTTPAsyncReqList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define WinHTTPAsyncReqList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define WinHTTPAsyncReqList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define WinHTTPAsyncReqList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define WinHTTPAsyncReqList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define WinHTTPAsyncReqList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define WinHTTPAsyncReqList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define WinHTTPAsyncReqList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

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
	/* Pending in WinHTTP API queue. */
	KSI_LIST(WinHTTPAsyncReq) *httpQueue;
	/* Input queue. */
	KSI_LIST(KSI_OctetString) *respQueue;

	/* HTTP header fields. */
	LPWSTR userAgent;
	LPWSTR mimeType;

	/* Round throttling. */
	time_t roundStartAt;
	size_t roundCount;

	/* Poiter to the async options. */
	size_t *options;

	/* Endpoint data. */
	char *ksi_user;
	char *ksi_pass;
	LPWSTR host;
	LPWSTR path;
	int port;
	bool isSecure;
} HttpAsyncCtx;

struct WinHTTPAsyncReq_st {
	/* WinHTTP request handle. */
	HINTERNET requestHandle;

	/* Parent client. */
	HttpAsyncCtx *client;

	/* Request context. */
	KSI_AsyncHandle *reqCtx;
	/* Receive buffer. */
	unsigned char *raw;
	size_t len;
	bool dataComplete;

	/* Synchronization event for resource cleanup. */
	HANDLE closedEvent;
	/* Status handling. */
	bool reqComplete;
	int status;
	DWORD errExt;

#ifdef KSI_DEBUG_WINHTTP_STATUS_CALLBACK
	DWORD callbackReceived;
#endif
};

/* Global lock for resource use synchronization. */
static CRITICAL_SECTION CriticalSection;

static void WinHTTPAsyncReq_free(WinHTTPAsyncReq *o) {
	if (o != NULL) {

		if (o->requestHandle && WinHttpCloseHandle(o->requestHandle)) {
			if (o->closedEvent) WaitForSingleObject(o->closedEvent, INFINITE);
		}
		if (o->closedEvent) CloseHandle(o->closedEvent);
		KSI_AsyncHandle_free(o->reqCtx);
		KSI_free(o->raw);
		KSI_free(o);
	}
}

static int WinHTTPAsyncReq_new(HttpAsyncCtx *clientCtx, WinHTTPAsyncReq **o) {
	int res = KSI_UNKNOWN_ERROR;
	WinHTTPAsyncReq *tmp = NULL;

	if (clientCtx == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_malloc(sizeof(WinHTTPAsyncReq));
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->client = clientCtx;
	tmp->reqCtx = NULL;
	tmp->requestHandle = NULL;
	tmp->len = 0;
	tmp->raw = NULL;
	tmp->dataComplete = false;

	tmp->closedEvent = NULL;

	tmp->reqComplete = false;
	tmp->status = KSI_ASYNC_NOT_FINISHED;
	tmp->errExt = 0;

#ifdef KSI_DEBUG_WINHTTP_STATUS_CALLBACK
	tmp->callbackReceived = 0;
#endif

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	WinHTTPAsyncReq_free(tmp);
	return res;
}

KSI_IMPLEMENT_LIST(WinHTTPAsyncReq, WinHTTPAsyncReq_free);

#ifdef KSI_DEBUG_WINHTTP_STATUS_CALLBACK

#define WINHTTP_STATUS_CALLBACK_LIST\
	_(RESOLVING_NAME)\
	_(NAME_RESOLVED)\
	_(CONNECTING_TO_SERVER)\
	_(CONNECTED_TO_SERVER)\
	_(SENDING_REQUEST)\
	_(REQUEST_SENT)\
	_(RECEIVING_RESPONSE)\
	_(RESPONSE_RECEIVED)\
	_(CLOSING_CONNECTION)\
	_(CONNECTION_CLOSED)\
	_(HANDLE_CREATED)\
	_(HANDLE_CLOSING)\
	_(DETECTING_PROXY)\
	_(REDIRECT)\
	_(INTERMEDIATE_RESPONSE)\
	_(SECURE_FAILURE)\
	_(HEADERS_AVAILABLE)\
	_(DATA_AVAILABLE)\
	_(READ_COMPLETE)\
	_(WRITE_COMPLETE)\
	_(REQUEST_ERROR)\
	_(SENDREQUEST_COMPLETE)

static char *WinHTTPCallbackStatus_toString(DWORD status) {
	switch (status) {
#define _(sta) case WINHTTP_CALLBACK_STATUS_##sta: return #sta;
		WINHTTP_STATUS_CALLBACK_LIST
#undef _
		default: return "UNKNOWN";
	}
}

#endif

static void CALLBACK WinHTTP_asyncCallback(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus,
			LPVOID lpvStatusInformation, DWORD dwStatusInformationLength) {

	EnterCriticalSection(&CriticalSection);

	UNREFERENCED_PARAMETER(hInternet);
	UNREFERENCED_PARAMETER(dwStatusInformationLength);

	if ((void*)dwContext != NULL) {
		DWORD dwError = ERROR_SUCCESS;
		WinHTTPAsyncReq *request = (WinHTTPAsyncReq*)dwContext;
		unsigned char *tmpBuffer = NULL;

#ifdef KSI_DEBUG_WINHTTP_STATUS_CALLBACK
		request->callbackReceived |= dwInternetStatus;
		KSI_LOG_debug(request->client->ctx, "[%p] Async WinHTTP: [%p] thread=%d callback=%08x (%s).",
				request->client, request,
				GetCurrentThreadId(), dwInternetStatus, WinHTTPCallbackStatus_toString(dwInternetStatus));
#endif
		switch (dwInternetStatus) {
			case WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE:
				if (!WinHttpReceiveResponse(request->requestHandle, NULL)) {
					KSI_LOG_error(request->client->ctx, "[%p] Async WinHTTP: [%p] unable to get HTTP response. Error %d.",
							request->client, request,
							(dwError = GetLastError()));
					goto cleanup;
				}
				break;
			case WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE: {
					DWORD statusLen;
					DWORD httpStatus = 0;

					/* Get HTTP status code. */
					statusLen = sizeof(httpStatus);
					if (!WinHttpQueryHeaders(request->requestHandle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
								WINHTTP_HEADER_NAME_BY_INDEX, &httpStatus, &statusLen, NULL)) {
						KSI_LOG_error(request->client->ctx, "[%p] Async WinHTTP: [%p] unable to get HTTP status. Error %d.",
								request->client, request,
								(dwError = GetLastError()));
						goto cleanup;
					}

					if (httpStatus >= 400 && httpStatus < 600) {
						KSI_LOG_error(request->client->ctx, "[%p] Async WinHTTP: [%p] received HTTP code %d.",
								request->client, request,
								httpStatus);
						request->status = KSI_HTTP_ERROR;
						request->errExt = httpStatus;
						/* We are finished with the request. Close handle and wait for WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING. */
						WinHttpCloseHandle(request->requestHandle);
						request->requestHandle = NULL;
						goto cleanup;
					}

					/* Query data and wait for WINHTTP_STATUS_CALLBACK_DATA_AVAILABLE. */
					if (!WinHttpQueryDataAvailable(request->requestHandle, NULL)) {
						KSI_LOG_error(request->client->ctx,
								"[%p] Async WinHTTP: [%p] unable to get HTTP data status. Error %d.",
								request->client, request,
								(dwError = GetLastError()));
						goto cleanup;
					}
				}
				break;
			case WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE: {
					size_t bytesCount = 0;
					DWORD bytesReceived = *(DWORD*)lpvStatusInformation;

					if (bytesReceived == 0) {
						request->dataComplete = true;
						/* Dummy read for triggering WINHTTP_CALLBACK_STATUS_READ_COMPLETE event. */
						WinHttpReadData(request->requestHandle, NULL, 0, NULL);
						goto cleanup;
					}

					bytesCount = request->len + bytesReceived;
					if (bytesCount > UINT_MAX) {
						KSI_LOG_error(request->client->ctx,
								"[%p] Async WinHTTP: [%p] too many bytes received %llu bytes (%llu so far).",
								request->client, request,
								bytesReceived, request->len);
						request->status = KSI_BUFFER_OVERFLOW;
						WinHttpCloseHandle(request->requestHandle);
						request->requestHandle = NULL;
						goto cleanup;
					}
					tmpBuffer = KSI_malloc(bytesCount * sizeof(unsigned char));
					if (tmpBuffer == NULL){
						request->status = KSI_OUT_OF_MEMORY;
						/* We are finished with the request. Close handle and for WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING. */
						WinHttpCloseHandle(request->requestHandle);
						request->requestHandle = NULL;
						goto cleanup;
					}
					if (request->len) memcpy(tmpBuffer, request->raw, request->len);

					if (!WinHttpReadData(request->requestHandle, tmpBuffer + request->len, bytesReceived, NULL)) {
						KSI_LOG_error(request->client->ctx,
								"[%p] Async WinHTTP: [%p] Unable to get HTTP data status. Error %d.",
								request->client, request,
								(dwError = GetLastError()));
						goto cleanup;
					}
					KSI_LOG_debug(request->client->ctx, "[%p] Async WinHTTP: [%p] received %d bytes (%llu total).",
							request->client, request,
							(unsigned long long) bytesReceived, bytesCount);

					KSI_free(request->raw);
					request->raw = tmpBuffer;
					request->len = bytesCount;
					tmpBuffer = NULL;

					/* Query data and wait for WINHTTP_STATUS_CALLBACK_DATA_AVAILABLE. */
					if (!WinHttpQueryDataAvailable(request->requestHandle, NULL)) {
						KSI_LOG_error(request->client->ctx,
								"[%p] Async WinHTTP: [%p] unable to get HTTP data status. Error %d.",
								request->client, request,
								(dwError = GetLastError()));
						goto cleanup;
					}
				}
				break;
			case WINHTTP_CALLBACK_STATUS_READ_COMPLETE:
				if (!request->dataComplete) goto cleanup;
				/* We are done. */
				request->status = KSI_OK;
				/* Close request handle and wait for WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING. */
				WinHttpCloseHandle(request->requestHandle);
				request->requestHandle = NULL;
				KSI_LOG_logBlob(request->client->ctx, KSI_LOG_DEBUG, "[%p] Async WinHTTP: [%p] read complete",
						request->raw, request->len,
						request->client, request);
				break;
			case WINHTTP_CALLBACK_STATUS_REQUEST_ERROR:
				dwError = ((WINHTTP_ASYNC_RESULT*)lpvStatusInformation)->dwError;
				break;
			case WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING:
				/* Guaranteed last callback this context will ever receive. */
				request->reqComplete = true;
				/* Now it is save to free the context. */
				SetEvent(request->closedEvent);
				break;
			default:
				/* Do nothing. */
				goto cleanup;
		}

cleanup:
		if (dwError != ERROR_SUCCESS) {
			KSI_LOG_error(request->client->ctx, "[%p] Async WinHTTP: [%p] Status %x: Error %d.",
					request->client, request,
					dwInternetStatus, dwError);
			/* Set error. */
			request->status = KSI_NETWORK_ERROR;
			request->errExt = dwError;
			/* Close handle and wait for WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING. */
			if (request->requestHandle) {
				WinHttpCloseHandle(request->requestHandle);
				request->requestHandle = NULL;
			}
		}
		KSI_free(tmpBuffer);
	}

	LeaveCriticalSection(&CriticalSection);
}

static void reqQueue_clearWithError(KSI_AsyncHandleList *reqQueue, int err, long ext) {
	size_t size = 0;

	if (reqQueue == NULL) return;

	while ((size = KSI_AsyncHandleList_length(reqQueue)) > 0) {
		int res;
		KSI_AsyncHandle *req = NULL;

		res = KSI_AsyncHandleList_remove(reqQueue, size - 1, &req);
		if (res != KSI_OK || req == NULL) return;

		/* Update request state. */
		req->state = KSI_ASYNC_STATE_ERROR;
		req->err = err;
		req->errExt = ext;

		KSI_AsyncHandle_free(req);
	}
}

static int WinHTTP_init(HttpAsyncCtx *clientCtx) {
	int res = KSI_UNKNOWN_ERROR;
	HINTERNET hSession = NULL;
	HINTERNET hConnect = NULL;

	if (clientCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Obtain session handle. */
	hSession = WinHttpOpen(clientCtx->userAgent,
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS,
			WINHTTP_FLAG_ASYNC);
	if (hSession == NULL) {
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	/* Limit the total amount of connections. The default value is INFINITE. */
#ifdef KSI_WINHTTP_LIMIT_MAX_CONSS
	{
		DWORD opt = (DWORD)clientCtx->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE];
		if (!WinHttpSetOption(hSession, WINHTTP_OPTION_MAX_CONNS_PER_SERVER, &opt, sizeof(opt)) ||
			!WinHttpSetOption(hSession, WINHTTP_OPTION_MAX_CONNS_PER_1_0_SERVER, &opt, sizeof(opt))) {
			res = KSI_NETWORK_ERROR;
			goto cleanup;
		}
	}
#endif

	/* Set timeouts (in millisec). Only set connect timeout, as other timeouts are handled internally. */
	if (!WinHttpSetTimeouts(hSession, 0, (int)clientCtx->options[KSI_ASYNC_OPT_CON_TIMEOUT] * 1000, 0, 0)) {
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	/* Obtain connect handle. */
	hConnect = WinHttpConnect(hSession, clientCtx->host, (INTERNET_PORT)clientCtx->port, 0);
	if (hConnect == NULL) {
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	clientCtx->sessionHandle = hSession;
	hSession = NULL;
	clientCtx->connectHandle = hConnect;
	hConnect = NULL;

	res = KSI_OK;
cleanup:
	if (hSession != NULL) WinHttpCloseHandle(hSession);
	if (hConnect != NULL) WinHttpCloseHandle(hConnect);

	return res;
}

static int WinHTTP_sendRequest(HttpAsyncCtx *clientCtx, KSI_AsyncHandle *req) {
	int res = KSI_UNKNOWN_ERROR;
	WinHTTPAsyncReq *httpReq = NULL;
	bool locked = false;

	if (clientCtx == NULL || req == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Verify the length on the raw data. */
	if (req->len > DWORD_MAX) {
		KSI_LOG_error(clientCtx->ctx, "[%p] Async WinHTTP: Request length larger than DWORD_MAX %d.", clientCtx, httpReq->len);
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = WinHTTPAsyncReq_new(clientCtx, &httpReq);
	if (res != KSI_OK) {
		KSI_pushError(clientCtx->ctx, res, NULL);
		goto cleanup;
	}
	httpReq->reqCtx = KSI_AsyncHandle_ref(req);

	/* Obtain request handle. */
	httpReq->requestHandle = WinHttpOpenRequest(clientCtx->connectHandle,
			(httpReq->reqCtx->raw == NULL ? L"GET" : L"POST"),
			clientCtx->path, NULL, NULL, NULL,
			clientCtx->isSecure ? WINHTTP_FLAG_SECURE : 0);
	if (httpReq->requestHandle == NULL) {
		KSI_LOG_error(clientCtx->ctx, "[%p] Async WinHTTP: Unable to initialize request handle. Error %d.",
				clientCtx, GetLastError());
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	/* Create events. */
	httpReq->closedEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (httpReq->closedEvent == NULL) {
		KSI_LOG_error(clientCtx->ctx, "[%p] Async WinHTTP: failed to create event handle. Error %d.",
				clientCtx, GetLastError());
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	/* Set timeouts (in millisec). Only set connect timeout, as other timeouts are handled internally. */
	if (!WinHttpSetTimeouts(httpReq->requestHandle,
				(int)clientCtx->options[KSI_ASYNC_OPT_CON_TIMEOUT] * 1000,
				(int)clientCtx->options[KSI_ASYNC_OPT_CON_TIMEOUT] * 1000,
				(int)clientCtx->options[KSI_ASYNC_OPT_SND_TIMEOUT] * 1000,
				(int)clientCtx->options[KSI_ASYNC_OPT_RCV_TIMEOUT] * 1000)) {
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	/* Add MIME type header. */
	if (clientCtx->mimeType) {
		if (!WinHttpAddRequestHeaders(httpReq->requestHandle, clientCtx->mimeType, -1L,
				WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE)) {
			KSI_LOG_error(clientCtx->ctx, "[%p] Async WinHTTP: Unable to initialize request handle. Error %d.",
					clientCtx, GetLastError());
			res = KSI_NETWORK_ERROR;
			goto cleanup;
		}
	}

	EnterCriticalSection(&CriticalSection);
	locked = true;

	/* Set status callback. */
	if (WinHttpSetStatusCallback(httpReq->requestHandle, WinHTTP_asyncCallback,
				WINHTTP_CALLBACK_FLAG_ALL_NOTIFICATIONS, 0) == WINHTTP_INVALID_STATUS_CALLBACK)	{
		KSI_LOG_error(clientCtx->ctx, "[%p] Async WinHTTP: Unable to set callback. Error %d.", clientCtx, GetLastError());
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	/* Send request. */
	if (!WinHttpSendRequest(httpReq->requestHandle, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
				(LPVOID)httpReq->reqCtx->raw, (DWORD)httpReq->reqCtx->len, (DWORD)httpReq->reqCtx->len,
				(DWORD_PTR)httpReq)) {
		KSI_LOG_error(clientCtx->ctx, "[%p] Async WinHTTP: failed to send request. Error %d.", clientCtx, GetLastError());
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}
	KSI_LOG_debug(clientCtx->ctx, "[%p] Async WinHTTP: request %p sent.", clientCtx, httpReq);

	res = WinHTTPAsyncReqList_append(clientCtx->httpQueue, httpReq);
	if (res != KSI_OK) goto cleanup;
	httpReq = NULL;

cleanup:
	WinHTTPAsyncReq_free(httpReq);

	if (locked) LeaveCriticalSection(&CriticalSection);

	return res;
}

static int WinHTTP_handleResponse(HttpAsyncCtx *clientCtx) {
	int res = KSI_UNKNOWN_ERROR;
	WinHTTPAsyncReq *httpReq = NULL;
	KSI_OctetString *resp = NULL;
	bool locked = false;
	size_t i;

	if (clientCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Try to acquire the resource lock. */
	if (!TryEnterCriticalSection(&CriticalSection)) {
		res = KSI_OK;
		goto cleanup;
	}
	locked = true;

	for (i = 0; i < WinHTTPAsyncReqList_length(clientCtx->httpQueue); i++) {
		KSI_AsyncHandle *handle = NULL;

		res = WinHTTPAsyncReqList_elementAt(clientCtx->httpQueue, i, &httpReq);
		if (res != KSI_OK) goto cleanup;

		if (httpReq == NULL) {
			res = KSI_INVALID_STATE;
			goto cleanup;
		}
		handle = httpReq->reqCtx;

		if (handle->state != KSI_ASYNC_STATE_WAITING_FOR_RESPONSE) {
			WinHTTPAsyncReqList_remove(clientCtx->httpQueue, i, NULL);
			break;
		}

		if (!httpReq->reqComplete) continue;

		if (httpReq->status != KSI_OK) {
			KSI_LOG_debug(clientCtx->ctx, "[%p] Async WinHTTP: error result %x:%d.",
					clientCtx, httpReq->status, httpReq->errExt);
			handle->state = KSI_ASYNC_STATE_ERROR;
			handle->err = httpReq->status;
			handle->errExt = httpReq->errExt;
		} else {
			size_t count = 0;

			KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG, "[%p] Async WinHTTP: received stream",
					httpReq->raw, httpReq->len,
					clientCtx);

			while (count < httpReq->len) {
				KSI_FTLV ftlv;
				size_t tlvSize = 0;

				/* Traverse through the input stream and verify that a complete TLV is present. */
				memset(&ftlv, 0, sizeof(KSI_FTLV));
				res = KSI_FTLV_memRead(httpReq->raw + count, httpReq->len - count, &ftlv);
				if (res != KSI_OK) {
					KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_ERROR,
							"[%p] Async WinHTTP: Unable to extract TLV from input stream",
							httpReq->raw, httpReq->len, clientCtx);
					handle->state = KSI_ASYNC_STATE_ERROR;
					handle->err = KSI_NETWORK_ERROR;
					break;
				}
				tlvSize = ftlv.hdr_len + ftlv.dat_len;

				KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG, "[%p] Async WinHTTP: received response",
						httpReq->raw + count, tlvSize, clientCtx);

				res = KSI_OctetString_new(clientCtx->ctx, httpReq->raw + count,  tlvSize, &resp);
				if (res != KSI_OK) {
					KSI_LOG_error(clientCtx->ctx, "[%p] Async WinHTTP: unable to create new KSI_OctetString object. Error: %x.",
							clientCtx, res);
					res = KSI_OK;
					goto cleanup;
				}

				res = KSI_OctetStringList_append(clientCtx->respQueue, resp);
				if (res != KSI_OK) {
					KSI_LOG_error(clientCtx->ctx, "[%p] Async WinHTTP: unable to add new response to queue. Error: %x.",
							clientCtx, res);
					res = KSI_OK;
					goto cleanup;
				}
				resp = NULL;

				count += tlvSize;
			}
		}
		WinHTTPAsyncReqList_remove(clientCtx->httpQueue, i, NULL);
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
			KSI_LOG_debug(clientCtx->ctx, "[%p] Async WinHTTP not ready: request queue is empty.", clientCtx);
			res = KSI_OK;
			goto cleanup;
		}

		res = WinHTTP_init(clientCtx);
		if (res != KSI_OK) {
			reqQueue_clearWithError(clientCtx->reqQueue, res, GetLastError());
			KSI_pushError(clientCtx->ctx, res, "Failed to init WinHTTP.");
			res = KSI_OK;
			goto cleanup;
		}
	}

	/* Handle output. */
	while (KSI_AsyncHandleList_length(clientCtx->reqQueue) > 0 &&
				KSI_AsyncHandleList_elementAt(clientCtx->reqQueue, 0, &req) == KSI_OK && req != NULL) {
		time_t curTime = 0;

		/* Check if the request count can be restarted. */
		if (difftime(time(&curTime), clientCtx->roundStartAt) >= clientCtx->options[KSI_ASYNC_PRIVOPT_ROUND_DURATION]) {
			KSI_LOG_info(clientCtx->ctx, "[%p] Async WinHTTP round request count: %u.", clientCtx, clientCtx->roundCount);
			clientCtx->roundCount = 0;
			clientCtx->roundStartAt = curTime;
		}
		/* Check if more requests can be sent within the given timeframe. */
		if (!(clientCtx->roundCount < clientCtx->options[KSI_ASYNC_OPT_MAX_REQUEST_COUNT])) {
			KSI_LOG_debug(clientCtx->ctx, "[%p] Async WinHTTP round max request count reached.", clientCtx);
			break;
		}

		if (req->state == KSI_ASYNC_STATE_WAITING_FOR_DISPATCH) {
			/* Verify that the send timeout has not elapsed. */
			if (clientCtx->options[KSI_ASYNC_OPT_SND_TIMEOUT] == 0 ||
						(difftime(curTime, req->reqTime) > clientCtx->options[KSI_ASYNC_OPT_SND_TIMEOUT])) {
				/* Set error. */
				req->state = KSI_ASYNC_STATE_ERROR;
				req->err = KSI_NETWORK_SEND_TIMEOUT;
				/* Just remove the request from the request queue. */
				KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
			} else {
				KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG, "[%p] Async WinHTTP: Preparing request",
						req->raw, req->len, clientCtx);

				res = WinHTTP_sendRequest(clientCtx, req);
				if (res != KSI_OK) {
					KSI_LOG_debug(clientCtx->ctx, "[%p] Async WinHTTP: Failed to send request. Error %x.", clientCtx, res);
					KSI_pushError(clientCtx->ctx, res, "Failed to send request.");
					/* Set error. */
					req->state = KSI_ASYNC_STATE_ERROR;
					req->err = res;
					req->errExt = GetLastError();
					/* Just remove the request from the request queue. */
					KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
					res = KSI_OK;
					goto cleanup;
				}

				/* Update state. */
				req->state = KSI_ASYNC_STATE_WAITING_FOR_RESPONSE;
				/* Start receive timeout. */
				req->sndTime = curTime;

				/* The request has been successfully dispatched. Remove it from the request queue. */
				KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
				clientCtx->roundCount++;
			}
		} else {
			/* The state could have been changed in application layer. Just remove the request from the queue. */
			KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
		}
	}

	/* Handle input. */
	res = WinHTTP_handleResponse(clientCtx);
	if (res != KSI_OK) {
		KSI_LOG_debug(clientCtx->ctx, "[%p] Async WinHTTP: Failed to handle response. Error %x.", clientCtx, res);
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


/* TODO: win common. */
static int LPWSTR_new(const char * cstr, LPWSTR *new){
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
	res = LPWSTR_new(host, &clientCtx->host);
	if (res != KSI_OK) goto cleanup;

	if (clientCtx->path) KSI_free(clientCtx->path);
	clientCtx->path = NULL;
	if (path) {
		res = LPWSTR_new(path, &clientCtx->path);
		if (res != KSI_OK) goto cleanup;
	}

	clientCtx->port = port;
	clientCtx->isSecure = (strcmp("https", scheme) == 0);

	if (clientCtx->ksi_user) KSI_free(clientCtx->ksi_user);
	res = KSI_strdup(user, &clientCtx->ksi_user);
	if (res != KSI_OK) goto cleanup;

	if (clientCtx->ksi_pass) KSI_free(clientCtx->ksi_pass);
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
		/* Cleanup WinHTTP handles. */
		if (o->connectHandle != NULL) WinHttpCloseHandle(o->connectHandle);
		if (o->sessionHandle != NULL) WinHttpCloseHandle(o->sessionHandle);

		/* Cleanup queues. */
		KSI_AsyncHandleList_free(o->reqQueue);
		WinHTTPAsyncReqList_free(o->httpQueue);
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

	/* Queues. */
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
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	tmp->criticalSecInitialized = true;

	/* Initialize io queues. */
	res = KSI_AsyncHandleList_new(&tmp->reqQueue);
	if (res != KSI_OK) goto cleanup;
	res = WinHTTPAsyncReqList_new(&tmp->httpQueue);
	if (res != KSI_OK) goto cleanup;
	res = KSI_OctetStringList_new(&tmp->respQueue);
	if (res != KSI_OK) goto cleanup;

	/* TODO: move to options. */
	res = LPWSTR_new("KSI HTTP Client", &tmp->userAgent);
	if (res != KSI_OK) goto cleanup;
	res = LPWSTR_new("Content-Type: application/ksi-request", &tmp->mimeType);
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
	tmp->options[KSI_ASYNC_PRIVOPT_ENDPOINT_ID] = (size_t)netImpl;
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


#endif /* KSI_NET_HTTP_IMPL==KSI_IMPL_WINHTTP */
