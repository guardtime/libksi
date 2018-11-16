/*
 * Copyright 2013-2018 Guardtime, Inc.
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

#if KSI_NET_HTTP_IMPL==KSI_IMPL_CURL

#include <string.h>
#include <sys/types.h>

#include <curl/curl.h>

#include "net_http.h"
#include "impl/net_async_impl.h"
#include "net_async.h"
#include "tlv.h"
#include "fast_tlv.h"
#include "types.h"
#include "list.h"

typedef struct HttpAsyncCtx_st HttpAsyncCtx;
typedef struct CurlMulti_st CurlMulti;
typedef struct CurlAsyncRequest_st CurlAsyncRequest;

static void CurlAsyncRequest_free(CurlAsyncRequest *t);

KSI_DEFINE_LIST(CurlAsyncRequest)
#define CurlAsyncRequestList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define CurlAsyncRequestList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define CurlAsyncRequestList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define CurlAsyncRequestList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define CurlAsyncRequestList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define CurlAsyncRequestList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define CurlAsyncRequestList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define CurlAsyncRequestList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define CurlAsyncRequestList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)
#define CurlAsyncRequestList_find(lst, o,f, i) KSI_APPLY_TO_NOT_NULL((lst), find, ((lst), (o), (f), (i)))
KSI_IMPLEMENT_LIST(CurlAsyncRequest, CurlAsyncRequest_free)

struct CurlMulti_st {
	size_t initCount;
	CURLM *handle;
};

struct HttpAsyncCtx_st {
	KSI_CTX *ctx;

	/* Curl multi handle. */
	CurlMulti *curl;

	/* Output queue. */
	KSI_LIST(KSI_AsyncHandle) *reqQueue;
	/* Input queue. */
	KSI_LIST(KSI_OctetString) *respQueue;

	/* HTTP header fields. */
	char *userAgent;
	struct curl_slist *httpHeaders;

	/* Round throttling. */
	time_t roundStartAt;
	size_t roundCount;

	/* Poiter to the async options. */
	size_t *options;

	/* Endpoint data. */
	char *ksi_user;
	char *ksi_pass;
	char *url;

	/* This list is used to recycle #CurlAsyncRequest objects to reduce the number of allocs. */
	KSI_LIST(CurlAsyncRequest) *reqRecycle;
};

struct CurlAsyncRequest_st {
	size_t ref;
	HttpAsyncCtx *client;
	/* Curl easy handle. */
	CURL *easyHandle;
	/* Error message. */
	char errMsg[CURL_ERROR_SIZE];
	/* Receive buffer. */
	unsigned char *raw;
	size_t len;
	size_t cap;
	/* Request context. */
	KSI_AsyncHandle *reqCtx;
};

static void CurlAsyncRequest_free(CurlAsyncRequest *t) {
	if (t == NULL) return;
	if (t->ref == 0) goto cleanup;
	if (--t->ref == 0) {
		if (t->client == NULL || CurlAsyncRequestList_append(t->client->reqRecycle, t) != KSI_OK) goto cleanup;
		return;
	}
cleanup:
	KSI_nofree(t->client);
	KSI_AsyncHandle_free(t->reqCtx);
	KSI_free(t->raw);
	if (t->easyHandle != NULL) curl_easy_cleanup(t->easyHandle);
	KSI_free(t);
}

static int CurlAsyncRequest_new(HttpAsyncCtx *client, CurlAsyncRequest **t) {
	int res = KSI_UNKNOWN_ERROR;
	CurlAsyncRequest *tmp = NULL;
	size_t len;

	if (client == NULL || t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if ((len = CurlAsyncRequestList_length(client->reqRecycle)) > 0) {
		res = CurlAsyncRequestList_remove(client->reqRecycle, len - 1, &tmp);
		if (res != KSI_OK) goto cleanup;

		curl_easy_reset(tmp->easyHandle);
		KSI_AsyncHandle_free(tmp->reqCtx);
	} else {
		tmp = KSI_malloc(sizeof(CurlAsyncRequest));
		if (tmp == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}
		tmp->ref = 0;

		tmp->cap = 0;
		tmp->raw = NULL;

		tmp->easyHandle = curl_easy_init();
		if (tmp->easyHandle == NULL) {
			KSI_pushError(client->ctx, res = KSI_OUT_OF_MEMORY, "Curl: Unable to init easy handle.");
			goto cleanup;
		}
	}
	tmp->ref = 1;

	tmp->client = client;
	tmp->errMsg[0] = '\0';
	tmp->reqCtx = NULL;
	/* Reset the receive buffer tail. */
	tmp->len = 0;

	*t = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	CurlAsyncRequest_free(tmp);
	return res;
}

static int CurlAsyncRequest_processResponse(CurlAsyncRequest *curlResponse) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_OctetString *resp = NULL;
	HttpAsyncCtx *clientCtx = NULL;
	KSI_AsyncHandle *handle = NULL;

	if (curlResponse == NULL || curlResponse->client == NULL || curlResponse->reqCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	clientCtx = curlResponse->client;
	handle = curlResponse->reqCtx;

	KSI_ERR_clearErrors(clientCtx->ctx);

	if (handle->state == KSI_ASYNC_STATE_WAITING_FOR_RESPONSE) {
		size_t count = 0;

		/* The stream might contain several response PDUs. */
		while (count < curlResponse->len) {
			KSI_FTLV ftlv;
			size_t tlvSize = 0;

			/* Traverse through the input stream and verify that a complete TLV is present. */
			memset(&ftlv, 0, sizeof(KSI_FTLV));
			res = KSI_FTLV_memRead(curlResponse->raw + count, curlResponse->len - count, &ftlv);
			if (res != KSI_OK) {
				KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_ERROR,
						"[%p] Async Curl HTTP: [%p] unable to extract TLV from input stream",
						curlResponse->raw, curlResponse->len,
						clientCtx, curlResponse);
				handle->state = KSI_ASYNC_STATE_ERROR;
				handle->err = KSI_NETWORK_ERROR;
				break;
			}
			tlvSize = ftlv.hdr_len + ftlv.dat_len;

			KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG,
					"[%p] Async Curl HTTP: [%p] received response",
					curlResponse->raw + count, tlvSize,
					clientCtx, curlResponse);

			res = KSI_OctetString_new(clientCtx->ctx, curlResponse->raw + count,  tlvSize, &resp);
			if (res != KSI_OK) {
				KSI_LOG_error(clientCtx->ctx,
						"[%p] Async Curl HTTP: unable to create new KSI_OctetString object. Error: 0x%x.",
						clientCtx, res);
				res = KSI_OK;
				goto cleanup;
			}

			res = KSI_OctetStringList_append(clientCtx->respQueue, resp);
			if (res != KSI_OK) {
				KSI_LOG_error(clientCtx->ctx,
						"[%p] Async Curl HTTP: unable to add new response to queue. Error: 0x%x.",
						clientCtx, res);
				res = KSI_OK;
				goto cleanup;
			}
			resp = NULL;

			count += tlvSize;
		}
	}

	res = KSI_OK;
cleanup:
	KSI_OctetString_free(resp);
	return res;
}

static size_t curlCallback_receive(char *ptr, size_t size, size_t nmemb, void *userdata) {
	const size_t bytesReceived = size * nmemb;
	CurlAsyncRequest *curlReq = (CurlAsyncRequest*)userdata;
	size_t totalCount = 0;
	unsigned char *tmp_buffer = NULL;

	/* Just for safety, should never happen */
	if (curlReq == NULL) {
		/* The callback should return the number of bytes actually taken care of. If that amount differs from the
		 * amount passed to the callback function, it'll signal an error condition to the libcurl. This will cause
		 * the transfer to get aborted and the libcurl function used will return CURLE_WRITE_ERROR.
		 */
		totalCount = bytesReceived + 1;
		goto cleanup;
	}

	totalCount = curlReq->len + bytesReceived;
	if (totalCount > UINT_MAX) {
		KSI_LOG_debug(curlReq->client->ctx,
				"[%p] Async Curl HTTP: [%p] too many bytes received %llu bytes (%llu so far).",
				curlReq->client, curlReq,
				(unsigned long long)curlReq->len, (unsigned long long)bytesReceived);
		goto cleanup;
	}

	if (totalCount > curlReq->cap) {
		size_t newCap = totalCount + 255;
		tmp_buffer = KSI_calloc(newCap, sizeof(unsigned char));
		if (tmp_buffer == NULL) goto cleanup;
		curlReq->cap = newCap;

		memcpy(tmp_buffer, curlReq->raw, curlReq->len);
		KSI_free(curlReq->raw);
	} else {
		tmp_buffer = curlReq->raw;
	}
	memcpy(tmp_buffer + curlReq->len, ptr, bytesReceived);
	curlReq->raw = tmp_buffer;
	curlReq->len = totalCount;
	tmp_buffer = NULL;

	KSI_LOG_debug(curlReq->client->ctx, "0x%p: Async Curl HTTP received %llu bytes (%llu so far).", curlReq,
			(unsigned long long)bytesReceived, (unsigned long long)curlReq->len);

	totalCount = bytesReceived;
cleanup:
	KSI_free(tmp_buffer);
	return totalCount;
}

static void reqQueue_clearWithError(KSI_AsyncHandleList *reqQueue, int err, long ext, const char *msg) {
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
		if (msg) KSI_Utf8String_new(req->ctx, msg, strlen(msg)+1, &req->errMsg);

		KSI_AsyncHandle_free(req);
	}
}

static int dispatch(HttpAsyncCtx *clientCtx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_OctetString *resp = NULL;
	int queueSize = -1;
	CURLMcode curlmCode;
	CURLMsg *curlMsg = NULL;
	CurlAsyncRequest *curlRequest = NULL;
	CurlAsyncRequest *curlResponse = NULL;
	KSI_AsyncHandle *req = NULL;

	if (clientCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(clientCtx->ctx);

	if (clientCtx->curl == NULL) {
		KSI_pushError(clientCtx->ctx, res = KSI_INVALID_STATE, "Curl multi handle is not initialized.");
		goto cleanup;
	}

	/* Handle output. */
	/* Add all requests to the curl multi handle. */
	while (KSI_AsyncHandleList_length(clientCtx->reqQueue) > 0 &&
				KSI_AsyncHandleList_elementAt(clientCtx->reqQueue, 0, &req) == KSI_OK && req != NULL) {
		time_t curTime = 0;

		/* Check if the request count can be restarted. */
		if (difftime(time(&curTime), clientCtx->roundStartAt) >= clientCtx->options[KSI_ASYNC_PRIVOPT_ROUND_DURATION]) {
			KSI_LOG_info(clientCtx->ctx, "[%p] Async Curl HTTP: round request count: %u", clientCtx,
					(unsigned)clientCtx->roundCount);
			clientCtx->roundCount = 0;
			clientCtx->roundStartAt = curTime;
		}
		/* Check if more requests can be sent within the given timeframe. */
		if (!(clientCtx->roundCount < clientCtx->options[KSI_ASYNC_OPT_MAX_REQUEST_COUNT])) {
			KSI_LOG_debug(clientCtx->ctx, "[%p] Async Curl HTTP: round max request count reached.", clientCtx);
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
				KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG,
						"[%p] Async Curl HTTP: Preparing request", req->raw, req->len, clientCtx);

				res = CurlAsyncRequest_new(clientCtx, &curlRequest);
				if (res != KSI_OK) {
					KSI_pushError(clientCtx->ctx, res, NULL);
					goto cleanup;
				}
				/* Keep a reference to the request for handling error response. */
				curlRequest->reqCtx = KSI_AsyncHandle_ref(req);

				/* Setup curl easy handle. */
				curl_easy_setopt(curlRequest->easyHandle, CURLOPT_VERBOSE, 0);
				curl_easy_setopt(curlRequest->easyHandle, CURLOPT_WRITEFUNCTION, curlCallback_receive);
				curl_easy_setopt(curlRequest->easyHandle, CURLOPT_NOPROGRESS, 1);

				/* Make sure cURL won't use signals. */
				curl_easy_setopt(curlRequest->easyHandle, CURLOPT_NOSIGNAL, 1);

				/* Use SSL for both control and data. */
				curl_easy_setopt(curlRequest->easyHandle, CURLOPT_USE_SSL, CURLUSESSL_ALL);

				curl_easy_setopt(curlRequest->easyHandle, CURLOPT_ERRORBUFFER, curlRequest->errMsg);

				if (clientCtx->userAgent != NULL) {
					curl_easy_setopt(curlRequest->easyHandle, CURLOPT_USERAGENT, clientCtx->userAgent);
				}
				if (clientCtx->httpHeaders != NULL) {
					curl_easy_setopt(curlRequest->easyHandle, CURLOPT_HTTPHEADER, clientCtx->httpHeaders);
				}

				if (req->raw != NULL) {
					curl_easy_setopt(curlRequest->easyHandle, CURLOPT_POST, 1);
					curl_easy_setopt(curlRequest->easyHandle, CURLOPT_POSTFIELDS, (char *)req->raw);
					curl_easy_setopt(curlRequest->easyHandle, CURLOPT_POSTFIELDSIZE, (long)req->len);
				} else {
					curl_easy_setopt(curlRequest->easyHandle, CURLOPT_POST, 0);
				}

				curl_easy_setopt(curlRequest->easyHandle, CURLOPT_WRITEDATA, curlRequest);
				curl_easy_setopt(curlRequest->easyHandle, CURLOPT_PRIVATE, curlRequest);

				curl_easy_setopt(curlRequest->easyHandle, CURLOPT_CONNECTTIMEOUT, clientCtx->options[KSI_ASYNC_OPT_CON_TIMEOUT]);

				curl_easy_setopt(curlRequest->easyHandle, CURLOPT_URL, clientCtx->url);

				/* Add easy handle to the multi handle. */
				curlmCode = curl_multi_add_handle(clientCtx->curl->handle, curlRequest->easyHandle);
				if (curlmCode != CURLM_OK) {
					KSI_LOG_error(clientCtx->ctx, "[%p] Async Curl HTTP: returned error. Error: %d (%s).",
							clientCtx, curlmCode, curl_multi_strerror(curlmCode));
					reqQueue_clearWithError(clientCtx->reqQueue, KSI_NETWORK_ERROR, curlmCode, curl_multi_strerror(curlmCode));
					res = KSI_OK;
					goto cleanup;
				}

				curlRequest = NULL;
				clientCtx->roundCount++;

				/* Update state. */
				req->state = KSI_ASYNC_STATE_WAITING_FOR_RESPONSE;
				/* Start receive timeout. */
				req->sndTime = curTime;
				/* The request has been successfully dispatched. Remove it from the request queue. */
				KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
			}
		} else {
			/* The state could have been changed in application layer. Just remove the request from the request queue. */
			KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
		}
	}

	while((curlmCode = curl_multi_perform(clientCtx->curl->handle, &queueSize)) == CURLM_CALL_MULTI_PERFORM);
	if (curlmCode != CURLM_OK) {
		KSI_LOG_error(clientCtx->ctx, "[%p] Async Curl HTTP: returned error. Error: %d (%s).",
				clientCtx, curlmCode, curl_multi_strerror(curlmCode));
		reqQueue_clearWithError(clientCtx->reqQueue, KSI_NETWORK_ERROR, curlmCode, curl_multi_strerror(curlmCode));
		res = KSI_OK;
		goto cleanup;
	}

	/* Sanity check. */
	if (queueSize < 0) {
		KSI_pushError(clientCtx->ctx, res = KSI_UNKNOWN_ERROR, "Curl returned a negative count of still running queries.");
		goto cleanup;
	}

	/* Check if any transfer has completed. */
	while ((curlMsg = curl_multi_info_read(clientCtx->curl->handle, &queueSize)) &&
			(curlMsg->msg == CURLMSG_DONE)) {
		CURLcode curlCode;

		curlResponse = NULL;
		curlCode = curl_easy_getinfo(curlMsg->easy_handle, CURLINFO_PRIVATE, (char **)&curlResponse);
		if (curlCode != CURLE_OK || curlResponse == NULL) {
			KSI_LOG_error(clientCtx->ctx, "[%p] Async Curl HTTP: Failed to read private pointer.", clientCtx);
		} else {
			KSI_AsyncHandle *handle = NULL;

			handle = curlResponse->reqCtx;
			if (curlMsg->data.result != CURLE_OK) {
				size_t len = strlen(curlResponse->errMsg);
				KSI_LOG_error(clientCtx->ctx, "[%p] Async Curl HTTP: error result %d (%s).",
						clientCtx, curlMsg->data.result, curlResponse->errMsg);
				handle->state = KSI_ASYNC_STATE_ERROR;
				handle->err = KSI_NETWORK_ERROR;
				handle->errExt = curlMsg->data.result;
				if (len) KSI_Utf8String_new(clientCtx->ctx, curlResponse->errMsg, len + 1, &handle->errMsg);
			} else {
				long httpCode = 0;

				/* Read HTTP error code. */
				if (curl_easy_getinfo(curlMsg->easy_handle, CURLINFO_RESPONSE_CODE, &httpCode) == CURLE_OK ||
					curl_easy_getinfo(curlMsg->easy_handle, CURLINFO_HTTP_CODE, &httpCode) == CURLE_OK) {
					KSI_LOG_debug(clientCtx->ctx, "[%p] Async Curl HTTP: Async received HTTP status code %ld.",
							clientCtx, httpCode);
				}

				if (httpCode >= 400 && httpCode < 600) {
					size_t len = strlen(curlResponse->errMsg);
					KSI_LOG_debug(clientCtx->ctx, "[%p] Async Curl HTTP: received HTTP code %ld.", clientCtx, httpCode);
					handle->state = KSI_ASYNC_STATE_ERROR;
					handle->err = KSI_HTTP_ERROR;
					handle->errExt = httpCode;
					if (len) KSI_Utf8String_new(clientCtx->ctx, curlResponse->errMsg, len + 1, &handle->errMsg);
				} else {
					/* Process responses for all active clients. */
					res = CurlAsyncRequest_processResponse(curlResponse);
					if (res != KSI_OK) {
						KSI_LOG_error(clientCtx->ctx, "[%p] Async Curl HTTP: unable to process curl response. Error: 0x%x.",
								clientCtx, res);
						res = KSI_OK;
						goto cleanup;
					}
				}
			}
		}
		curl_multi_remove_handle(clientCtx->curl->handle, curlMsg->easy_handle);
		curlMsg = NULL;
		CurlAsyncRequest_free(curlResponse);
		curlResponse = NULL;
	}

	res = KSI_OK;
cleanup:
	CurlAsyncRequest_free(curlRequest);

	if (curlResponse != NULL) {
		curl_multi_remove_handle(clientCtx->curl->handle, curlResponse->easyHandle);
		CurlAsyncRequest_free(curlResponse);
	}

	KSI_OctetString_free(resp);
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

	if (clientCtx == NULL || url == NULL || user == NULL || pass == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (clientCtx->url) KSI_free(clientCtx->url);
	res = KSI_strdup(url, &clientCtx->url);
	if (res != KSI_OK) goto cleanup;

	if (clientCtx->ksi_user) KSI_free(clientCtx->ksi_user);
	res = KSI_strdup(user, &clientCtx->ksi_user);
	if (res != KSI_OK) goto cleanup;

	if (clientCtx->ksi_pass) KSI_free(clientCtx->ksi_pass);
	res = KSI_strdup(pass, &clientCtx->ksi_pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;
cleanup:
	return res;
}

static int getCredentials(HttpAsyncCtx *asyncCtx, const char **user, const char **pass) {
	if (asyncCtx == NULL) return KSI_INVALID_ARGUMENT;
	if (user != NULL) *user = asyncCtx->ksi_user;
	if (pass != NULL) *pass = asyncCtx->ksi_pass;
	return KSI_OK;
}

static CurlMulti *_curlMulti = NULL;

static void CurlMulti_free(CurlMulti *o) {
	if (o != NULL) {
		int msgCount = 0;

		/* Cleanup curl easy handles attached to the multi handle. */
		do {
			CURLMsg *msg;
			msg = curl_multi_info_read(o->handle, &msgCount);
			if (msg) {
				char *curlPriv = NULL;
				curl_multi_remove_handle(o->handle, msg->easy_handle);
				curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &curlPriv);
				CurlAsyncRequest_free((CurlAsyncRequest *)curlPriv);
			}
		} while (msgCount);
		curl_multi_cleanup(_curlMulti->handle);

		KSI_free(o);
	}
}

static CurlMulti *curlMulti_init(void) {
	CurlMulti *tmp = NULL;

	if (_curlMulti == NULL) {
		tmp = KSI_new(CurlMulti);
		if (tmp == NULL) goto cleanup;

		tmp->handle = NULL;
		tmp->initCount = 0;

		if ((tmp->handle = curl_multi_init()) == NULL) goto cleanup;

#ifdef LIMIT_MAXCONNS
		/* Limit the total amount of connections this multi handle uses. */
		curl_multi_setopt(curlMulti->handle, CURLMOPT_MAXCONNECTS, (long)count);
#endif

		_curlMulti = tmp;
		tmp = NULL;
	}
	_curlMulti->initCount++;
cleanup:
	CurlMulti_free(tmp);
	return _curlMulti;
}

static void curlMulti_cleanup(void) {
	if (_curlMulti != NULL && --_curlMulti->initCount == 0) {
		CurlMulti_free(_curlMulti);
		_curlMulti = NULL;
	}
}

static void HttpAsyncCtx_free(HttpAsyncCtx *o) {
	if (o != NULL) {
		curlMulti_cleanup();

		/* Cleanup queues. */
		KSI_AsyncHandleList_free(o->reqQueue);
		KSI_OctetStringList_free(o->respQueue);

		KSI_nofree(o->userAgent);
		if (o->httpHeaders != NULL) curl_slist_free_all(o->httpHeaders);

		/* Cleanup endpoint data. */
		KSI_free(o->url);
		KSI_free(o->ksi_user);
		KSI_free(o->ksi_pass);

		CurlAsyncRequestList_free(o->reqRecycle);

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
	tmp->curl = NULL;

	tmp->options = NULL;
	tmp->userAgent = NULL;
	tmp->httpHeaders = NULL;
	tmp->roundStartAt = 0;
	tmp->roundCount = 0;

	/* Queues. */
	tmp->reqQueue = NULL;
	tmp->respQueue = NULL;

	/* Endpoint. */
	tmp->ksi_user = NULL;
	tmp->ksi_pass = NULL;
	tmp->url = NULL;

	/* Recycling. */
	tmp->reqRecycle = NULL;

	res = KSI_Http_init(ctx);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->curl = curlMulti_init();
	if (tmp->curl == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, "Curl: Unable to init multi handle.");
		goto cleanup;
	}

	/* Initialize io queues. */
	res = KSI_AsyncHandleList_new(&tmp->reqQueue);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OctetStringList_new(&tmp->respQueue);
	if (res != KSI_OK) goto cleanup;

	tmp->userAgent = "KSI HTTP Client";
	tmp->httpHeaders = curl_slist_append(tmp->httpHeaders,  "Content-Type: application/ksi-request");
	if (tmp->httpHeaders == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "Curl: Failed to set mime type.");
		goto cleanup;
	}

	res = CurlAsyncRequestList_new(&tmp->reqRecycle);
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

#endif /* KSI_NET_HTTP_IMPL==KSI_IMPL_CURL */
