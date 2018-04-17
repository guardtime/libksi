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
	char *mimeType;

	/* Round throttling. */
	time_t roundStartAt;
	size_t roundCount;

	/* Poiter to the async options. */
	size_t *options;

	/* Endpoint data. */
	char *ksi_user;
	char *ksi_pass;
	char *url;
};

struct CurlAsyncRequest_st {
	HttpAsyncCtx *client;
	/* Curl easy handle. */
	CURL *easyHandle;
	/* Curl HTTP header list. */
	struct curl_slist *httpHeaders;
	/* Error message. */
	char errMsg[CURL_ERROR_SIZE];
	/* Receive buffer. */
	unsigned char *raw;
	size_t len;
	/* Request context. */
	KSI_AsyncHandle *reqCtx;
};

static void curlAsyncRequest_free(CurlAsyncRequest *t) {
	if (t != NULL) {
		KSI_nofree(t->client);
		KSI_AsyncHandle_free(t->reqCtx);
		KSI_free(t->raw);
		if (t->httpHeaders != NULL) curl_slist_free_all(t->httpHeaders);
		if (t->easyHandle != NULL) curl_easy_cleanup(t->easyHandle);
		KSI_free(t);
	}
}

static int curlAsyncRequest_new(HttpAsyncCtx *client, CurlAsyncRequest **t) {
	int res = KSI_UNKNOWN_ERROR;
	CurlAsyncRequest *tmp = NULL;

	if (client == NULL || t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_malloc(sizeof(CurlAsyncRequest));
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	tmp->client = client;

	tmp->easyHandle = NULL;
	tmp->len = 0;
	tmp->raw = NULL;
	tmp->errMsg[0] = '\0';
	tmp->httpHeaders = NULL;
	tmp->reqCtx = NULL;

	tmp->easyHandle = curl_easy_init();
	if (tmp->easyHandle == NULL) {
		KSI_pushError(client->ctx, res = KSI_OUT_OF_MEMORY, "Curl: Unable to init easy handle.");
		goto cleanup;
	}

	*t = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	curlAsyncRequest_free(tmp);
	return res;
}

static int curlAsyncRequest_processResponse(CurlAsyncRequest *curlResponse) {
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
						"Async Curl HTTP: Unable to extract TLV from input stream",
						curlResponse->raw, curlResponse->len);
				handle->state = KSI_ASYNC_STATE_ERROR;
				handle->err = KSI_NETWORK_ERROR;
				break;
			}
			tlvSize = ftlv.hdr_len + ftlv.dat_len;

			KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG, "Async Curl HTTP: received response", curlResponse->raw + count, tlvSize);

			res = KSI_OctetString_new(clientCtx->ctx, curlResponse->raw + count,  tlvSize, &resp);
			if (res != KSI_OK) {
				KSI_LOG_error(clientCtx->ctx, "Async Curl HTTP: unable to create new KSI_OctetString object. Error: 0x%x.", res);
				res = KSI_OK;
				goto cleanup;
			}

			res = KSI_OctetStringList_append(clientCtx->respQueue, resp);
			if (res != KSI_OK) {
				KSI_LOG_error(clientCtx->ctx, "Async Curl HTTP: unable to add new response to queue. Error: 0x%x.", res);
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
	size_t bytesCount = 0;
	unsigned char *tmp_buffer = NULL;

	bytesCount = curlReq->len + bytesReceived;
	if (bytesCount > UINT_MAX) {
		KSI_LOG_debug(curlReq->client->ctx, "Async Curl HTTP: too many bytes received %llu bytes (%llu so far).",
				(unsigned long long)curlReq->len, (unsigned long long)bytesReceived);
		goto cleanup;
	}
	tmp_buffer = KSI_calloc(bytesCount, 1);
	if (tmp_buffer == NULL) goto cleanup;

	memcpy(tmp_buffer, curlReq->raw, curlReq->len);
	memcpy(tmp_buffer + curlReq->len, ptr, bytesReceived);

	KSI_free(curlReq->raw);
	curlReq->raw = tmp_buffer;
	curlReq->len = bytesCount;
	tmp_buffer = NULL;

	KSI_LOG_debug(curlReq->client->ctx, "0x%p: Async Curl HTTP received %llu bytes (%llu so far).", curlReq,
			(unsigned long long)bytesCount, (unsigned long long)curlReq->len);

	bytesCount = bytesReceived;
cleanup:
	KSI_free(tmp_buffer);
	return bytesCount;
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

static int dispatch(HttpAsyncCtx *clientCtx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_OctetString *resp = NULL;
	int stillRunning = -1;
	int msgQueue;
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
			KSI_LOG_info(clientCtx->ctx, "Async Curl HTTP round request count: %u", (unsigned)clientCtx->roundCount);
			clientCtx->roundCount = 0;
			clientCtx->roundStartAt = curTime;
		}
		/* Check if more requests can be sent within the given timeframe. */
		if (!(clientCtx->roundCount < clientCtx->options[KSI_ASYNC_OPT_MAX_REQUEST_COUNT])) {
			KSI_LOG_debug(clientCtx->ctx, "Async Curl HTTP round max request count reached.");
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
				KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG, "Curl HTTP: Preparing request", req->raw, req->len);

				res = curlAsyncRequest_new(clientCtx, &curlRequest);
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

				if (clientCtx->mimeType != NULL) {
					char header[1024];
					struct curl_slist *slist = NULL;

					KSI_snprintf(header, sizeof(header), "Content-Type: %s", clientCtx->mimeType);
					slist = curl_slist_append(curlRequest->httpHeaders, header);
					if (slist == NULL) {
						KSI_pushError(clientCtx->ctx, res = KSI_INVALID_STATE, "Failed to set mime type.");
						goto cleanup;
					}
					curlRequest->httpHeaders = slist;
					curl_easy_setopt(curlRequest->easyHandle, CURLOPT_HTTPHEADER, curlRequest->httpHeaders);
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
				curl_multi_add_handle(clientCtx->curl->handle, curlRequest->easyHandle);
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

	while((curlmCode = curl_multi_perform(clientCtx->curl->handle, &stillRunning)) == CURLM_CALL_MULTI_PERFORM);
	if (curlmCode != CURLM_OK) {
		KSI_LOG_error(clientCtx->ctx, "Async Curl HTTP returned error. Error: %d (%s).", curlmCode, curl_multi_strerror(curlmCode));
		reqQueue_clearWithError(clientCtx->reqQueue, KSI_NETWORK_ERROR, curlmCode);
		res = KSI_OK;
		goto cleanup;
	}

	/* Sanity check. */
	if (stillRunning < 0) {
		KSI_pushError(clientCtx->ctx, res = KSI_UNKNOWN_ERROR, "Curl returned a negative count of still running queries.");
		goto cleanup;
	}

	/* Check if any transfer has completed. */
	while ((curlMsg = curl_multi_info_read(clientCtx->curl->handle, &msgQueue)) &&
			(curlMsg->msg == CURLMSG_DONE)) {
		CURLcode curlCode;

		curlResponse = NULL;
		curlCode = curl_easy_getinfo(curlMsg->easy_handle, CURLINFO_PRIVATE, (char **)&curlResponse);
		if (curlCode != CURLE_OK || curlResponse == NULL) {
			KSI_LOG_error(clientCtx->ctx, "Async Curl HTTP: Failed to read private pointer.");
		} else {
			KSI_AsyncHandle *handle = NULL;

			handle = curlResponse->reqCtx;
			if (curlMsg->data.result != CURLE_OK) {
				size_t len = strlen(curlResponse->errMsg);
				KSI_LOG_error(clientCtx->ctx, "Async Curl HTTP: error result %d (%s).", curlMsg->data.result, curlResponse->errMsg);
				handle->state = KSI_ASYNC_STATE_ERROR;
				handle->err = KSI_NETWORK_ERROR;
				handle->errExt = curlMsg->data.result;
				if (len) KSI_Utf8String_new(clientCtx->ctx, curlResponse->errMsg, len + 1, &handle->errMsg);
			} else {
				long httpCode = 0;

				/* Read HTTP error code. */
				if (curl_easy_getinfo(curlMsg->easy_handle, CURLINFO_RESPONSE_CODE, &httpCode) == CURLE_OK ||
					curl_easy_getinfo(curlMsg->easy_handle, CURLINFO_HTTP_CODE, &httpCode) == CURLE_OK) {
					KSI_LOG_debug(clientCtx->ctx, "Async Curl HTTP: Async received HTTP status code %ld.", httpCode);
				}

				if (httpCode >= 400 && httpCode < 600) {
					size_t len = strlen(curlResponse->errMsg);
					KSI_LOG_debug(clientCtx->ctx, "Async Curl HTTP: received HTTP code %ld. Curl error '%s'.", httpCode, curlResponse->errMsg);
					handle->state = KSI_ASYNC_STATE_ERROR;
					handle->err = KSI_HTTP_ERROR;
					handle->errExt = httpCode;
					if (len) KSI_Utf8String_new(clientCtx->ctx, curlResponse->errMsg, len + 1, &handle->errMsg);
				} else {
					/* Process responses for all active clients. */
					res = curlAsyncRequest_processResponse(curlResponse);
					if (res != KSI_OK) {
						KSI_LOG_error(clientCtx->ctx, "Async Curl HTTP: unable to process curl response. Error: 0x%x.", res);
						KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_ERROR, "Async Curl HTTP: response stream", curlResponse->raw, curlResponse->len);
						res = KSI_OK;
						goto cleanup;
					}
				}
			}
		}
		curl_multi_remove_handle(clientCtx->curl->handle, curlMsg->easy_handle);
		curlMsg = NULL;
		curlAsyncRequest_free(curlResponse);
		curlResponse = NULL;
	}

	res = KSI_OK;
cleanup:
	curlAsyncRequest_free(curlRequest);

	if (curlResponse != NULL) {
		curl_multi_remove_handle(clientCtx->curl->handle, curlResponse->easyHandle);
		curlAsyncRequest_free(curlResponse);
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
				curlAsyncRequest_free((CurlAsyncRequest *)curlPriv);
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

		KSI_free(o->userAgent);
		KSI_free(o->mimeType);

		/* Cleanup endpoint data. */
		KSI_free(o->url);
		KSI_free(o->ksi_user);
		KSI_free(o->ksi_pass);

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
	tmp->mimeType = NULL;
	tmp->roundStartAt = 0;
	tmp->roundCount = 0;

	/* Queues. */
	tmp->reqQueue = NULL;
	tmp->respQueue = NULL;

	/* Endpoint. */
	tmp->ksi_user = NULL;
	tmp->ksi_pass = NULL;
	tmp->url = NULL;

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

	/* TODO: move to options. */
	res = KSI_strdup("KSI HTTP Client", &tmp->userAgent);
	if (res != KSI_OK) goto cleanup;
	res = KSI_strdup("application/ksi-request", &tmp->mimeType);
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
