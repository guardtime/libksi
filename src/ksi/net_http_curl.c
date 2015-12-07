/*
 * Copyright 2013-2015 Guardtime, Inc.
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

#include <curl/curl.h>
#include <string.h>

#include "net_http_impl.h"
#include "net_impl.h"

static size_t curlGlobal_initCount = 0;

typedef struct CurlNetHandleCtx_st {
	KSI_CTX *ctx;
	CURL *curl;
	unsigned char *raw;
	size_t len;
	struct curl_slist *httpHeaders;
	char curlErr[CURL_ERROR_SIZE];
} CurlNetHandleCtx;

static int curlGlobal_init(void) {
	int res = KSI_UNKNOWN_ERROR;

	if (curlGlobal_initCount++ > 0) {
		/* Nothing to do */
		return KSI_OK;
	}

	if (curl_global_init(CURLUSESSL_ALL) != CURLE_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static void curlGlobal_cleanup(void) {
	if (--curlGlobal_initCount > 0) {
		/* Nothing to do. */
		return;
	}
	curl_global_cleanup();
}

static void CurlNetHandleCtx_free(CurlNetHandleCtx *handleCtx) {
	if (handleCtx != NULL) {
		KSI_free(handleCtx->raw);
		if (handleCtx->httpHeaders != NULL) curl_slist_free_all(handleCtx->httpHeaders);
		if (handleCtx->curl != NULL) curl_easy_cleanup(handleCtx->curl);
		KSI_free(handleCtx);
	}
}

static int CurlNetHandleCtx_new(KSI_CTX *ctx, CurlNetHandleCtx **handleCtx) {
	int res = KSI_UNKNOWN_ERROR;
	CurlNetHandleCtx *tmp = NULL;

	if (handleCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(CurlNetHandleCtx);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->curl = NULL;
	tmp->len = 0;
	tmp->raw = NULL;
	tmp->curlErr[0] = '\0';
	tmp->httpHeaders = NULL;


	*handleCtx = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	CurlNetHandleCtx_free(tmp);

return res;
}

static size_t receiveDataFromLibCurl(void *ptr, size_t size, size_t nmemb, void *stream) {
	size_t bytesCount = 0;
	unsigned char *tmp_buffer = NULL;
	CurlNetHandleCtx *nc = (CurlNetHandleCtx *) stream;

	bytesCount = nc->len + size * nmemb;
	if (bytesCount > UINT_MAX) {
		goto cleanup;
	}
	tmp_buffer = KSI_calloc(bytesCount, 1);
	if (tmp_buffer == NULL) goto cleanup;

	memcpy(tmp_buffer, nc->raw, nc->len);
	memcpy(tmp_buffer + nc->len, ptr, size * nmemb);

	KSI_free(nc->raw);
	nc->raw = tmp_buffer;
	nc->len = bytesCount;
	tmp_buffer = NULL;

	KSI_LOG_debug(nc->ctx, "0x%x: Received %llu bytes (%llu so far)", nc, (unsigned long long) bytesCount, nc->len);

	bytesCount = size * nmemb;

cleanup:

	KSI_free(tmp_buffer);
	return bytesCount;
}

static int updateStatus(KSI_RequestHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	CurlNetHandleCtx *impl = NULL;
	CURLcode cc;
	long httpCode = 0;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	impl = handle->implCtx;
	if (impl == NULL) {
		res = KSI_UNKNOWN_ERROR;
		goto cleanup;
	}

	cc = curl_easy_getinfo(impl->curl, CURLINFO_RESPONSE_CODE, &httpCode);
	if (cc != CURLE_OK) {
		res = KSI_UNKNOWN_ERROR;
		goto cleanup;
	}

	handle->err.code = httpCode;

	res = KSI_OK;

cleanup:

	return res;
}

static int curlReceive(KSI_RequestHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	CurlNetHandleCtx *implCtx = NULL;
	KSI_HttpClient *http = NULL;
	long httpCode;

	if (handle == NULL || handle->client == NULL || handle->implCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(handle->ctx);

	http = handle->client->impl;

	implCtx = handle->implCtx;

	KSI_LOG_debug(handle->ctx, "Sending request.");

    res = curl_easy_perform(implCtx->curl);
    KSI_LOG_debug(handle->ctx, "Received %llu bytes.", (unsigned long long)implCtx->len);

	if (curl_easy_getinfo(implCtx->curl, CURLINFO_HTTP_CODE, &httpCode) == CURLE_OK) {
		updateStatus(handle);
		KSI_LOG_debug(handle->ctx, "Received HTTP error code %d. Curl error '%s'.", httpCode, implCtx->curlErr);
	}

	if (res != CURLE_OK) {
		KSI_pushError(handle->ctx, res = KSI_NETWORK_ERROR, implCtx->curlErr);
		goto cleanup;
	}

    res = KSI_RequestHandle_setResponse(handle, implCtx->raw, implCtx->len);
    if (res != KSI_OK) {
    	KSI_pushError(handle->ctx, res, NULL);
    	goto cleanup;
    }

    /* Cleanup on success.*/
    KSI_free(implCtx->raw);
    implCtx->raw = NULL;
    implCtx->len = 0;
    handle->completed = true;

    res = KSI_OK;

cleanup:

	return res;
}

static int sendRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *url) {
	int res = KSI_UNKNOWN_ERROR;
	CurlNetHandleCtx *implCtx = NULL;
	KSI_HttpClient *http = client->impl;
	char mimeTypeHeader[1024];

	if (client == NULL || client->ctx == NULL || handle == NULL || url == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(client->ctx);

	res = CurlNetHandleCtx_new(client->ctx, &implCtx);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_debug(handle->ctx, "Curl: Preparing request to: %s", url);

	implCtx->curl = curl_easy_init();
	if (implCtx->curl == NULL) {
		KSI_pushError(client->ctx, res = KSI_OUT_OF_MEMORY, "Unable to init CURL.");
		goto cleanup;
	}

    curl_easy_setopt(implCtx->curl, CURLOPT_VERBOSE, 0);
	curl_easy_setopt(implCtx->curl, CURLOPT_WRITEFUNCTION, receiveDataFromLibCurl);
	curl_easy_setopt(implCtx->curl, CURLOPT_NOPROGRESS, 1);

    curl_easy_setopt(implCtx->curl, CURLOPT_ERRORBUFFER, implCtx->curlErr);
    if (http->agentName != NULL) {
    	curl_easy_setopt(implCtx->curl, CURLOPT_USERAGENT, http->agentName);
    }

	if (http->mimeType != NULL) {
		KSI_snprintf(mimeTypeHeader, sizeof(mimeTypeHeader) ,"Content-Type: %s", http->mimeType);
		implCtx->httpHeaders = curl_slist_append(implCtx->httpHeaders, mimeTypeHeader);
		curl_easy_setopt(implCtx->curl, CURLOPT_HTTPHEADER, implCtx->httpHeaders);
	}

	if (handle->request != NULL) {
		curl_easy_setopt(implCtx->curl, CURLOPT_POST, 1);
		curl_easy_setopt(implCtx->curl, CURLOPT_POSTFIELDS, (char *)handle->request);
		curl_easy_setopt(implCtx->curl, CURLOPT_POSTFIELDSIZE, (long)handle->request_length);
	} else {
		curl_easy_setopt(implCtx->curl, CURLOPT_POST, 0);
	}

    curl_easy_setopt(implCtx->curl, CURLOPT_WRITEDATA, implCtx);

    curl_easy_setopt(implCtx->curl, CURLOPT_CONNECTTIMEOUT, http->connectionTimeoutSeconds);
    curl_easy_setopt(implCtx->curl, CURLOPT_TIMEOUT, http->readTimeoutSeconds);

	curl_easy_setopt(implCtx->curl, CURLOPT_URL, url);

	handle->readResponse = curlReceive;
	handle->client = client;

    res = KSI_RequestHandle_setImplContext(handle, implCtx, (void (*)(void *))CurlNetHandleCtx_free);
    if (res != KSI_OK) {
    	KSI_pushError(handle->ctx, res, NULL);
    	goto cleanup;
    }

    implCtx = NULL;

    res = KSI_OK;

cleanup:

	CurlNetHandleCtx_free(implCtx);

	return res;
}

static int performN(KSI_NetworkClient *client, KSI_RequestHandle **arr, size_t arr_len) {
	int res = KSI_UNKNOWN_ERROR;
	CURLM *cm = NULL;
	CURLMcode cres;
	size_t i;
	int count;
	char buf[1024];
	fd_set fdread;
	fd_set fdwrite;
	fd_set fdexcep;
	int maxfd = -1;
	struct timeval timeout;

	FD_ZERO(&fdread);
	FD_ZERO(&fdwrite);
	FD_ZERO(&fdexcep);

	if (client == NULL || (arr == NULL && arr_len != 0)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(client->ctx);

	KSI_LOG_debug(client->ctx, "Starting cURL multi perform.");

	timeout.tv_sec = 0;
	timeout.tv_usec = 100;

	cm = curl_multi_init();
	if (cm == NULL) {
		KSI_pushError(client->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	for (i = 0; i < arr_len; i++) {
		CurlNetHandleCtx *pctx = arr[i]->implCtx;
		cres = curl_multi_add_handle(cm, pctx->curl);
		if (cres != CURLM_OK) {
			KSI_snprintf(buf, sizeof(buf), "Curl error occurred: %s", curl_multi_strerror(cres));
			KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, buf);
			goto cleanup;
		}
	}

	curl_multi_setopt(cm, CURLMOPT_PIPELINING, 1);

	do {
		cres  = curl_multi_fdset(cm, &fdread, &fdwrite, &fdexcep, &maxfd);
		if (cres != CURLM_OK) {
			KSI_snprintf(buf, sizeof(buf), "Curl error occurred: %s", curl_multi_strerror(cres));
			KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, buf);
			goto cleanup;
		}

		select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

		cres = curl_multi_perform(cm, &count);
		if (cres != CURLM_OK && cres != CURLM_CALL_MULTI_PERFORM) {
			KSI_snprintf(buf, sizeof(buf), "Curl error occurred: %s", curl_multi_strerror(cres));
			KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, buf);
			goto cleanup;
		}
	} while (count > 0 || cres == CURLM_CALL_MULTI_PERFORM);

	/* Remove the handles from the multi container. */
	for (i = 0; i < arr_len; i++) {
		CurlNetHandleCtx *pctx = arr[i]->implCtx;
		cres = curl_multi_remove_handle(cm, pctx->curl);
		if (cres != CURLM_OK) {
			KSI_snprintf(buf, sizeof(buf), "Curl error occurred: %s", curl_multi_strerror(cres));
			KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, buf);
			goto cleanup;
		}
		arr[i]->response = pctx->raw;
		pctx->raw = NULL;

		arr[i]->response_length = pctx->len;
		arr[i]->completed = true;

		res = updateStatus(arr[i]);
		if (res != KSI_OK) goto cleanup;
	}

	KSI_LOG_debug(client->ctx, "Finished cURL multi perform.");


	res = KSI_OK;

cleanup:

	if (cm != NULL) curl_multi_cleanup(cm);

	return res;

}

static int performAll(KSI_NetworkClient *client, KSI_RequestHandle **arr, size_t arr_len) {
	int res = KSI_UNKNOWN_ERROR;
	const size_t MAX_BLOCK = 1000;
	size_t start;

	if (client == NULL || (arr == NULL && arr_len != 0)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	start = 0;
	while (start < arr_len) {
		size_t len = arr_len - start;
		if (len > MAX_BLOCK) {
			len = MAX_BLOCK;
		}

		res = performN(client, arr + start, len);
		if (res != KSI_OK) goto cleanup;

		start += len;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_HttpClient_new(KSI_CTX *ctx, KSI_NetworkClient **client) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_NetworkClient *tmp = NULL;
	KSI_HttpClient *http = NULL;

	if (ctx == NULL || client == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_AbstractHttpClient_new(ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	http = tmp->impl;

	http->sendRequest = sendRequest;
	tmp->performAll = performAll;

	res = KSI_CTX_registerGlobals(ctx, curlGlobal_init, curlGlobal_cleanup);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*client = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_NetworkClient_free(tmp);

	return res;
}

#endif
