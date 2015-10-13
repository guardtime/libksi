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
    unsigned len;
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
		if (handleCtx->curl != NULL) curl_easy_cleanup(handleCtx->curl);
		KSI_free(handleCtx);
	}
}

static size_t receiveDataFromLibCurl(void *ptr, size_t size, size_t nmemb, void *stream) {
	size_t bytesCount = 0;
	unsigned char *tmp_buffer = NULL;
	CurlNetHandleCtx *nc = (CurlNetHandleCtx *) stream;

	KSI_LOG_debug(nc->ctx, "Curl: Receive data size=%lld, nmemb=%lld", size, nmemb);

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
	nc->len = (unsigned)bytesCount;
	tmp_buffer = NULL;

	bytesCount = size * nmemb;

cleanup:

	KSI_free(tmp_buffer);
	return bytesCount;
}

static int curlReceive(KSI_RequestHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	CurlNetHandleCtx *implCtx = NULL;
	KSI_HttpClient *http = NULL;

	if (handle == NULL || handle->client == NULL || handle->implCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(handle->ctx);

	http = (KSI_HttpClient *)handle->client;

	implCtx = handle->implCtx;

    res = curl_easy_perform(implCtx->curl);
    if (res != CURLE_OK) {
    	long httpCode;
    	if (res == CURLE_HTTP_RETURNED_ERROR && curl_easy_getinfo(implCtx->curl, CURLINFO_HTTP_CODE, &httpCode) == CURLE_OK) {
    		KSI_LOG_debug(handle->ctx, "Received HTTP error code %d. Curl error '%s'.", httpCode, implCtx->curlErr);
			http->httpStatus = httpCode;
		} else {
    		KSI_pushError(handle->ctx, res = KSI_NETWORK_ERROR, implCtx->curlErr);
			goto cleanup;
    	}
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
	KSI_HttpClient *http = (KSI_HttpClient *)client;
	size_t len;

	if (client == NULL || handle == NULL || url == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(client->ctx);

	implCtx = KSI_new(CurlNetHandleCtx);
	if (implCtx == NULL) {
		KSI_pushError(client->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	implCtx->ctx = handle->ctx;
	implCtx->curl = NULL;
	implCtx->len = 0;
	implCtx->raw = NULL;

	KSI_LOG_debug(handle->ctx, "Curl: Sending request to: %s", url);

	implCtx->curl = curl_easy_init();
	if (implCtx->curl == NULL) {
		KSI_pushError(http->parent.ctx, res = KSI_OUT_OF_MEMORY, "Unable to init CURL");
		goto cleanup;
	}

    curl_easy_setopt(implCtx->curl, CURLOPT_VERBOSE, 0);
	curl_easy_setopt(implCtx->curl, CURLOPT_WRITEFUNCTION, receiveDataFromLibCurl);
	curl_easy_setopt(implCtx->curl, CURLOPT_NOPROGRESS, 1);

    curl_easy_setopt(implCtx->curl, CURLOPT_ERRORBUFFER, implCtx->curlErr);
    if (http->agentName != NULL) {
    	curl_easy_setopt(implCtx->curl, CURLOPT_USERAGENT, http->agentName);
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

int performAll(KSI_NetworkClient *client, KSI_RequestHandle **arr, size_t arr_len) {
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

	timeout.tv_sec = 10;
	timeout.tv_usec = 0;

	cm = curl_multi_init();
	if (cm == NULL) {
		KSI_pushError(client->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	for (i = 0; i < arr_len; i++) {
		cres = curl_multi_add_handle(cm, (CURL *)arr[i]->implCtx);
		if (cres != CURLM_OK) {
			KSI_snprintf(buf, sizeof(buf), "Curl error occurred: %s", curl_multi_strerror(cres));
			KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, buf);
		}
	}

	cres = curl_multi_fdset(cm, &fdread, &fdwrite, &fdexcep, &maxfd);
	if (cres != CURLM_OK) {
		KSI_snprintf(buf, sizeof(buf), "Curl error occurred: %s", curl_multi_strerror(cres));
		KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, buf);
	}

	cres = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);


	cres = curl_multi_perform(cm, &count);
	if (cres != CURLM_OK) {
		KSI_snprintf(buf, sizeof(buf), "Curl error occurred: %s", curl_multi_strerror(cres));
		KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, buf);
	}
	if (cres != CURLM_OK) {
		KSI_snprintf(buf, sizeof(buf), "Curl error occurred: %s", curl_multi_strerror(cres));
		KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, buf);
	}

	res = KSI_OK;

cleanup:

	if (cm != NULL) curl_multi_cleanup(cm);

	return res;

}

int KSI_HttpClientImpl_init(KSI_HttpClient *http) {
	int res = KSI_UNKNOWN_ERROR;

	if (http == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (http == NULL) {
		KSI_pushError(http->parent.ctx, res = KSI_INVALID_ARGUMENT, "HttpClient network client context not initialized.");
		goto cleanup;
	}

	http->sendRequest = sendRequest;
	http->parent.performAll = performAll;

	/* Register global init and cleanup methods. */
	res = KSI_CTX_registerGlobals(http->parent.ctx, curlGlobal_init, curlGlobal_cleanup);
	if (res != KSI_OK) {
		KSI_pushError(http->parent.ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;

}

#endif
