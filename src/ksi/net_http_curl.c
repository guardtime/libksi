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

#include "impl/net_http_impl.h"
#include "impl/net_impl.h"

size_t curlGlobal_initCount = 0;

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
		/* Nothing to do. */
		return KSI_OK;
	}

	if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) goto cleanup;

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

	KSI_LOG_debug(nc->ctx, "0x%p: Received %llu bytes (%llu so far).", nc, (unsigned long long)bytesCount, (unsigned long long)nc->len);

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
	long httpCode;

	if (handle == NULL || handle->client == NULL || handle->implCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(handle->ctx);

	implCtx = handle->implCtx;

	KSI_LOG_debug(handle->ctx, "Sending request.");

	res = curl_easy_perform(implCtx->curl);
	KSI_LOG_debug(handle->ctx, "Received %llu bytes.", (unsigned long long)implCtx->len);

	if (curl_easy_getinfo(implCtx->curl, CURLINFO_HTTP_CODE, &httpCode) == CURLE_OK) {
		updateStatus(handle);
		KSI_LOG_debug(handle->ctx, "Received HTTP error code %ld. Curl error '%s'.", httpCode, implCtx->curlErr);
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

	/* Cleanup on success. */
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

	/* Make sure cURL won't use signals. */
	curl_easy_setopt(implCtx->curl, CURLOPT_NOSIGNAL, 1);

	/* Use SSL for both control and data. */
	curl_easy_setopt(implCtx->curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

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
