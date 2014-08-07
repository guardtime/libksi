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
		curl_easy_cleanup(handleCtx->curl);
		KSI_free(handleCtx->raw);
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
	KSI_ERR err;
	int res;
	char curlErr[CURL_ERROR_SIZE];
	CurlNetHandleCtx *nc = NULL;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(KSI_RequestHandle_getCtx(handle), &err);

	nc = handle->handleCtx;

    curl_easy_setopt(nc->curl, CURLOPT_ERRORBUFFER, curlErr);

    res = curl_easy_perform(nc->curl);
    if (res != CURLE_OK) {
    	long httpCode;
    	if (res == CURLE_HTTP_RETURNED_ERROR && curl_easy_getinfo(nc->curl, CURLINFO_HTTP_CODE, &httpCode) == CURLE_OK) {
    		KSI_LOG_debug(handle->ctx, "Received HTTP error code %d", httpCode);
   			KSI_FAIL_EXT(&err, KSI_HTTP_ERROR, httpCode, curlErr);
    	} else {
    		KSI_FAIL(&err, KSI_NETWORK_ERROR, curlErr);
    	}
    	goto cleanup;
    }

    res = KSI_RequestHandle_setResponse(handle, nc->raw, nc->len);
    KSI_CATCH(&err, res) goto cleanup;

    /* Cleanup on success.*/
    KSI_free(nc->raw);
    nc->raw = NULL;
    nc->len = 0;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(state);

	return KSI_RETURN(&err);
}


static int sendRequest(KSI_RequestHandle *handle, char *agent, char *url, int connectionTimeout, int readTimeout ) {
	KSI_ERR err;
	int res;
	CurlNetHandleCtx *hc = NULL;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	hc = KSI_new(CurlNetHandleCtx);
	if (hc == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}


	hc->ctx = handle->ctx;
	hc->curl = NULL;
	hc->len = 0;
	hc->raw = NULL;

	hc->curl = curl_easy_init();

	if (hc->curl == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	KSI_LOG_debug(handle->ctx, "Curl: Sending request to: %s", url);

	handle->readResponse = curlReceive;

	curl_easy_setopt(hc->curl, CURLOPT_USERAGENT, agent);
	curl_easy_setopt(hc->curl, CURLOPT_URL, url);
	curl_easy_setopt(hc->curl, CURLOPT_NOPROGRESS, 1);
	if (handle->request != NULL) {
		curl_easy_setopt(hc->curl, CURLOPT_POST, 1);
		curl_easy_setopt(hc->curl, CURLOPT_POSTFIELDS, (char *)handle->request);
		curl_easy_setopt(hc->curl, CURLOPT_POSTFIELDSIZE, (long)handle->request_length);
	}
	curl_easy_setopt(hc->curl, CURLOPT_NOPROGRESS, 1);

	curl_easy_setopt(hc->curl, CURLOPT_WRITEFUNCTION, receiveDataFromLibCurl);

    curl_easy_setopt(hc->curl, CURLOPT_WRITEDATA, hc);

    curl_easy_setopt(hc->curl, CURLOPT_CONNECTTIMEOUT, connectionTimeout);
    curl_easy_setopt(hc->curl, CURLOPT_TIMEOUT, readTimeout);

    curl_easy_setopt(hc->curl, CURLOPT_FAILONERROR, 1);

    curl_easy_setopt(hc->curl, CURLOPT_VERBOSE, 0);

    res = KSI_RequestHandle_setNetContext(handle, hc, (void (*)(void *))CurlNetHandleCtx_free);
    KSI_CATCH(&err, res) goto cleanup;

    hc = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(request);
	KSI_nofree(state);

	CurlNetHandleCtx_free(hc);

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

	http->sendRequest = sendRequest;

	/* Register global init and cleanup methods. */
	res = KSI_CTX_registerGlobals(client->ctx, curlGlobal_init, curlGlobal_cleanup);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);

}

#endif
