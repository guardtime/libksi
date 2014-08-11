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
    char *url;
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
		KSI_free(handleCtx->url);
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
	CurlNetHandleCtx *implCtx = NULL;
	KSI_HttpClientCtx *http = NULL;
	KSI_NetworkClient *client = NULL;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, handle->client != NULL) goto cleanup;
	KSI_PRE(&err, handle->implCtx != NULL) goto cleanup;
	KSI_BEGIN(KSI_RequestHandle_getCtx(handle), &err);

	client = handle->client;
	http = client->implCtx; // TODO!

	implCtx = handle->implCtx;

    curl_easy_setopt(implCtx->curl, CURLOPT_ERRORBUFFER, curlErr);
	curl_easy_setopt(implCtx->curl, CURLOPT_USERAGENT, http->agentName);

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

	curl_easy_setopt(implCtx->curl, CURLOPT_URL, implCtx->url);

    res = curl_easy_perform(implCtx->curl);
    if (res != CURLE_OK) {
    	long httpCode;
    	if (res == CURLE_HTTP_RETURNED_ERROR && curl_easy_getinfo(implCtx->curl, CURLINFO_HTTP_CODE, &httpCode) == CURLE_OK) {
    		KSI_LOG_debug(handle->ctx, "Received HTTP error code %d", httpCode);
   			KSI_FAIL_EXT(&err, KSI_HTTP_ERROR, httpCode, curlErr);
    	} else {
    		KSI_FAIL(&err, KSI_NETWORK_ERROR, curlErr);
    	}
    	goto cleanup;
    }

    res = KSI_RequestHandle_setResponse(handle, implCtx->raw, implCtx->len);
    KSI_CATCH(&err, res) goto cleanup;

    /* Cleanup on success.*/
    KSI_free(implCtx->raw);
    implCtx->raw = NULL;
    implCtx->len = 0;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(state);

	return KSI_RETURN(&err);
}


static int sendRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *url) {
	KSI_ERR err;
	int res;
	CurlNetHandleCtx *implCtx = NULL;
	KSI_HttpClientCtx *http = NULL;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_PRE(&err, client->implCtx != NULL) goto cleanup;
	KSI_PRE(&err, ((KSI_HttpClientCtx *)client->implCtx)->implCtx != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	http = client->implCtx;

	implCtx = KSI_new(CurlNetHandleCtx);
	if (implCtx == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}


	implCtx->ctx = handle->ctx;
	implCtx->curl = http->implCtx;
	implCtx->len = 0;
	implCtx->raw = NULL;

	KSI_LOG_debug(handle->ctx, "Curl: Sending request to: %s", url);

	handle->readResponse = curlReceive;
	handle->client = client;

	implCtx->url = KSI_calloc(strlen(url) + 1, 1);
	if (implCtx->url == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	strcpy(implCtx->url, url);

    res = KSI_RequestHandle_setImplContext(handle, implCtx, (void (*)(void *))CurlNetHandleCtx_free);
    KSI_CATCH(&err, res) goto cleanup;

    implCtx = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(request);
	KSI_nofree(state);

	CurlNetHandleCtx_free(implCtx);

	return KSI_RETURN(&err);
}

int KSI_HttpClient_init(KSI_NetworkClient *client) {
	KSI_ERR err;
	KSI_HttpClientCtx *http = NULL;
	CURL *curl = NULL;
	int res;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	http = client->implCtx;
	if (http == NULL) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "HttpClient network client context not initialized.");
		goto cleanup;
	}

	curl = curl_easy_init();
	if (curl == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, "Unable to init CURL");
		goto cleanup;
	}

    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receiveDataFromLibCurl);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
	http->implCtx = curl;
	http->implCtx_free = curl_easy_cleanup;
	curl = NULL;

	http->sendRequest = sendRequest;

	/* Register global init and cleanup methods. */
	res = KSI_CTX_registerGlobals(client->ctx, curlGlobal_init, curlGlobal_cleanup);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	if (curl != NULL) curl_easy_cleanup(curl);

	return KSI_RETURN(&err);

}

#endif
