#include <curl/curl.h>
#include <string.h>

#include "ksi_internal.h"
#include "ksi_net.h"

static size_t receiveDataFromLibCurl(void *ptr, size_t size, size_t nmemb,
                void *stream)
{
        size_t res = 0;
        unsigned char *tmp_buffer;
        KSI_NetHandle *handle;

        handle = (KSI_NetHandle *)stream;
        tmp_buffer = KSI_realloc(handle->response,
                        handle->response_length + size * nmemb);
        if (tmp_buffer != NULL) {
                res = size * nmemb;
                memcpy(tmp_buffer + handle->response_length, ptr, res);
                handle->response = tmp_buffer;
                handle->response_length += res;
        }

        return res;
}

static int curlReceive(KSI_NetHandle *handle) {
	KSI_ERR err;
	int res;
	char curlErr[CURL_ERROR_SIZE];
	CURL *curl = (CURL *)handle->netCtx;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, handle->netCtx != NULL) goto cleanup;

	KSI_BEGIN(handle->ctx, &err);

	KSI_LOG_debug(handle->ctx, "Connecting to: %s", handle->url);

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlErr);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
    	int httpCode;
    	if (res == CURLE_HTTP_RETURNED_ERROR && curl_easy_getinfo(curl, CURLINFO_HTTP_CODE, &httpCode) == CURLE_OK) {
   			KSI_FAIL_EXT(&err, KSI_HTTP_ERROR, httpCode, curlErr);
    	} else {
    		KSI_FAIL(&err, KSI_NETWORK_ERROR, curlErr);
    	}
    	goto cleanup;
    }

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(state);

	return KSI_RETURN(&err);
}


static int curlSend(KSI_NetHandle *handle) {
	KSI_ERR err;
	CURL *curl = NULL;

	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(handle->ctx, &err);

	handle->netCtx_free = curl_easy_cleanup;

	curl = curl_easy_init();

	if (curl == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	handle->readResponse = curlReceive;

	curl_easy_setopt(curl, CURLOPT_USERAGENT, handle->ctx->conf.net.agent); // TODO! Make configurable
	curl_easy_setopt(curl, CURLOPT_URL, handle->url);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
	if (handle->request != NULL) {
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const void *)handle->request);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, handle->request_length);
	}
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receiveDataFromLibCurl);

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, handle);

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, handle->ctx->conf.net.connectTimeoutSeconds);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, handle->ctx->conf.net.readTimeoutSeconds);

    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);



    handle->netCtx = curl;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(state);

	return KSI_RETURN(&err);
}

int KSI_NET_global_init(void) {
	int res = KSI_UNKNOWN_ERROR;

	if (curl_global_init(CURLUSESSL_ALL) != CURLE_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

void KSI_NET_global_cleanup(void) {
	curl_global_cleanup();
}

/**
 *
 */
int KSI_NET_CURL(KSI_CTX *ctx) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	ctx->netProvider.poviderCtx = NULL;
	ctx->netProvider.providerCleanup = NULL;
	ctx->netProvider.sendRequest = curlSend;

	KSI_SUCCESS(&err);

cleanup:


	return KSI_RETURN(&err);
}
