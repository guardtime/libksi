#include <curl/curl.h>
#include <string.h>

#include "ksi_internal.h"
#include "ksi_net.h"

typedef struct CurlNetProviderCtx_st {
	int connectionTimeoutSeconds;
	int readTimeoutSeconds;
	char *urlSigner;
	char *urlExtender;
	char *urlPublication;
} CurlNetProviderCtx;

static void CurlNetProviderCtx_free(CurlNetProviderCtx *providerCtx) {
	if (providerCtx != NULL) {
		KSI_free(providerCtx->urlExtender);
		KSI_free(providerCtx->urlPublication);
		KSI_free(providerCtx->urlSigner);

		KSI_free(providerCtx);
	}
}

static int CurlNetProviderCtx_new(CurlNetProviderCtx **providerCtx) {
	CurlNetProviderCtx *pctx = NULL;
	int res;

	pctx = KSI_new (CurlNetProviderCtx);
	if (pctx == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	pctx->connectionTimeoutSeconds = 0;
	pctx->readTimeoutSeconds = 0;
	pctx->urlSigner = NULL;
	pctx->urlPublication = NULL;
	pctx->urlExtender = NULL;

	*providerCtx = pctx;
	pctx = NULL;

	res = KSI_OK;

cleanup:

	CurlNetProviderCtx_free(pctx);

	return res;
}

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
	CURL *curl = (CURL *)handle->handleCtx;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_PRE(&err, handle->handleCtx != NULL) goto cleanup;

	KSI_BEGIN(handle->ctx, &err);

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlErr);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
    	long httpCode;
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


static int curlSendRequest(KSI_NetHandle *handle, char *agent, char *url, int connectionTimeout, int readTimeout ) {
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

	curl_easy_setopt(curl, CURLOPT_USERAGENT, agent);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
	if (handle->request != NULL) {
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const void *)handle->request);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, handle->request_length);
	}
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receiveDataFromLibCurl);

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, handle);

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connectionTimeout);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, readTimeout);

    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);

    handle->handleCtx = curl;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(state);

	return KSI_RETURN(&err);
}

static int curlSendSignRequest(KSI_NetProvider *netProvider, KSI_NetHandle *handle) {
	CurlNetProviderCtx *pctx = (CurlNetProviderCtx *)netProvider->poviderCtx;
	return curlSendRequest(handle, "TODO", pctx->urlSigner, pctx->connectionTimeoutSeconds, pctx->readTimeoutSeconds);
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
int KSI_NET_CURL_new(KSI_CTX *ctx, KSI_NetProvider **netProvider) {
	KSI_ERR err;
	KSI_NetProvider *pr = NULL;
	CurlNetProviderCtx *pctx = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	pr = KSI_new(KSI_NetProvider);
	if (pr == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	pr->ctx = ctx;


	pr->sendSignRequest = curlSendSignRequest;
	pr->sendExtendRequest = NULL;
	pr->sendPublicationRequest = NULL;

	res = CurlNetProviderCtx_new(&pctx);
	KSI_CATCH(&err, res) goto cleanup;

	pr->poviderCtx = pctx;
	pctx = NULL;
	pr->providerCtx_free = (void (*)(void*))CurlNetProviderCtx_free;

	*netProvider = pr;
	pr = NULL;

	KSI_SUCCESS(&err);

cleanup:

	CurlNetProviderCtx_free(pctx);
	KSI_free(pr);

	return KSI_RETURN(&err);
}

static int setStringParam(char **param, char *urlSigner) {
	char *val = NULL;
	int res = KSI_UNKNOWN_ERROR;


	val = KSI_calloc(strlen(urlSigner) + 1, 1);
	if (val == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	memcpy(val, urlSigner, strlen(urlSigner) + 1);

	if (*param != NULL) {
		KSI_free(*param);
	}

	*param = val;
	val = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(pctx);
	KSI_free(val);

	return res;
}

static int setIntParam(int *param, int val) {
	*param = val;
	return KSI_OK;
}

#define KSI_NET_CURL_SETTER($name, $type, $var, $fn) 													\
		int KSI_NET_CURL_set##$name(KSI_NetProvider *netProvider, $type val) {							\
			int res = KSI_UNKNOWN_ERROR;																\
			CurlNetProviderCtx *pctx = NULL;															\
			if (netProvider == NULL || netProvider->poviderCtx == NULL) {								\
				res = KSI_INVALID_ARGUMENT;																\
				goto cleanup;																			\
			}																							\
			pctx = (CurlNetProviderCtx *)netProvider->poviderCtx;										\
			res = ($fn)(&pctx->$var, val);																\
		cleanup:																						\
			return res;																					\
		}																								\

KSI_NET_CURL_SETTER(SignerUrl, char *, urlSigner, setStringParam);
KSI_NET_CURL_SETTER(ExtenderUrl, char *, urlExtender, setStringParam);
KSI_NET_CURL_SETTER(PublicationUrl, char *, urlPublication, setStringParam);
KSI_NET_CURL_SETTER(ConnectTimeoutSeconds, int, connectionTimeoutSeconds, setIntParam);
KSI_NET_CURL_SETTER(ReadTimeoutSeconds, int, readTimeoutSeconds, setIntParam);
