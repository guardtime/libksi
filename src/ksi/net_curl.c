#include <curl/curl.h>
#include <string.h>

#include "internal.h"

typedef struct CurlNetProviderCtx_st {
	int connectionTimeoutSeconds;
	int readTimeoutSeconds;
	char *urlSigner;
	char *urlExtender;
	char *urlPublication;
} CurlNetProviderCtx;

typedef struct CurlNetHandleCtx_st {
	KSI_CTX *ctx;
	CURL *curl;
	char *raw;
    size_t len;
} CurlNetHandleCtx;

static void CurlNetHandleCtx_free(CurlNetHandleCtx *handleCtx) {
	if (handleCtx != NULL) {
		curl_easy_cleanup(handleCtx->curl);
		KSI_free(handleCtx->raw);
		KSI_free(handleCtx);
	}
}

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
			void *stream) {
	int res;
	size_t bytesCount = 0;
	unsigned char *tmp_buffer = NULL;
	CurlNetHandleCtx *nc = (CurlNetHandleCtx *) stream;

	KSI_LOG_debug(nc->ctx, "curl: receive data size=%lld, nmemb=%lld", size, nmemb);

	bytesCount = nc->len + size * nmemb;
	tmp_buffer = KSI_calloc(bytesCount, 1);
	if (tmp_buffer == NULL) goto cleanup;

	memcpy(tmp_buffer, nc->raw, nc->len);
	memcpy(tmp_buffer + nc->len, ptr, size * nmemb);

	KSI_free(nc->raw);
	nc->raw = tmp_buffer;
	nc->len = bytesCount;
	tmp_buffer = NULL;

	bytesCount = size * nmemb;

cleanup:

	KSI_free(tmp_buffer);
	return bytesCount;
}

static int curlReceive(KSI_NetHandle *handle) {
	KSI_ERR err;
	int res;
	char curlErr[CURL_ERROR_SIZE];
	CurlNetHandleCtx *nc = NULL;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(KSI_NetHandle_getCtx(handle), &err);

	res = KSI_NetHandle_getNetContext(handle, (void **)&nc);
	KSI_CATCH(&err, res) goto cleanup;

    curl_easy_setopt(nc->curl, CURLOPT_ERRORBUFFER, curlErr);

    res = curl_easy_perform(nc->curl);
    if (res != CURLE_OK) {
    	long httpCode;
    	if (res == CURLE_HTTP_RETURNED_ERROR && curl_easy_getinfo(nc->curl, CURLINFO_HTTP_CODE, &httpCode) == CURLE_OK) {
   			KSI_FAIL_EXT(&err, KSI_HTTP_ERROR, httpCode, curlErr);
    	} else {
    		KSI_FAIL(&err, KSI_NETWORK_ERROR, curlErr);
    	}
    	goto cleanup;
    }

    res = KSI_NetHandle_setResponse(handle, nc->raw, nc->len);
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


static int curlSendRequest(KSI_NetHandle *handle, char *agent, char *url, int connectionTimeout, int readTimeout ) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL;
	const unsigned char *request = NULL;
	int request_len = 0;
	CurlNetHandleCtx *hc = NULL;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(KSI_NetHandle_getCtx(handle), &err);

	hc = KSI_new(CurlNetHandleCtx);
	if (hc == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	ctx = KSI_NetHandle_getCtx(handle);

	hc->ctx = ctx;
	hc->curl = NULL;
	hc->len = 0;
	hc->raw = NULL;

	hc->curl = curl_easy_init();

	if (hc->curl == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	KSI_LOG_debug(ctx, "Sending request to: %s", url);

	res = KSI_NetHandle_getRequest(handle, &request, &request_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetHandle_setReadResponseFn(handle, curlReceive);
	KSI_CATCH(&err, res) goto cleanup;

	curl_easy_setopt(hc->curl, CURLOPT_USERAGENT, agent);
	curl_easy_setopt(hc->curl, CURLOPT_URL, url);
	curl_easy_setopt(hc->curl, CURLOPT_NOPROGRESS, 1);
	if (request != NULL) {
		curl_easy_setopt(hc->curl, CURLOPT_POST, 1);
		curl_easy_setopt(hc->curl, CURLOPT_POSTFIELDS, (char *)request);
		curl_easy_setopt(hc->curl, CURLOPT_POSTFIELDSIZE, request_len);
	}
	curl_easy_setopt(hc->curl, CURLOPT_NOPROGRESS, 1);

	curl_easy_setopt(hc->curl, CURLOPT_WRITEFUNCTION, receiveDataFromLibCurl);

    curl_easy_setopt(hc->curl, CURLOPT_WRITEDATA, hc);

    curl_easy_setopt(hc->curl, CURLOPT_CONNECTTIMEOUT, connectionTimeout);
    curl_easy_setopt(hc->curl, CURLOPT_TIMEOUT, readTimeout);

    curl_easy_setopt(hc->curl, CURLOPT_FAILONERROR, 1);

    curl_easy_setopt(hc->curl, CURLOPT_VERBOSE, 0);

    res = KSI_NetHandle_setNetContext(handle, hc, (void (*)(void *))CurlNetHandleCtx_free);
    KSI_CATCH(&err, res) goto cleanup;

    hc = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(request);
	KSI_nofree(state);

	CurlNetHandleCtx_free(hc);

	return KSI_RETURN(&err);
}

static int curlSendSignRequest(KSI_NetProvider *netProvider, KSI_NetHandle *handle) {
	CurlNetProviderCtx *pctx = NULL;
	int res;

	res = KSI_NetProvider_getNetContext(netProvider, (void **)&pctx);
	if (res != KSI_OK) goto cleanup;

	res = curlSendRequest(handle, "TODO", pctx->urlSigner, pctx->connectionTimeoutSeconds, pctx->readTimeoutSeconds);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static int curlSendExtendRequest(KSI_NetProvider *netProvider, KSI_NetHandle *handle) {
	CurlNetProviderCtx *pctx = NULL;
	int res;

	res = KSI_NetProvider_getNetContext(netProvider, (void **)&pctx);
	if (res != KSI_OK) goto cleanup;

	res = curlSendRequest(handle, "TODO", pctx->urlExtender, pctx->connectionTimeoutSeconds, pctx->readTimeoutSeconds);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static int curlSendPublicationsFileRequest(KSI_NetProvider *netProvider, KSI_NetHandle *handle) {
	CurlNetProviderCtx *pctx = NULL;
	int res;

	res = KSI_NetProvider_getNetContext(netProvider, (void **)&pctx);
	if (res != KSI_OK) goto cleanup;

	res = curlSendRequest(handle, "TODO", pctx->urlPublication, pctx->connectionTimeoutSeconds, pctx->readTimeoutSeconds);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_CurlNetProvider_global_init(void) {
	int res = KSI_UNKNOWN_ERROR;

	if (curl_global_init(CURLUSESSL_ALL) != CURLE_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

void KSI_CurlNetProvider_global_cleanup(void) {
	curl_global_cleanup();
}

/**
 *
 */
int KSI_CurlNetProvider_new(KSI_CTX *ctx, KSI_NetProvider **netProvider) {
	KSI_ERR err;
	KSI_NetProvider *pr = NULL;
	CurlNetProviderCtx *pctx = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_NetProvider_new(ctx, &pr);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_setSendSignRequestFn(pr, curlSendSignRequest);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_setSendExtendRequestFn(pr, curlSendExtendRequest);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_setSendPublicationRequestFn(pr, curlSendPublicationsFileRequest);
	KSI_CATCH(&err, res) goto cleanup;

	res = CurlNetProviderCtx_new(&pctx);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_setNetCtx(pr, pctx, (void (*)(void*))CurlNetProviderCtx_free);
	pctx = NULL;

	res = KSI_CurlNetProvider_setSignerUrl(pr, KSI_DEFAULT_URI_AGGREGATOR);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_CurlNetProvider_setExtenderUrl(pr, KSI_DEFAULT_URI_EXTENDER);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_CurlNetProvider_setPublicationUrl(pr, KSI_DEFAULT_URI_PUBLICATIONS_FILE);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_CurlNetProvider_setReadTimeoutSeconds(pr, 5);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_CurlNetProvider_setConnectTimeoutSeconds(pr, 5);
	KSI_CATCH(&err, res) goto cleanup;

	*netProvider = pr;
	pr = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetProvider_free(pr);
	CurlNetProviderCtx_free(pctx);

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

#define KSI_NET_CURL_SETTER(name, type, var, fn) 														\
		int KSI_CurlNetProvider_set##name(KSI_NetProvider *netProvider, type val) {						\
			int res = KSI_UNKNOWN_ERROR;																\
			CurlNetProviderCtx *pctx = NULL;															\
			if (netProvider == NULL) {																	\
				res = KSI_INVALID_ARGUMENT;																\
				goto cleanup;																			\
			}																							\
			res = KSI_NetProvider_getNetContext(netProvider, (void **)&pctx);							\
			if (res != KSI_OK) goto cleanup;															\
			res = (fn)(&pctx->var, val);																\
		cleanup:																						\
			return res;																					\
		}																								\

KSI_NET_CURL_SETTER(SignerUrl, char *, urlSigner, setStringParam);
KSI_NET_CURL_SETTER(ExtenderUrl, char *, urlExtender, setStringParam);
KSI_NET_CURL_SETTER(PublicationUrl, char *, urlPublication, setStringParam);
KSI_NET_CURL_SETTER(ConnectTimeoutSeconds, int, connectionTimeoutSeconds, setIntParam);
KSI_NET_CURL_SETTER(ReadTimeoutSeconds, int, readTimeoutSeconds, setIntParam);
