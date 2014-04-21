#include <curl/curl.h>
#include <string.h>

#include "ksi_internal.h"

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
		int res;
        size_t bytesCount = 0;
        unsigned char *tmp_buffer;
        KSI_NetHandle *handle;
        unsigned char *resp = NULL;
        size_t resp_len = 0;

        handle = (KSI_NetHandle *)stream;

        res = KSI_NetHandle_getResponse(handle, &resp, &resp_len);
        if (res != KSI_OK) goto cleanup;

        bytesCount = resp_len + size * nmemb;
        tmp_buffer = KSI_calloc(bytesCount, 1);
        if (tmp_buffer == NULL) goto cleanup;

        memcpy(tmp_buffer, resp, resp_len);
        memcpy(tmp_buffer + resp_len, ptr, size * nmemb);


        res = KSI_NetHandle_setResponse(handle, tmp_buffer, bytesCount);
        if (tmp_buffer == NULL) goto cleanup;

        bytesCount = size * nmemb;

cleanup:

		KSI_nofree(resp);
		KSI_free(tmp_buffer);
        return bytesCount;
}

static int curlReceive(KSI_NetHandle *handle) {
	KSI_ERR err;
	int res;
	char curlErr[CURL_ERROR_SIZE];
	CURL *curl = NULL;

	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(KSI_NetHandle_getCtx(handle), &err);

	curl = (CURL *)KSI_NetHandle_getNetContext(handle);

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
	int res;
	CURL *curl = NULL;
	const unsigned char *request = NULL;
	int request_len = 0;

	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(KSI_NetHandle_getCtx(handle), &err);

	curl = curl_easy_init();

	if (curl == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = KSI_NetHandle_getRequest(handle, &request, &request_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetHandle_setReadResponseFn(handle, curlReceive);

	curl_easy_setopt(curl, CURLOPT_USERAGENT, agent);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
	if (request != NULL) {
		curl_easy_setopt(curl, CURLOPT_POST, 1);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request_len);
	}
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receiveDataFromLibCurl);

    curl_easy_setopt(curl, CURLOPT_WRITEDATA, handle);

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connectionTimeout);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, readTimeout);

    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);

    res = KSI_NetHandle_setNetContext(handle, curl, curl_easy_cleanup);
    KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(request);
	KSI_nofree(state);

	return KSI_RETURN(&err);
}

static int curlSendSignRequest(KSI_NetProvider *netProvider, KSI_NetHandle *handle) {
	CurlNetProviderCtx *pctx = (CurlNetProviderCtx *) KSI_NetProvider_getNetContext(netProvider);
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

	res = KSI_NetProvider_new(ctx, &pr);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_setSendSignRequestFn(pr, curlSendSignRequest);

	res = CurlNetProviderCtx_new(&pctx);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_setNetCtx(pr, pctx, (void (*)(void*))CurlNetProviderCtx_free);
	pctx = NULL;

	*netProvider = pr;
	pr = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetProvider_free(pr);
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
			if (netProvider == NULL) {																	\
				res = KSI_INVALID_ARGUMENT;																\
				goto cleanup;																			\
			}																							\
			pctx = KSI_NetProvider_getNetContext(netProvider);											\
			if (pctx == NULL) {																			\
				res = KSI_INVALID_ARGUMENT;																\
				goto cleanup;																			\
			}																							\
			res = ($fn)(&pctx->$var, val);																\
		cleanup:																						\
			return res;																					\
		}																								\

KSI_NET_CURL_SETTER(SignerUrl, char *, urlSigner, setStringParam);
KSI_NET_CURL_SETTER(ExtenderUrl, char *, urlExtender, setStringParam);
KSI_NET_CURL_SETTER(PublicationUrl, char *, urlPublication, setStringParam);
KSI_NET_CURL_SETTER(ConnectTimeoutSeconds, int, connectionTimeoutSeconds, setIntParam);
KSI_NET_CURL_SETTER(ReadTimeoutSeconds, int, readTimeoutSeconds, setIntParam);
