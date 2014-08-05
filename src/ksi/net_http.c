#include <string.h>
#include "net_http_impl.h"

static int setStringParam(char **param, char *val) {
	char *tmp = NULL;
	int res = KSI_UNKNOWN_ERROR;


	tmp = KSI_calloc(strlen(val) + 1, 1);
	if (tmp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	memcpy(tmp, val, strlen(val) + 1);

	if (*param != NULL) {
		KSI_free(*param);
	}

	*param = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(pctx);
	KSI_free(tmp);

	return res;
}

static int setIntParam(int *param, int val) {
	*param = val;
	return KSI_OK;
}

void KSI_HttpClientCtx_free(KSI_HttpClientCtx *http) {
	if (http != NULL) {
		KSI_free(http->urlSigner);
		KSI_free(http->urlExtender);
		KSI_free(http->urlPublication);
		KSI_free(http->agentName);
		KSI_free(http);
	}
}

int KSI_HttpClientCtx_new(KSI_HttpClientCtx **http) {
	KSI_HttpClientCtx *tmp = NULL;
	int res;

	tmp = KSI_new (KSI_HttpClientCtx);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	setIntParam(&tmp->connectionTimeoutSeconds, 5);
	setIntParam(&tmp->readTimeoutSeconds, 5);
	setStringParam(&tmp->urlSigner, KSI_DEFAULT_URI_AGGREGATOR);
	setStringParam(&tmp->urlExtender, KSI_DEFAULT_URI_EXTENDER);
	setStringParam(&tmp->urlPublication, KSI_DEFAULT_URI_PUBLICATIONS_FILE);
	setStringParam(&tmp->agentName, "KSI HTTP Client");

	*http = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_HttpClientCtx_free(tmp);

	return res;
}

#define KSI_NET_IMPLEMENT_SETTER(name, type, var, fn) 														\
		int KSI_HttpClient_set##name(KSI_NetworkClient *client, type val) {								\
			int res = KSI_UNKNOWN_ERROR;																\
			KSI_HttpClientCtx *pctx = NULL;																\
			if (client == NULL) {																		\
				res = KSI_INVALID_ARGUMENT;																\
				goto cleanup;																			\
			}																							\
			res = KSI_NetworkClient_getNetContext(client, (void **)&pctx);								\
			if (res != KSI_OK) goto cleanup;															\
			res = (fn)(&pctx->var, val);																\
		cleanup:																						\
			return res;																					\
		}																								\

KSI_NET_IMPLEMENT_SETTER(SignerUrl, char *, urlSigner, setStringParam);
KSI_NET_IMPLEMENT_SETTER(ExtenderUrl, char *, urlExtender, setStringParam);
KSI_NET_IMPLEMENT_SETTER(PublicationUrl, char *, urlPublication, setStringParam);
KSI_NET_IMPLEMENT_SETTER(ConnectTimeoutSeconds, int, connectionTimeoutSeconds, setIntParam);
KSI_NET_IMPLEMENT_SETTER(ReadTimeoutSeconds, int, readTimeoutSeconds, setIntParam);
