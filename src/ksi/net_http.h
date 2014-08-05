#include "net.h"

#ifndef KSI_NET_HTTP_H_
#define KSI_NET_HTTP_H_

#ifdef __cplusplus
extern "C" {
#endif
	/** Transport Providers */
	typedef struct KSI_HttpClientCtx_st KSI_HttpClientCtx;

	void KSI_HttpClientCtx_free(KSI_HttpClientCtx *http);
	int KSI_HttpClientCtx_new(KSI_HttpClientCtx **http);

	int KSI_HttpClient_new(KSI_CTX *ctx, KSI_NetworkClient **netProvider);
	int KSI_HttpClient_setSignerUrl(KSI_NetworkClient *netProvider, char *val);
	int KSI_HttpClient_setExtenderUrl(KSI_NetworkClient *netProvider, char *val);
	int KSI_HttpClient_setPublicationUrl(KSI_NetworkClient *netProvider, char *val);
	int KSI_HttpClient_setConnectTimeoutSeconds(KSI_NetworkClient *netProvider, int val);
	int KSI_HttpClient_setReadTimeoutSeconds(KSI_NetworkClient *netProvider, int val);


#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_CURL_H_ */
