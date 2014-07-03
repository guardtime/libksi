#include "net.h"

#ifndef KSI_NET_HTTP_H_
#define KSI_NET_HTTP_H_

#ifdef __cplusplus
extern "C" {
#endif

	int KSI_CurlNetProvider_global_init(void);

	void KSI_CurlNetProvider_global_cleanup(void);

	/** Transport Providers */
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
