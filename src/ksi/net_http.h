#include "net.h"

#ifndef KSI_NET_HTTP_H_
#define KSI_NET_HTTP_H_

#ifdef __cplusplus
extern "C" {
#endif
	/** Transport Providers */
	int KSI_HttpClient_new(KSI_CTX *ctx, KSI_NetworkClient **netProvider);
	int KSI_HttpClient_setSignerUrl(KSI_NetworkClient *netProvider, const char *val);
	int KSI_HttpClient_setExtenderUrl(KSI_NetworkClient *netProvider, const char *val);
	int KSI_HttpClient_setPublicationUrl(KSI_NetworkClient *netProvider, const char *val);
	int KSI_HttpClient_setConnectTimeoutSeconds(KSI_NetworkClient *netProvider, int val);
	int KSI_HttpClient_setReadTimeoutSeconds(KSI_NetworkClient *netProvider, int val);

	int KSI_HttpClient_setExtenderUser(KSI_NetworkClient *netProvider, const char *val);
	int KSI_HttpClient_setExtenderPass(KSI_NetworkClient *netProvider, const char *val);
	int KSI_HttpClient_setAggregatoUser(KSI_NetworkClient *netProvider, const char *val);
	int KSI_HttpClient_setAggregatoPass(KSI_NetworkClient *netProvider, const char *val);
	
	int KSI_HttpClient_init(KSI_NetworkClient *client);

#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_CURL_H_ */
