#include "net.h"

#ifndef KSI_NET_CURL_H_
#define KSI_NET_CURL_H_

#ifdef __cplusplus
extern "C" {
#endif

	int KSI_CurlNetProvider_global_init(void);

	void KSI_CurlNetProvider_global_cleanup(void);

	/** Transport Providers */
	int KSI_CurlNetProvider_new(KSI_CTX *ctx, KSI_NetProvider **netProvider);
	int KSI_CurlNetProvider_setSignerUrl(KSI_NetProvider *netProvider, char *val);
	int KSI_CurlNetProvider_setExtenderUrl(KSI_NetProvider *netProvider, char *val);
	int KSI_CurlNetProvider_setPublicationUrl(KSI_NetProvider *netProvider, char *val);
	int KSI_CurlNetProvider_setConnectTimeoutSeconds(KSI_NetProvider *netProvider, int val);
	int KSI_CurlNetProvider_setReadTimeoutSeconds(KSI_NetProvider *netProvider, int val);


#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_CURL_H_ */
