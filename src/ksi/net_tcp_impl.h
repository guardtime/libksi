#ifndef NET_TCP_INTERNAL_H_
#define NET_TCP_INTERNAL_H_

#include "internal.h"
#include "net_http.h"
#include "net_impl.h"
#include "net_http_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_TcpClient_st {
		KSI_NetworkClient parent;
		
		char *aggrHost;
		unsigned aggrPort;

		char *extHost;
		unsigned extPort;

		int (*sendRequest)(KSI_NetworkClient *, KSI_RequestHandle *, char *host, unsigned port);
		KSI_HttpClient *http;
	};


#ifdef __cplusplus
}
#endif

#endif /* NET_HTTP_INTERNAL_H_ */
