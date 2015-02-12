#ifndef NET_URI_IMPL_H_
#define NET_URI_IMPL_H_

#include "net_http.h"
#include "net_tcp.h"
#include "net_impl.h"
#include "http_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

	enum client_e {
		URI_HTTP,
		URI_TCP,
		URI_CLIENT_COUNT
	};

	struct KSI_UriClient_st {
		KSI_NetworkClient parent;

		KSI_HttpClient *httpClient;
		KSI_TcpClient *tcpClient;

		KSI_NetworkClient *pExtendClient;
		KSI_NetworkClient *pAggregationClient;
	};

#ifdef __cplusplus
}
#endif

#endif /* NET_URI_IMPL_H_ */
