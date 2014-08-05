#ifndef NET_HTTP_INTERNAL_H_
#define NET_HTTP_INTERNAL_H_

#include "internal.h"
#include "net_http.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_HttpClientCtx_st {
		int connectionTimeoutSeconds;
		int readTimeoutSeconds;
		char *urlSigner;
		char *urlExtender;
		char *urlPublication;
		char *agentName;
	};


#ifdef __cplusplus
}
#endif

#endif /* NET_HTTP_INTERNAL_H_ */
