#ifndef NET_HTTP_INTERNAL_H_
#define NET_HTTP_INTERNAL_H_

#include "internal.h"
#include "net_http.h"
#include "net_impl.h"

#ifdef __cplusplus
extern "C" {
#endif
	typedef struct KSI_HttpClientCtx_st KSI_HttpClientCtx;

	struct KSI_HttpClientCtx_st {
		KSI_CTX *ctx;
		int connectionTimeoutSeconds;
		int readTimeoutSeconds;
		char *urlSigner;
		char *urlExtender;
		char *urlPublication;
		char *agentName;
		int (*sendRequest)(KSI_RequestHandle *, char *, char *, int, int);
		KSI_uint64_t requestId;
	};


#ifdef __cplusplus
}
#endif

#endif /* NET_HTTP_INTERNAL_H_ */
