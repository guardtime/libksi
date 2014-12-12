#ifndef NET_HTTP_INTERNAL_H_
#define NET_HTTP_INTERNAL_H_

#include "internal.h"
#include "net_http.h"
#include "net_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_HttpClient_st {
		KSI_NetworkClient parent;

		int connectionTimeoutSeconds;
		int readTimeoutSeconds;
		char *urlAggregator;
		char *urlExtender;
		char *urlPublication;
		char *agentName;
		
		int (*sendRequest)(KSI_NetworkClient *, KSI_RequestHandle *, char *);

		void *implCtx;
		void (*implCtx_free)(void *);
	};


#ifdef __cplusplus
}
#endif

#endif /* NET_HTTP_INTERNAL_H_ */
