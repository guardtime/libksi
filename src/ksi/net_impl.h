#ifndef NET_IMPL_H_
#define NET_IMPL_H_

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

	#define KSI_NETWORK_CLIENT_INIT(ctx)  (KSI_NetworkClient) {(ctx), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}

	struct KSI_NetworkClient_st {
		KSI_CTX *ctx;

		int (*sendSignRequest)(KSI_NetworkClient *, KSI_AggregationPdu *, KSI_RequestHandle **);
		int (*sendExtendRequest)(KSI_NetworkClient *, KSI_ExtendPdu *, KSI_RequestHandle **);
		int (*sendPublicationRequest)(KSI_NetworkClient *, KSI_RequestHandle *);

		/** Aggregator user. */
		char *agrUser;
		/** Aggregator pass phrase. */
		char *agrPass;

		/** Extender user. */
		char *extUser;
		/** Extender password. */
		char *extPass;
		
		/** Cleanup for the provider, gets the #providerCtx as parameter. */
		void (*implFree)(void *);
	};

	struct KSI_NetHandle_st {
		/** KSI context. */
		KSI_CTX *ctx;
		/** Request destination. */
		unsigned char *request;
		/** Length of the original request. */
		unsigned request_length;
		/** Response for the request. NULL if not yet present. */
		unsigned char *response;
		/** Length of the response. */
		unsigned response_length;

		int (*readResponse)(KSI_RequestHandle *);

		KSI_NetworkClient *client;

		/** Addidtional context for the trasnport layer. */
		void *implCtx;
		void (*implCtx_free)(void *);
	};

#ifdef __cplusplus
}
#endif

#endif /* NET_IMPL_H_ */
