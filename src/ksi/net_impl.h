#ifndef NET_IMPL_H_
#define NET_IMPL_H_

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_NetworkClient_st {
		KSI_CTX *ctx;

		int (*sendSignRequest)(KSI_NetworkClient *, KSI_AggregationReq *, KSI_RequestHandle **);
		int (*sendExtendRequest)(KSI_NetworkClient *, KSI_ExtendReq *, KSI_RequestHandle **);
		int (*sendPublicationRequest)(KSI_NetworkClient *, KSI_RequestHandle *);

		/** Dedicated context for the net provider */
		void *implCtx;
		/** Cleanup for the provider, gets the #providerCtx as parameter. */
		void (*implCtx_free)(void *);
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
