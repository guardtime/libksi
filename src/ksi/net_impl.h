#ifndef NET_IMPL_H_
#define NET_IMPL_H_

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_NetworkClient_st {
		KSI_CTX *ctx;

		/** Cleanup for the provider, gets the #providerCtx as parameter. */
		void (*providerCtx_free)(void *);

		int (*sendSignRequest)(KSI_NetworkClient *, KSI_RequestHandle *);
		int (*sendExtendRequest)(KSI_NetworkClient *, KSI_RequestHandle *);
		int (*sendPublicationRequest)(KSI_NetworkClient *, KSI_RequestHandle *);

		/** Dedicated context for the net provider */
		void *poviderCtx;
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

		void (*handleCtx_free)(void *);

		int (*readResponse)(KSI_RequestHandle *);

		/** Addidtional context for the trasnport layer. */
		void *handleCtx;
	};

#ifdef __cplusplus
}
#endif

#endif /* NET_IMPL_H_ */
