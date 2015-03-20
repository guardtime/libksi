/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#ifndef NET_IMPL_H_
#define NET_IMPL_H_

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

	#define KSI_NETWORK_CLIENT_INIT(ctx)  (KSI_NetworkClient) {(ctx), NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL}

	struct KSI_NetworkClient_st {
		KSI_CTX *ctx;

		int (*sendSignRequest)(KSI_NetworkClient *, KSI_AggregationReq *, KSI_RequestHandle **);
		int (*sendExtendRequest)(KSI_NetworkClient *, KSI_ExtendReq *, KSI_RequestHandle **);
		int (*sendPublicationRequest)(KSI_NetworkClient *, KSI_RequestHandle **);
		int (*getStausCode)(KSI_NetworkClient *);
		
		/** Aggregator user. */
		char *aggrUser;
		/** Aggregator pass phrase. */
		char *aggrPass;

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

		/** Additional context for the transport layer. */
		void *implCtx;
		void (*implCtx_free)(void *);
	};

#ifdef __cplusplus
}
#endif

#endif /* NET_IMPL_H_ */
