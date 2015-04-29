/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
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
		/** Extender shared HMAC secret. */
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
