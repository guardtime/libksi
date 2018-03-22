/*
 * Copyright 2013-2017 Guardtime, Inc.
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

#include "../net.h"
#include "../internal.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_NetEndpoint_st {
		KSI_CTX *ctx;

		/** KSI service password. */
		char *ksi_pass;

		/** KSI service user name. */
		char *ksi_user;

		/** Implementation for transport layer specific endpoint. */
		void *implCtx;

		/** Cleanup for implementation. */
		void (*implCtx_free)(void *);
	};


	struct KSI_NetworkClient_st {
		KSI_CTX *ctx;

		int (*sendSignRequest)(KSI_NetworkClient *, KSI_AggregationReq *, KSI_RequestHandle **);
		int (*sendExtendRequest)(KSI_NetworkClient *, KSI_ExtendReq *, KSI_RequestHandle **);
		int (*sendPublicationRequest)(KSI_NetworkClient *, KSI_RequestHandle **);

		/** Abstract endpoint for aggregator. */
		KSI_NetEndpoint *aggregator;

		/** Abstract endpoint for extender. */
		KSI_NetEndpoint *extender;

		/** Abstract endpoint for publications file. */
		KSI_NetEndpoint *publicationsFile;

		/** Implementation context. */
		void *impl;
		/** Cleanup for the provider, gets the #providerCtx as parameter. */
		void (*implFree)(void *);

		size_t requestCount;

		/** Private helper functions. */
		int (*setStringParam)(char **param, const char *val);
		int (*uriSplit)(const char *uri, char **scheme, char **user, char **pass, char **host, unsigned *port, char **path, char **query, char **fragment);
		int (*uriCompose)(const char *scheme, const char *user, const char *pass, const char *host, unsigned port, const char *path, const char *query, const char *fragment, char *buf, size_t len);
		int (*getClientByUriScheme)(const char *scheme, const char **replaceScheme);
	};

	struct KSI_NetHandle_st {
		/** KSI context. */
		KSI_CTX *ctx;

		/** Instance reference count. */
		size_t ref;

		KSI_RequestHandleStatus err;

		/** Has the request completeted. */
		bool completed;

		/** Request destination. */
		unsigned char *request;
		/** Length of the original request. */
		size_t request_length;

		/** Response for the request. NULL if not yet present. */
		unsigned char *response;
		/** Length of the response. */
		size_t response_length;

		int (*readResponse)(KSI_RequestHandle *);

		KSI_NetworkClient *client;

		void *reqCtx;
		void (*reqCtx_free)(void *);

		/** Additional context for the transport layer. */
		void *implCtx;
		void (*implCtx_free)(void *);

		/** Function to retrieve the status of the last perform call. Will return #KSI_REQUEST_PENDING if
		 * the request has not been performed. */
		int (*status)(KSI_RequestHandle *);
	};


#ifdef __cplusplus
}
#endif

#endif /* NET_IMPL_H_ */
