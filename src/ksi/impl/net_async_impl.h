/*
 * Copyright 2013-2018 Guardtime, Inc.
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

#ifndef NET_ASYNC_IMPL_H_
#define NET_ASYNC_IMPL_H_

#include "../net.h"
#include "../net_async.h"
#include "../internal.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_AsyncHandle_st {
		KSI_CTX *ctx;
		size_t ref;

		/** Payload id. */
		KSI_uint64_t id;

		/** Application layer request context. */
		/* Aggregation request. */
		KSI_AggregationReq *aggrReq;
		/* Extend request. */
		KSI_ExtendReq *extReq;
		const KSI_Signature *signature;
		const KSI_PublicationRecord *pubRec;

		/** Application layer response context. */
		void *respCtx;
		void (*respCtx_free)(void*);

		/** Serialized request payload. */
		unsigned char *raw;
		size_t len;
		size_t sentCount;

		/** Private user pointer. */
		void *userCtx;
		void (*userCtx_free)(void*);

		/** Handle state. */
		int state;

		/** Handle error. */
		int err;
		long errExt;
		KSI_Utf8String *errMsg;

		/** Time when the query has been added to the request queue. */
		time_t reqTime;
		/** Time when the query has been sent out. */
		time_t sndTime;
		/** Time when the response has been reeived. */
		time_t rcvTime;
	};

	enum KSI_AsyncPrivateOption_en {
		__KSI_ASYNC_PRIVOPT_OFFSET = __KSI_ASYNC_OPT_COUNT,

		/**
		 * Async round duration in sec.
		 * \param		count			Paramer of type size_t.
		 * \see #KSI_ASYNC_ROUND_DURATION_SEC default count.
		 */
		KSI_ASYNC_PRIVOPT_ROUND_DURATION,

		/**
		 * Enable/disanle of the invokation of conf callbacks.
		 * \param		state			Paramer of type bool.
		 */
		KSI_ASYNC_PRIVOPT_INVOKE_CONF_RECEIVED_CALLBACK,

		__NOF_KSI_ASYNC_OPT
	};

	struct KSI_AsyncClient_st {
		KSI_CTX *ctx;

		void *clientImpl;
		void (*clientImpl_free)(void*);

		int (*addRequest)(void *, KSI_AsyncHandle *);
		int (*getResponse)(void *, KSI_OctetString **, size_t *);
		int (*getCredentials)(void *, const char **, const char **);
		int (*dispatch)(void *);

		KSI_uint64_t instanceId;
		KSI_uint64_t messageId;

		size_t requestCountOffset; /**< A circular counter for increasing the request id entropy. */
		size_t requestCount; /**< Request cache position of the last allocated handle. */

		KSI_AsyncHandle **reqCache; /**< Request cache. */
		size_t tail; /**< Request cache position of the last handle that was returned to the used. */
		size_t pending; /**< Nof pending requests (including in error state). */
		size_t received; /**< Nof received valid responses. */

		KSI_AsyncHandle *serverConf; /**< Push config is not part of the request cache, as it can not be assigned to a particular request. */

		size_t options[__NOF_KSI_ASYNC_OPT];
	};

	struct KSI_AsyncService_st {
		KSI_CTX *ctx;

		void *impl;
		void (*impl_free)(void*);

		int (*addRequest)(void *, KSI_AsyncHandle *);
		int (*responseHandler)(void *);

		int (*run)(void *, int (*)(void *), KSI_AsyncHandle **, size_t *);
		int (*getPendingCount)(void *, size_t *);
		int (*getReceivedCount)(void *, size_t *);

		int (*setOption)(void *, int, void *);
		int (*getOption)(void *, int, void *);

		int (*setEndpoint)(void *, const char *, const char *, const char *);

		int (*uriSplit)(const char *uri, char **scheme, char **user, char **pass, char **host, unsigned *port, char **path, char **query, char **fragment);
		int (*uriCompose)(const char *scheme, const char *user, const char *pass, const char *host, unsigned port, const char *path, const char *query, const char *fragment, char *buf, size_t len);
		int (*getClientByUriScheme)(const char *scheme, const char **replaceScheme);
	};

	struct KSI_HighAvailabilityRequest_st {
		KSI_CTX *ctx;
		size_t ref;

		/* A refrence to the original async request handle. */
		KSI_AsyncHandle *asyncHandle;
		/* Number of expected responses. */
		size_t expectedRespCount;

		/* Request components. */
		bool hasReq;
		bool hasCnf;
	};

	struct KSI_HighAvailabilityService_st {
		KSI_CTX *ctx;

		KSI_LIST(KSI_AsyncService) *services;
		KSI_LIST(KSI_AsyncHandle) *respQueue;

		KSI_Config_Callback confCallback;
		KSI_Config *consolidatedConfig;

		int (*subservice_new)(KSI_CTX *, KSI_AsyncService **);
	};

#ifdef __cplusplus
}
#endif

#endif /* NET_ASYNC_IMPL_H_ */
