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

#include <string.h>
#include <assert.h>
#include "impl/net_http_impl.h"
#include "impl/ctx_impl.h"

typedef struct HttpClient_Endpoint_st HttpClient_Endpoint;

static int HttpClient_Endpoint_new(HttpClient_Endpoint **endpoint) {
	HttpClient_Endpoint *tmp = NULL;

	if (endpoint == NULL) return KSI_INVALID_ARGUMENT;

	tmp = KSI_new(HttpClient_Endpoint);
	if (tmp == NULL) return KSI_OUT_OF_MEMORY;

	tmp->url = NULL;

	*endpoint = tmp;
	return KSI_OK;
}

static void HttpClient_Endpoint_free(HttpClient_Endpoint *endpoint) {
	if (endpoint == NULL) return;
	KSI_free(endpoint->url);
	KSI_free(endpoint);
}

static int setIntParam(int *param, int val) {
	*param = val;
	return KSI_OK;
}

static int prepareRequest(
		KSI_NetworkClient *client,
		void *pdu,
		int (*serialize)(void *, unsigned char **, size_t *),
		KSI_RequestHandle **handle,
		char *url,
		const char *desc) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HttpClient *http = client->impl;
	KSI_RequestHandle *tmp = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;

	if (client == NULL || pdu == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(client->ctx);

	res = serialize(pdu, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logBlob(client->ctx, KSI_LOG_DEBUG, desc, raw, raw_len);

	/* Create a new request handle */
	res = KSI_RequestHandle_new(client->ctx, raw, raw_len, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	if (http->sendRequest == NULL) {
		KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}

	res = http->sendRequest(client, tmp, url);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	*handle = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_RequestHandle_free(tmp);
	KSI_free(raw);

	return res;
}

static int prepareExtendRequest(KSI_NetworkClient *client, KSI_ExtendReq *req, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendPdu *pdu = NULL;
	KSI_Integer *pReqId = NULL;
	KSI_Integer *reqId = NULL;
	KSI_NetEndpoint *ext = NULL;
	HttpClient_Endpoint *endp = NULL;
	KSI_ExtendReq *reqRef = NULL;

	if (client == NULL || req == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ext = client->extender;
	if (ext == NULL) {
		res = KSI_AGGREGATOR_NOT_CONFIGURED;
		goto cleanup;
	}
	endp = ext->implCtx;
	if (endp == NULL || endp->url == NULL) {
		res = KSI_AGGREGATOR_NOT_CONFIGURED;
		goto cleanup;
	}

	res = KSI_ExtendReq_getRequestId(req, &pReqId);
	if (res != KSI_OK) goto cleanup;

	if (pReqId == NULL) {
		res = KSI_Integer_new(client->ctx, ++client->requestCount, &reqId);
		if (res != KSI_OK) goto cleanup;

		res = KSI_ExtendReq_setRequestId(req, reqId);
		if (res != KSI_OK) goto cleanup;

		reqId = NULL;
	}

	res = KSI_ExtendReq_enclose((reqRef = KSI_ExtendReq_ref(req)), ext->ksi_user, ext->ksi_pass, &pdu);
	if (res != KSI_OK) {
		KSI_ExtendReq_free(reqRef);
		goto cleanup;
	}

	res = prepareRequest(
			client,
			pdu,
			(int (*)(void *, unsigned char **, size_t *))KSI_ExtendPdu_serialize,
			handle,
			endp->url,
			"Extend request");
	if (res != KSI_OK) goto cleanup;

	(*handle)->reqCtx = (void*)req;
	(*handle)->reqCtx_free = (void (*)(void *))KSI_ExtendReq_free;

	res = KSI_OK;

cleanup:

	KSI_Integer_free(reqId);
	KSI_ExtendPdu_setRequest(pdu, NULL);
	KSI_ExtendPdu_free(pdu);

	return res;
}

static int prepareAggregationRequest(KSI_NetworkClient *client, KSI_AggregationReq *req, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationPdu *pdu = NULL;
	KSI_Integer *pReqId = NULL;
	KSI_Integer *reqId = NULL;
	KSI_NetEndpoint *aggr = NULL;
	HttpClient_Endpoint *endp = NULL;
	KSI_AggregationReq *reqRef = NULL;

	if (client == NULL || req == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	aggr = client->aggregator;
	if (aggr == NULL) {
		res = KSI_AGGREGATOR_NOT_CONFIGURED;
		goto cleanup;
	}
	endp = aggr->implCtx;
	if (endp == NULL || endp->url == NULL) {
		res = KSI_AGGREGATOR_NOT_CONFIGURED;
		goto cleanup;
	}

	res = KSI_AggregationReq_getRequestId(req, &pReqId);
	if (res != KSI_OK) goto cleanup;

	if (pReqId == NULL) {
		res = KSI_Integer_new(client->ctx, ++client->requestCount, &reqId);
		if (res != KSI_OK) goto cleanup;

		res = KSI_AggregationReq_setRequestId(req, reqId);
		if (res != KSI_OK) goto cleanup;

		reqId = NULL;
	}

	res = KSI_AggregationReq_enclose((reqRef = KSI_AggregationReq_ref(req)), aggr->ksi_user, aggr->ksi_pass, &pdu);
	if (res != KSI_OK) {
		KSI_AggregationReq_free(reqRef);
		goto cleanup;
	}

	res = prepareRequest(
			client,
			pdu,
			(int (*)(void *, unsigned char **, size_t *))KSI_AggregationPdu_serialize,
			handle,
			endp->url,
			"Aggregation request");
	if (res != KSI_OK) goto cleanup;

	(*handle)->reqCtx = (void*)req;
	(*handle)->reqCtx_free = (void (*)(void *))KSI_AggregationReq_free;

	res = KSI_OK;

cleanup:

	KSI_Integer_free(reqId);
	KSI_AggregationPdu_setRequest(pdu, NULL);
	KSI_AggregationPdu_free(pdu);

	return res;
}

static int preparePublicationsFileRequest(KSI_NetworkClient *client, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HttpClient *http = NULL;
	HttpClient_Endpoint *endp = NULL;
	KSI_RequestHandle *tmp = NULL;

	if (client == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(client->ctx);

	http = client->impl;
	endp = client->publicationsFile->implCtx;

	if (endp->url == NULL) {
		KSI_pushError(client->ctx, res = KSI_PUBLICATIONS_FILE_NOT_CONFIGURED, "The publications file URL has not been configured.");
		goto cleanup;
	}

	if (http->sendRequest == NULL) {
		KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}

	res = KSI_RequestHandle_new(client->ctx, NULL, 0, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	res = http->sendRequest(client, tmp, endp->url);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	*handle = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	return res;
}

static void httpClient_free(KSI_HttpClient *http) {
	if (http != NULL) {
		KSI_free(http->agentName);
		KSI_free(http->mimeType);

		if (http->implCtx_free != NULL) http->implCtx_free(http->implCtx);
		KSI_free(http);
	}
}

int KSI_AbstractHttpClient_new(KSI_CTX *ctx, KSI_NetworkClient **http) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_NetworkClient *tmp = NULL;
	KSI_HttpClient *c = NULL;
	HttpClient_Endpoint *endp_aggr = NULL;
	HttpClient_Endpoint *endp_ext = NULL;
	HttpClient_Endpoint *endp_pub = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || http == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* Create Abstract Network client with abstract endpoints. */
	res = KSI_AbstractNetworkClient_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Create Implementation for Abstract Network client. */
	c = KSI_new(KSI_HttpClient);
	if (c == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	c->agentName = NULL;
	c->mimeType = NULL;
	c->sendRequest = NULL;
	c->implCtx = NULL;
	c->implCtx_free = NULL;

	c->connectionTimeoutSeconds = 10; /* FIXME! Magic constants. */
	c->readTimeoutSeconds = 10;

	res = tmp->setStringParam(&c->agentName, "KSI HTTP Client"); /** Should be only user provided */
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->setStringParam(&c->mimeType, "application/ksi-request");
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Create implementations for abstract endpoints. */
	res = HttpClient_Endpoint_new(&endp_aggr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = HttpClient_Endpoint_new(&endp_ext);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = HttpClient_Endpoint_new(&endp_pub);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Set implementations for abstract endpoints. */
	res = KSI_NetEndpoint_setImplContext(tmp->aggregator, endp_aggr, (void (*)(void*))HttpClient_Endpoint_free);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	endp_aggr = NULL;

	res = KSI_NetEndpoint_setImplContext(tmp->extender, endp_ext, (void (*)(void*))HttpClient_Endpoint_free);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	endp_ext = NULL;

	res = KSI_NetEndpoint_setImplContext(tmp->publicationsFile, endp_pub, (void (*)(void*))HttpClient_Endpoint_free);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	endp_pub = NULL;


	/* Set implementations for abstract functions in KSI_NetworkClient. */
	tmp->sendExtendRequest = prepareExtendRequest;
	tmp->sendSignRequest = prepareAggregationRequest;
	tmp->sendPublicationRequest = preparePublicationsFileRequest;

	tmp->impl = c;
	tmp->implFree = (void (*)(void*))httpClient_free;
	c = NULL;

	*http = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	httpClient_free(c);
	KSI_NetworkClient_free(tmp);
	HttpClient_Endpoint_free(endp_aggr);
	HttpClient_Endpoint_free(endp_ext);
	HttpClient_Endpoint_free(endp_pub);

	return res;
}


#define KSI_NET_IMPLEMENT_SETTER(name, type, var, fn) 													\
		int KSI_HttpClient_set##name(KSI_NetworkClient *client, type val) {								\
			int res = KSI_UNKNOWN_ERROR;																\
			KSI_HttpClient *http = NULL;																\
			if (client == NULL || client->impl == NULL) {												\
				res = KSI_INVALID_ARGUMENT;																\
				goto cleanup;																			\
			}																							\
			http = client->impl;																		\
			res = (fn)(&http->var, val);																\
		cleanup:																						\
			return res;																					\
		}																								\

KSI_NET_IMPLEMENT_SETTER(ConnectTimeoutSeconds, int, connectionTimeoutSeconds, setIntParam);
KSI_NET_IMPLEMENT_SETTER(ReadTimeoutSeconds, int, readTimeoutSeconds, setIntParam);

static int ksi_HttpClient_setService(KSI_NetworkClient *client, KSI_NetEndpoint *abs_endp, const char *url, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;
	HttpClient_Endpoint *endp = NULL;

	if (abs_endp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	endp = abs_endp->implCtx;
	if (url != NULL) {
		res = client->setStringParam(&endp->url, url);
		if (res != KSI_OK) goto cleanup;
	}

	if (user != NULL) {
		res = client->setStringParam(&abs_endp->ksi_user, user);
		if (res != KSI_OK) goto cleanup;
	}

	if (pass != NULL) {
		res = client->setStringParam(&abs_endp->ksi_pass, pass);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_HttpClient_setAggregator(KSI_NetworkClient *client, const char *url, const char *user, const char *pass) {
	if (client == NULL || url == NULL || user == NULL || pass == NULL) return KSI_INVALID_ARGUMENT;
	return ksi_HttpClient_setService(client, client->aggregator, url, user, pass);
}

int KSI_HttpClient_setExtender(KSI_NetworkClient *client, const char *url, const char *user, const char *pass) {
	if (client == NULL || url == NULL || user == NULL || pass == NULL) return KSI_INVALID_ARGUMENT;
	return ksi_HttpClient_setService(client, client->extender, url, user, pass);
}

int KSI_HttpClient_setPublicationUrl(KSI_NetworkClient *client, const char *url) {
	if (client == NULL || url == NULL) return KSI_INVALID_ARGUMENT;
	return ksi_HttpClient_setService(client, client->publicationsFile, url, NULL, NULL);
}
