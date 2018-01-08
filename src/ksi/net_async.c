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

#include "net_async.h"

#include <string.h>

#include "internal.h"
#include "signature_builder.h"
#include "impl/signature_builder_impl.h"
#include "impl/net_impl.h"
#include "impl/ctx_impl.h"

#define KSI_ASYNC_REQUEST_ID_OFFSET 32
#define KSI_ASYNC_REQUEST_ID_OFFSET_MAX 0xff
#define KSI_ASYNC_REQUEST_ID_OFFSET_MASK 0xffffffff00000000ULL
#define KSI_ASYNC_REQUEST_ID_MASK        0x00000000ffffffffULL

#define KSI_ASYNC_DEFAULT_ROUND_MAX_COUNT 1
#define KSI_ASYNC_DEFAULT_REQUEST_CACHE_SIZE 1
#define KSI_ASYNC_DEFAULT_TIMEOUT_SEC 10
#define KSI_ASYNC_ROUND_DURATION_SEC 1

#define KSI_ASYNC_CACHE_START_POS 1

void KSI_AsyncHandle_free(KSI_AsyncHandle *o) {
	if (o != NULL && --o->ref == 0) {
		KSI_AggregationReq_free(o->aggrReq);
		KSI_ExtendReq_free(o->extReq);
		if (o->respCtx_free) o->respCtx_free(o->respCtx);
		if (o->userCtx_free) o->userCtx_free(o->userCtx);
		KSI_free(o->raw);
		KSI_Utf8String_free(o->errMsg);

		KSI_free(o);
	}
}

static int KSI_AbstractAsyncHandle_new(KSI_CTX *ctx, KSI_AsyncHandle **o) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncHandle *tmp = NULL;

	if (ctx == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_malloc(sizeof(KSI_AsyncHandle));
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;

	tmp->id = 0;

	tmp->raw = NULL;
	tmp->len = 0;
	tmp->sentCount = 0;

	tmp->aggrReq = NULL;
	tmp->extReq = NULL;

	tmp->respCtx = NULL;
	tmp->respCtx_free = NULL;

	tmp->reqTime = 0;
	tmp->sndTime = 0;
	tmp->rcvTime = 0;

	tmp->userCtx = NULL;
	tmp->userCtx_free = NULL;

	tmp->state = KSI_ASYNC_STATE_UNDEFINED;

	tmp->err = KSI_OK;
	tmp->errExt = 0L;
	tmp->errMsg = NULL;

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncHandle_free(tmp);
	return res;
}

int KSI_AsyncAggregationHandle_new(KSI_CTX *ctx, KSI_AggregationReq *req, KSI_AsyncHandle **o) {
	int res = KSI_UNKNOWN_ERROR;

	if (ctx == NULL || req == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_AbstractAsyncHandle_new(ctx, o);
	if (res != KSI_OK) goto cleanup;

	(*o)->aggrReq = req;
	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncExtendHandle_new(KSI_CTX *ctx, KSI_ExtendReq *req, KSI_AsyncHandle **o) {
	int res = KSI_UNKNOWN_ERROR;

	if (ctx == NULL || req == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_AbstractAsyncHandle_new(ctx, o);
	if (res != KSI_OK) goto cleanup;

	(*o)->extReq = req;
	res = KSI_OK;
cleanup:
	return res;
}

KSI_IMPLEMENT_REF(KSI_AsyncHandle)

KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, int, state, State)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, int, err, Error)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, long, errExt, ExtError)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, KSI_Utf8String *, errMsg, ErrorMessage)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, const void *, userCtx, RequestCtx)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, KSI_uint64_t, id, RequestId)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, KSI_AggregationReq *, aggrReq, AggregationReq)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, KSI_ExtendReq *, extReq, ExtendReq)

int KSI_AsyncHandle_getAggregationResp(const KSI_AsyncHandle *h, KSI_AggregationResp **resp) {
	int res = KSI_UNKNOWN_ERROR;

	if (h == NULL || resp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	if (h->aggrReq == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}
	*resp = (KSI_AggregationResp*)h->respCtx;
	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncHandle_getExtendResp(const KSI_AsyncHandle *h, KSI_ExtendResp **resp) {
	int res = KSI_UNKNOWN_ERROR;

	if (h == NULL || resp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	if (h->extReq == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}
	*resp = (KSI_ExtendResp*)h->respCtx;
	res = KSI_OK;
cleanup:
	return res;
}

static int createSignature(const KSI_AsyncHandle *h, KSI_Signature **sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;
	KSI_DataHash *rootHash = NULL;
	KSI_Integer *rootLevel = NULL;
	KSI_AggregationResp *resp = NULL;
	KSI_SignatureBuilder *builder = NULL;

	if (h == NULL || sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(h->ctx);

	if (h->aggrReq == NULL || h->respCtx == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}
	resp = (KSI_AggregationResp *)h->respCtx;

	res = KSI_SignatureBuilder_openFromAggregationResp(resp, &builder);
	if (res != KSI_OK) {
		KSI_pushError(h->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationReq_getRequestLevel(h->aggrReq, &rootLevel);
	if (res != KSI_OK) {
		KSI_pushError(h->ctx, res, NULL);
		goto cleanup;
	}

	/* Turn off the verification. */
	builder->noVerify = 1;
	res = KSI_SignatureBuilder_close(builder, KSI_Integer_getUInt64(rootLevel), &tmp);
	if (res != KSI_OK) {
		KSI_pushError(h->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationReq_getRequestHash(h->aggrReq, &rootHash);
	if (res != KSI_OK) {
		KSI_pushError(h->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_Signature_verifyWithPolicy(tmp, rootHash, 0, KSI_VERIFICATION_POLICY_INTERNAL, NULL);
	if (res != KSI_OK) {
		KSI_pushError(h->ctx, res, NULL);
		goto cleanup;
	}

	*sig = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_SignatureBuilder_free(builder);
	KSI_Signature_free(tmp);
	return res;
}

int KSI_AsyncHandle_getSignature(const KSI_AsyncHandle *h, KSI_Signature **signature) {
	int res = KSI_UNKNOWN_ERROR;

	if (h == NULL || signature == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(h->ctx);

	if (h->aggrReq != NULL) {
		res = createSignature(h, signature);
		if (res != KSI_OK) {
			KSI_pushError(h->ctx, res, NULL);
			goto cleanup;
		}
	} else if (h->extReq != NULL) {
		KSI_pushError(h->ctx, res = KSI_INVALID_STATE, "Not implemented.");
		goto cleanup;
	} else {
		KSI_pushError(h->ctx, res = KSI_INVALID_STATE, "Request is missing.");
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncHandle_getConfig(const KSI_AsyncHandle *h, KSI_Config **config) {
	int res = KSI_UNKNOWN_ERROR;

	if (h == NULL || config == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(h->ctx);

	*config = (KSI_Config*)h->respCtx;
	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncHandle_setRequestCtx(KSI_AsyncHandle *o, void *reqCtx, void (*reqCtx_free)(void*)) {
	int res = KSI_UNKNOWN_ERROR;

	if (o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (o->userCtx_free) o->userCtx_free(o->userCtx);

	o->userCtx = reqCtx;
	o->userCtx_free = reqCtx_free;

	res = KSI_OK;
cleanup:
	return res;
}


static int asyncClient_calculateRequestId(KSI_AsyncClient *c, KSI_uint64_t *id, KSI_uint64_t *offset) {
	int res = KSI_UNKNOWN_ERROR;

	if (c == NULL || c->reqCache == NULL || id == NULL || offset == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	do {
		/* Check if the cache is full. */
		if ((c->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE]) == (c->pending + c->received + 1)) {
			res = KSI_ASYNC_REQUEST_CACHE_FULL;
			goto cleanup;
		}
		if (++c->requestCount == c->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE]) {
			c->requestCountOffset =  (c->requestCountOffset + 1) % KSI_ASYNC_REQUEST_ID_OFFSET_MAX;
			c->requestCount = KSI_ASYNC_CACHE_START_POS;
		}
	} while (c->reqCache[c->requestCount] != NULL);

	*id = c->requestCount;
	*offset = c->requestCountOffset;
	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_composeRequestHeader(KSI_AsyncClient *c, KSI_Header **hdr) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Header *tmp = NULL;
	const char *user = NULL;
	KSI_Utf8String *loginId = NULL;
	KSI_Integer *instanceId = NULL;

	if (c == NULL || hdr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (c->clientImpl == NULL || c->getCredentials == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	res = KSI_Header_new(c->ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = c->getCredentials(c->clientImpl, &user, NULL);
	if (res != KSI_OK) goto cleanup;

	if (user != NULL) {
		res = KSI_Utf8String_new(c->ctx, user, strlen(user) + 1, &loginId);
		if (res != KSI_OK) goto cleanup;

		res = KSI_Header_setLoginId(tmp, loginId);
		if (res != KSI_OK) goto cleanup;
		loginId = NULL;
	}

	res = KSI_Integer_new(c->ctx, c->instanceId, &instanceId);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Header_setInstanceId(tmp, instanceId);
	if (res != KSI_OK) goto cleanup;
	instanceId = NULL;

	*hdr = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_Header_free(tmp);
	KSI_Utf8String_free(loginId);
	KSI_Integer_free(instanceId);

	return res;
}

static int asyncClient_addAggregatorRequest(KSI_AsyncClient *c, KSI_AsyncHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationReq *reqRef = NULL;
	KSI_AggregationPdu *pdu = NULL;
	unsigned char *raw = NULL;
	size_t len;
	KSI_AsyncHandle *hndlRef = NULL;
	KSI_Integer *reqId = NULL;
	const char *pass = NULL;
	KSI_uint64_t id = 0;
	KSI_uint64_t idOffset = 0;
	KSI_uint64_t requestId = 0;
	void *impl = NULL;
	KSI_AggregationReq *aggrReq = NULL;
	KSI_Header *hdr = NULL;
	KSI_DataHash *reqHsh = NULL;
	KSI_Config *reqConf = NULL;
	KSI_AsyncHandle *confHandle = NULL;
	KSI_AggregationReq *tmpReq = NULL;

	if (c == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(c->ctx);

	if (handle->aggrReq == NULL ||
			c->clientImpl == NULL || c->addRequest == NULL || c->getCredentials == NULL) {
		KSI_pushError(c->ctx, res = KSI_INVALID_STATE, "Async client is not initialized properly.");
		goto cleanup;
	}
	impl = c->clientImpl;
	aggrReq = handle->aggrReq;

	/* Cleanup the handle in case it has been added repeteadly. */
	KSI_free(handle->raw);
	handle->raw = NULL;
	KSI_Utf8String_free(handle->errMsg);
	handle->errMsg = NULL;
	if (handle->respCtx_free) handle->respCtx_free(handle->respCtx);
	handle->respCtx_free = NULL;
	handle->id = 0;

	res = KSI_AggregationReq_getRequestHash(aggrReq, &reqHsh);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AggregationReq_getConfig(aggrReq, &reqConf);
	if (res != KSI_OK) goto cleanup;

	/* Update request id only in case of aggregation request. */
	if (reqHsh != NULL) {
		res = KSI_AggregationReq_getRequestId(aggrReq, &reqId);
		if (res != KSI_OK) goto cleanup;

		/* Clear the request id that was set.  */
		if (reqId != NULL) {
			KSI_Integer_free(reqId);
			res = KSI_AggregationReq_setRequestId(aggrReq, (reqId = NULL));
			if (res != KSI_OK) goto cleanup;
		}

		/* Verify if there is spare place in the request cache and get the request id. */
		res = asyncClient_calculateRequestId(c, &id, &idOffset);
		if (res != KSI_OK) goto cleanup;

		requestId = (idOffset << KSI_ASYNC_REQUEST_ID_OFFSET) | id;
		res = KSI_Integer_new(c->ctx, requestId, &reqId);
		if (res != KSI_OK) goto cleanup;

		res = KSI_AggregationReq_setRequestId(aggrReq, reqId);
		if (res != KSI_OK) goto cleanup;
		reqId = NULL;
	}

	res = c->getCredentials(impl, NULL, &pass);
	if (res != KSI_OK) goto cleanup;

	res = asyncClient_composeRequestHeader(c, &hdr);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AggregationReq_encloseWithHeader((reqRef = KSI_AggregationReq_ref(aggrReq)), hdr, pass, &pdu);
	if (res != KSI_OK) {
		KSI_AggregationReq_free(reqRef);
		goto cleanup;
	}
	hdr = NULL;

	res = KSI_AggregationPdu_serialize(pdu, &raw, &len);
	if (res != KSI_OK) goto cleanup;

	handle->id = requestId;
	handle->raw = raw;
	raw = NULL;
	handle->len = len;
	handle->sentCount = 0;

	/* Add request to the impl output queue. The query might fail if the queue is full. */
	res = c->addRequest(impl, (hndlRef = KSI_AsyncHandle_ref(handle)));
	if (res != KSI_OK) {
		KSI_AsyncHandle_free(hndlRef);
		goto cleanup;
	}

	/* Set aggregation request into local cache. */
	if (reqHsh != NULL) {
		c->reqCache[id] = handle;
		c->pending++;
	}

	/* Cache the config request separatelly, as the response can not be assigned to any request in the common cache. */
	if (reqConf != NULL) {
		/* Check if this is a multy-payload request. */
		if (reqHsh != NULL) {
			KSI_Config *confRef = NULL;

			/* Create a separate conf request handle. */
			res = KSI_AggregationReq_new(c->ctx, &tmpReq);
			if (res != KSI_OK) goto cleanup;

			res = KSI_AggregationReq_setConfig(tmpReq, (confRef = KSI_Config_ref(reqConf)));
			if (res != KSI_OK) {
				KSI_Config_free(confRef);
				goto cleanup;
			}

			res = KSI_AsyncAggregationHandle_new(c->ctx, tmpReq, &confHandle);
			if (res != KSI_OK) goto cleanup;
			tmpReq = NULL;

			/* Copy the send state from the initial handle. */
			confHandle->state = handle->state;
			confHandle->reqTime = handle->reqTime;
		} else {
			/* This is a server conf request. */
			confHandle = handle;
		}

		c->serverConf = confHandle;
		confHandle = NULL;
		c->pending++;
	}

	res = KSI_OK;
cleanup:
	KSI_AggregationReq_free(tmpReq);
	KSI_AsyncHandle_free(confHandle);
	KSI_Header_free(hdr);
	KSI_free(raw);
	KSI_Integer_free(reqId);
	KSI_AggregationPdu_free(pdu);

	return res;
}

static int asyncClient_addExtenderRequest(KSI_AsyncClient *c, KSI_AsyncHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendReq *reqRef = NULL;
	KSI_ExtendPdu *pdu = NULL;
	unsigned char *raw = NULL;
	size_t len;
	KSI_AsyncHandle *hndlRef = NULL;
	KSI_Integer *reqId = NULL;
	const char *pass = NULL;
	KSI_uint64_t id = 0;
	KSI_uint64_t idOffset = 0;
	KSI_uint64_t requestId = 0;
	void *impl = NULL;
	KSI_ExtendReq *extReq = NULL;
	KSI_Header *hdr = NULL;
	KSI_Integer *aggrTime = NULL;
	KSI_Integer *publTime = NULL;
	KSI_Config *reqConf = NULL;
	KSI_AsyncHandle *confHandle = NULL;
	KSI_ExtendReq *tmpReq = NULL;

	if (c == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(c->ctx);

	if (handle->extReq == NULL ||
			c->clientImpl == NULL || c->addRequest == NULL || c->getCredentials == NULL) {
		KSI_pushError(c->ctx, res = KSI_INVALID_STATE, "Async client is not initialized properly.");
		goto cleanup;
	}
	impl = c->clientImpl;
	extReq = handle->extReq;

	/* Cleanup the handle in case it has been added repeteadly. */
	KSI_free(handle->raw);
	handle->raw = NULL;
	KSI_Utf8String_free(handle->errMsg);
	handle->errMsg = NULL;
	if (handle->respCtx_free) handle->respCtx_free(handle->respCtx);
	handle->respCtx_free = NULL;
	handle->id = 0;

	res = KSI_ExtendReq_getAggregationTime(extReq, &aggrTime);
	if (res != KSI_OK) goto cleanup;

	res = KSI_ExtendReq_getPublicationTime(extReq, &publTime);
	if (res != KSI_OK) goto cleanup;

	res = KSI_ExtendReq_getConfig(extReq, &reqConf);
	if (res != KSI_OK) goto cleanup;

	/* Update request id only in case of aggregation request. */
	if (aggrTime != NULL || publTime != NULL) {
		res = KSI_ExtendReq_getRequestId(extReq, &reqId);
		if (res != KSI_OK) goto cleanup;

		/* Clear the request id that was set.  */
		if (reqId != NULL) {
			KSI_Integer_free(reqId);
			res = KSI_ExtendReq_setRequestId(extReq, (reqId = NULL));
			if (res != KSI_OK) goto cleanup;
		}

		/* Verify if there is spare place in the request cache and get the request id. */
		res = asyncClient_calculateRequestId(c, &id, &idOffset);
		if (res != KSI_OK) goto cleanup;

		requestId = (idOffset << KSI_ASYNC_REQUEST_ID_OFFSET) | id;
		res = KSI_Integer_new(c->ctx, requestId, &reqId);
		if (res != KSI_OK) goto cleanup;

		res = KSI_ExtendReq_setRequestId(extReq, reqId);
		if (res != KSI_OK) goto cleanup;
		reqId = NULL;
	}

	res = c->getCredentials(impl, NULL, &pass);
	if (res != KSI_OK) goto cleanup;

	res = asyncClient_composeRequestHeader(c, &hdr);
	if (res != KSI_OK) goto cleanup;

	res = KSI_ExtendReq_encloseWithHeader((reqRef = KSI_ExtendReq_ref(extReq)), hdr, pass, &pdu);
	if (res != KSI_OK) {
		KSI_ExtendReq_free(reqRef);
		goto cleanup;
	}
	hdr = NULL;

	res = KSI_ExtendPdu_serialize(pdu, &raw, &len);
	if (res != KSI_OK) goto cleanup;

	handle->id = requestId;
	handle->raw = raw;
	raw = NULL;
	handle->len = len;
	handle->sentCount = 0;

	/* Add request to the impl output queue. The query might fail if the queue is full. */
	res = c->addRequest(impl, (hndlRef = KSI_AsyncHandle_ref(handle)));
	if (res != KSI_OK) {
		KSI_AsyncHandle_free(hndlRef);
		goto cleanup;
	}

	/* Set aggregation request into local cache. */
	if (aggrTime != NULL || publTime != NULL) {
		c->reqCache[id] = handle;
		c->pending++;
	}

	/* Cache the config request separatelly, as the response can not be assigned to any request in the common cache. */
	if (reqConf != NULL) {
		/* Check if this is a multy-payload request. */
		if (aggrTime != NULL || publTime != NULL) {
			KSI_Config *confRef = NULL;

			/* Create a separate conf request handle. */
			res = KSI_ExtendReq_new(c->ctx, &tmpReq);
			if (res != KSI_OK) goto cleanup;

			res = KSI_ExtendReq_setConfig(tmpReq, (confRef = KSI_Config_ref(reqConf)));
			if (res != KSI_OK) {
				KSI_Config_free(confRef);
				goto cleanup;
			}

			res = KSI_AsyncExtendHandle_new(c->ctx, tmpReq, &confHandle);
			if (res != KSI_OK) goto cleanup;
			tmpReq = NULL;

			/* Copy the send state from the initial handle. */
			confHandle->state = handle->state;
			confHandle->reqTime = handle->reqTime;
		} else {
			/* This is a server conf request. */
			confHandle = handle;
		}

		c->serverConf = confHandle;
		confHandle = NULL;
		c->pending++;
	}

	res = KSI_OK;
cleanup:
	KSI_ExtendReq_free(tmpReq);
	KSI_AsyncHandle_free(confHandle);
	KSI_Header_free(hdr);
	KSI_free(raw);
	KSI_Integer_free(reqId);
	KSI_ExtendPdu_free(pdu);

	return res;
}

static void asyncClient_setResponseError(KSI_AsyncClient *c, int state, int err, long extErr, KSI_Utf8String *errMsg) {
	size_t i;

	if (c == NULL) return;

	for (i = KSI_ASYNC_CACHE_START_POS; i < c->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE]; i++) {
		if (c->reqCache[i] != NULL && c->reqCache[i]->state == state) {
			c->reqCache[i]->state = KSI_ASYNC_STATE_ERROR;
			c->reqCache[i]->err = err;
			c->reqCache[i]->errExt = extErr;
			c->reqCache[i]->errMsg = KSI_Utf8String_ref(errMsg);
		}
	}
}

static int handleResponse(KSI_AsyncClient *c, void *resp,
		int (*asyncHandle_getRequest)(const KSI_AsyncHandle *h, void **req),
		int (*convertStatusCode)(const KSI_Integer *statusCode),
		int (*resp_getRequestId)(const void *resp, KSI_Integer **requestId),
		int (*resp_verifyWithRequest)(const void *resp, const void *req),
		int (*resp_getStatus)(const void *resp, KSI_Integer **status),
		int (*resp_getErrorMsg)(const void *resp, KSI_Utf8String **errorMsg),
		void* (*resp_ref)(void *resp),
		void (*resp_free)(void *resp)) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *reqId = NULL;
	KSI_AsyncHandle *handle = NULL;
	KSI_uint64_t id = 0;

	if (c == NULL || resp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(c->ctx);

	res = resp_getRequestId(resp, &reqId);
	if (res != KSI_OK) {
		KSI_pushError(c->ctx, res , NULL);
		goto cleanup;
	}

	id = KSI_Integer_getUInt64(reqId) & KSI_ASYNC_REQUEST_ID_MASK;
	if (c->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE] <= id ||
			(handle = c->reqCache[id]) == NULL || handle->id != KSI_Integer_getUInt64(reqId)) {
		KSI_LOG_warn(c->ctx, "Unexpected async response received.");
		goto cleanup;
	}

	if (handle->state == KSI_ASYNC_STATE_WAITING_FOR_RESPONSE) {
		KSI_Integer *status = NULL;
		void *req = NULL;

		res = asyncHandle_getRequest(handle, &req);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		res = resp_verifyWithRequest(resp, req);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		/* Verify response status. */
		res = resp_getStatus(resp, &status);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		res = convertStatusCode(status);
		if (res != KSI_OK) {
			KSI_Utf8String *errorMsg = NULL;

			resp_getErrorMsg(resp, &errorMsg);
			KSI_LOG_error(c->ctx, "Async request failed: [%llx] %s", (unsigned long long)KSI_Integer_getUInt64(status), KSI_Utf8String_cstr(errorMsg));

			handle->state = KSI_ASYNC_STATE_ERROR;
			handle->err = res;
			handle->errExt = (long)KSI_Integer_getUInt64(status);
			handle->errMsg = KSI_Utf8String_ref(errorMsg);
		} else {
			handle->respCtx = resp_ref(resp);
			handle->respCtx_free = resp_free;

			handle->state = KSI_ASYNC_STATE_RESPONSE_RECEIVED;
			c->pending--;
			c->received++;
		}
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_handleAggregationResp(KSI_AsyncClient *c, KSI_AggregationPdu *pdu) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationResp *resp = NULL;

	if (c == NULL || pdu == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(c->ctx);

	/*Get response object*/
	res = KSI_AggregationPdu_getResponse(pdu, &resp);
	if (res != KSI_OK) {
		KSI_pushError(c->ctx, res, NULL);
		goto cleanup;
	}

	if (resp != NULL) {
		res =  handleResponse(c, resp,
				(int (*)(const KSI_AsyncHandle *h, void **req))KSI_AsyncHandle_getAggregationReq,
				KSI_convertAggregatorStatusCode,
				(int (*)(const void *resp, KSI_Integer **requestId))KSI_AggregationResp_getRequestId,
				(int (*)(const void *resp, const void *req))KSI_AggregationResp_verifyWithRequest,
				(int (*)(const void *resp, KSI_Integer **status))KSI_AggregationResp_getStatus,
				(int (*)(const void *resp, KSI_Utf8String **errorMsg))KSI_AggregationResp_getErrorMsg,
				(void* (*)(void *resp))KSI_AggregationResp_ref,
				(void (*)(void *resp))KSI_AggregationResp_free);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_handleExtendResp(KSI_AsyncClient *c, KSI_ExtendPdu *pdu) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendResp *resp = NULL;

	if (c == NULL || pdu == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(c->ctx);

	/*Get response object*/
	res = KSI_ExtendPdu_getResponse(pdu, &resp);
	if (res != KSI_OK) {
		KSI_pushError(c->ctx, res, NULL);
		goto cleanup;
	}

	if (resp != NULL) {
		res =  handleResponse(c, resp,
				(int (*)(const KSI_AsyncHandle *h, void **req))KSI_AsyncHandle_getExtendReq,
				KSI_convertExtenderStatusCode,
				(int (*)(const void *resp, KSI_Integer **requestId))KSI_ExtendResp_getRequestId,
				(int (*)(const void *resp, const void *req))KSI_ExtendResp_verifyWithRequest,
				(int (*)(const void *resp, KSI_Integer **status))KSI_ExtendResp_getStatus,
				(int (*)(const void *resp, KSI_Utf8String **errorMsg))KSI_ExtendResp_getErrorMsg,
				(void* (*)(void *resp))KSI_ExtendResp_ref,
				(void (*)(void *resp))KSI_ExtendResp_free);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_handleServerConfig(KSI_AsyncClient *c, KSI_Config *config) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncHandle *confHandle = NULL;

	if (c == NULL || config == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(c->ctx);

	if (c->serverConf != NULL) {
		c->serverConf->state = KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED;
		/* Update internal state if the request has been requested. */
		if (c->serverConf->aggrReq != NULL && c->serverConf->respCtx == NULL) {
			c->pending--;
			c->received++;
		}
		/* Clear previoous response if present, as it will be renewed. */
		if (c->serverConf->respCtx != NULL) c->serverConf->respCtx_free(c->serverConf->respCtx);
		/* Set received config. */
		c->serverConf->respCtx = (void*)KSI_Config_ref(config);
		c->serverConf->respCtx_free = (void (*)(void*))KSI_Config_free;
	} else {
		KSI_Config_Callback confCallback = (KSI_Config_Callback)(c->ctx->options[KSI_OPT_AGGR_CONF_RECEIVED_CALLBACK]);

		/* It is push conf which was not explicitly requested. Invoke the user conf receive callback. */
		if (confCallback != NULL) {
			res = confCallback(c->ctx, config);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}
		} else {
			/* Create an empty handle. */
			res = KSI_AbstractAsyncHandle_new(c->ctx, &confHandle);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			confHandle->respCtx = (void*)KSI_Config_ref(config);
			confHandle->respCtx_free = (void (*)(void*))KSI_Config_free;

			confHandle->state = KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED;
			c->received++;

			c->serverConf = confHandle;
			confHandle = NULL;
		}
	}

	res = KSI_OK;
cleanup:
	KSI_AsyncHandle_free(confHandle);

	return res;
}

static int processResponseQueue(KSI_AsyncClient *c,
		int (*pdu_parse)(KSI_CTX *ctx, const unsigned char *raw, size_t len, void **t),
		void (*pdu_free)(void *pdu),
		int (*pdu_getError)(const void *pdu, KSI_ErrorPdu **error),
		int (*pdu_setError)(void *pdu, KSI_ErrorPdu *error),
		int (*pdu_verify)(const void *pdu, const char *pass),
		int (*pdu_getConfResponse)(const void *pdu, KSI_Config **confResponse),
		int (*convertStatusCode)(const KSI_Integer *statusCode),
		int (*asyncClient_handleResponse)(KSI_AsyncClient *c, void *pdu)) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_OctetString *resp = NULL;
	void *pdu = NULL;
	void *impl = NULL;
	size_t left = 0;
	KSI_ErrorPdu *errPdu = NULL;

	if (c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(c->ctx);

	if (c->clientImpl == NULL || c->getResponse == NULL || c->getCredentials == NULL) {
		KSI_pushError(c->ctx, res = KSI_INVALID_STATE, "Async client is not properly initialized.");
		goto cleanup;
	}
	impl = c->clientImpl;

	do {
		/* Cleanup leftovers from previous cycle. */
		KSI_OctetString_free(resp);
		resp = NULL;
		pdu_free(pdu);
		pdu = NULL;

		res = c->getResponse(impl, &resp, &left);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		if (resp != NULL) {
			KSI_ErrorPdu *error = NULL;
			KSI_Config *tmpConf = NULL;
			const char *pass = NULL;
			const unsigned char *raw = NULL;
			size_t len = 0;

			res = KSI_OctetString_extract(resp, &raw, &len);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			KSI_LOG_logBlob(c->ctx, KSI_LOG_DEBUG, "Parsing response response", raw, len);

			/* Get PDU object. */
			res = pdu_parse(c->ctx, raw, len, &pdu);
			if(res != KSI_OK){
				KSI_LOG_logBlob(c->ctx, KSI_LOG_ERROR, "Parsing aggregation response failed", raw, len);
				KSI_pushError(c->ctx, res, "Unable to parse aggregation pdu.");
				goto cleanup;
			}

			/* Check for error PDU. */
			res = pdu_getError(pdu, &error);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}
			if (error != NULL) {
				res = pdu_setError(pdu, NULL);
				if (res != KSI_OK) {
					KSI_pushError(c->ctx, res, NULL);
					goto cleanup;
				}
				KSI_ErrorPdu_free(errPdu);
				/* Keep the error until all responses have been processed. */
				errPdu = error;

				continue;
			}

			res = c->getCredentials(impl, NULL, &pass);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			res = pdu_verify(pdu, pass);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			res = pdu_getConfResponse(pdu, &tmpConf);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			/* Handle push config. */
			if (tmpConf != NULL) {
				res = asyncClient_handleServerConfig(c, tmpConf);
				if (res != KSI_OK) {
					KSI_pushError(c->ctx, res , NULL);
					goto cleanup;
				}
			}

			res = asyncClient_handleResponse(c, pdu);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res , NULL);
				goto cleanup;
			}
		}
	} while (left != 0);

	/* Handle error PDU. */
	if (errPdu != NULL) {
		KSI_Utf8String *errorMsg = NULL;
		KSI_Integer *status = NULL;

		KSI_ErrorPdu_getErrorMessage(errPdu, &errorMsg);
		KSI_ErrorPdu_getStatus(errPdu, &status);

		KSI_LOG_error(c->ctx, "Async received error PDU: [%x:%llx] %s",
				(unsigned)convertStatusCode(status), (unsigned long long)KSI_Integer_getUInt64(status), KSI_Utf8String_cstr(errorMsg));

		/* Set all handles that are still in response wait state into error state. */
		asyncClient_setResponseError(c, KSI_ASYNC_STATE_WAITING_FOR_RESPONSE,
				convertStatusCode(status), (long)KSI_Integer_getUInt64(status), errorMsg);
	}

	res = KSI_OK;
cleanup:
	KSI_ErrorPdu_free(errPdu);
	KSI_OctetString_free(resp);
	pdu_free(pdu);

	return res;
}

static int asyncClient_processAggregationResponseQueue(KSI_AsyncClient *c) {
	return processResponseQueue(c,
			(int (*)(KSI_CTX *, const unsigned char *, size_t, void **))KSI_AggregationPdu_parse,
			(void (*)(void *))KSI_AggregationPdu_free,
			(int (*)(const void *, KSI_ErrorPdu **))KSI_AggregationPdu_getError,
			(int (*)(void *, KSI_ErrorPdu *))KSI_AggregationPdu_setError,
			(int (*)(const void *, const char *))KSI_AggregationPdu_verify,
			(int (*)(const void *, KSI_Config **))KSI_AggregationPdu_getConfResponse,
			(int (*)(const KSI_Integer *))KSI_convertAggregatorStatusCode,
			(int (*)(KSI_AsyncClient *, void *))asyncClient_handleAggregationResp);
}

static int asyncClient_processExtenderResponseQueue(KSI_AsyncClient *c) {
	return processResponseQueue(c,
			(int (*)(KSI_CTX *, const unsigned char *, size_t, void **))KSI_ExtendPdu_parse,
			(void (*)(void *))KSI_ExtendPdu_free,
			(int (*)(const void *, KSI_ErrorPdu **))KSI_ExtendPdu_getError,
			(int (*)(void *, KSI_ErrorPdu *))KSI_ExtendPdu_setError,
			(int (*)(const void *, const char *))KSI_ExtendPdu_verify,
			(int (*)(const void *, KSI_Config **))KSI_ExtendPdu_getConfResponse,
			(int (*)(const KSI_Integer *))KSI_convertExtenderStatusCode,
			(int (*)(KSI_AsyncClient *, void *))asyncClient_handleExtendResp);
}

static bool asyncClient_finalizeRequest(KSI_AsyncClient *c, KSI_AsyncHandle *handle) {
	if (c == NULL || handle == NULL) return false;

	switch (handle->state) {
		case KSI_ASYNC_STATE_WAITING_FOR_RESPONSE:
			/* Verify that the handle has not been waiting a response for too long. */
			if (c->options[KSI_ASYNC_OPT_RCV_TIMEOUT] == 0 ||
				difftime(time(NULL), handle->sndTime) > c->options[KSI_ASYNC_OPT_RCV_TIMEOUT]) {
				/* Set handle into error state and return it. */
				handle->state = KSI_ASYNC_STATE_ERROR;
				handle->err = KSI_NETWORK_RECIEVE_TIMEOUT;
				c->pending--;
				return true;
			}
			return false;

		case KSI_ASYNC_STATE_ERROR:
			c->pending--;
			return true;

		case KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED:
		case KSI_ASYNC_STATE_RESPONSE_RECEIVED:
			c->received--;
			return true;

		default:
			return false;
	}
}

static int asyncClient_findNextResponse(KSI_AsyncClient *c, KSI_AsyncHandle **handle) {
	int res;
	size_t last;

	if (c == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(c->ctx);

	if (c->reqCache == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	/* Verify if there are any handles on hold in cache. */
	if (c->pending == 0 && c->received == 0) {
		*handle = NULL;
		res = KSI_OK;
		goto cleanup;
	}

	/* Check if server configuration has been received. */
	if (asyncClient_finalizeRequest(c, c->serverConf) == true) {
		*handle = c->serverConf;
		c->serverConf = NULL;
		res = KSI_OK;
		goto cleanup;
	}

	/* Search cache for finalized requests. */
	last = c->tail;
	for (;;) {
		if (asyncClient_finalizeRequest(c, c->reqCache[c->tail]) == true) {
			*handle = c->reqCache[c->tail];
			c->reqCache[c->tail] = NULL;
			res = KSI_OK;
			goto cleanup;
		}

		if (++c->tail == c->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE]) c->tail = KSI_ASYNC_CACHE_START_POS;
		if (c->tail == last) {
			/* We are back at where we began the search. There are no finalized requests to return yet. */
			break;
		}
	}
	/* Nothing to return. */
	*handle = NULL;
	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_run(KSI_AsyncClient *c, int (*handleResp)(KSI_AsyncClient *), KSI_AsyncHandle **handle, size_t *waiting) {
	int res = KSI_UNKNOWN_ERROR;
	bool connClosed = false;

	if (c == NULL || handleResp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(c->ctx);
	if (c->clientImpl == NULL || c->dispatch == NULL) {
		KSI_pushError(c->ctx, res = KSI_INVALID_STATE, "Async client is not properly initialized.");
		goto cleanup;
	}

	KSI_ERR_clearErrors(c->ctx);
	res = c->dispatch(c->clientImpl);
	if (res == KSI_ASYNC_CONNECTION_CLOSED) {
		connClosed = true;
	} else if (res != KSI_OK) {
		KSI_pushError(c->ctx, res, "Async client impl returned error.");
		KSI_LOG_logCtxError(c->ctx, KSI_LOG_ERROR);
		asyncClient_setResponseError(c, KSI_ASYNC_STATE_WAITING_FOR_RESPONSE, res, 0L, NULL);
	}

	/* Handle responses. */
	KSI_ERR_clearErrors(c->ctx);
	res = handleResp(c);
	if (res != KSI_OK) {
		KSI_pushError(c->ctx, res, "Async client failed to process responses.");
		KSI_LOG_logCtxError(c->ctx, KSI_LOG_ERROR);
		asyncClient_setResponseError(c, KSI_ASYNC_STATE_WAITING_FOR_RESPONSE, res, 0L, NULL);
	}

	/* Update request state if connection has been closed remotely. */
	if (connClosed) {
		/* Set all handles that are still in response wait state into error state. */
		asyncClient_setResponseError(c, KSI_ASYNC_STATE_WAITING_FOR_RESPONSE,
				KSI_ASYNC_CONNECTION_CLOSED, 0L, NULL);
	}

	if (handle != NULL) {
		KSI_ERR_clearErrors(c->ctx);
		res = asyncClient_findNextResponse(c, handle);
		if (res != KSI_OK)  {
			KSI_pushError(c->ctx, res, "Async client failed to find next response.");
			KSI_LOG_logCtxError(c->ctx, KSI_LOG_ERROR);
		}
	}
	if (waiting != NULL) *waiting = (c->pending + c->received);

	res = KSI_OK;
cleanup:
	return res;
}

int asyncClient_getPendingCount(KSI_AsyncClient *c, size_t *count) {
	int res = KSI_UNKNOWN_ERROR;

	if (c == NULL || count == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	*count = c->pending;

	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_getReceivedCount(KSI_AsyncClient *c, size_t *count) {
	int res = KSI_UNKNOWN_ERROR;

	if (c == NULL || count == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	*count = c->received;

	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_setOption(KSI_AsyncClient *c, int opt, void *param) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncHandle **tmpCache = NULL;

	KSI_ERR_clearErrors(c->ctx);
	if (c == NULL || opt >= __NOF_KSI_ASYNC_OPT) {
		KSI_pushError(c->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	switch (opt) {
		case KSI_ASYNC_OPT_REQUEST_CACHE_SIZE: {
				size_t count = KSI_ASYNC_CACHE_START_POS + (size_t)param; /* Cache at pos=0 is reserved. */

				if (c->reqCache != NULL) {
					size_t i;
					if (count < c->options[opt]) {
						res = KSI_INVALID_ARGUMENT;
						goto cleanup;
					}

					if (count > c->options[opt]) {
						tmpCache = KSI_calloc(count, sizeof(KSI_AsyncHandle *));
						if (tmpCache == NULL) {
							res = KSI_OUT_OF_MEMORY;
							goto cleanup;
						}

						for (i = 0; i < c->options[opt]; i++) {
							tmpCache[i] = c->reqCache[i];
						}
						KSI_free(c->reqCache);
						c->reqCache = tmpCache;
						tmpCache = NULL;
					}
				}
				c->options[opt] = count;
			}
			break;

		case KSI_ASYNC_OPT_CON_TIMEOUT:
		case KSI_ASYNC_OPT_RCV_TIMEOUT:
		case KSI_ASYNC_OPT_SND_TIMEOUT:
		case KSI_ASYNC_OPT_MAX_REQUEST_COUNT:
			c->options[opt] = (size_t)param;
			break;

		case KSI_ASYNC_PRIVOPT_ROUND_DURATION:
			c->options[opt] = (size_t)param;
			break;

		default:
			KSI_pushError(c->ctx, res = KSI_INVALID_ARGUMENT, "Unhandled option.");
			goto cleanup;
	}

	res = KSI_OK;
cleanup:

	KSI_free(tmpCache);

	return res;
}

static int asyncClient_getOption(KSI_AsyncClient *c, int opt, void *param) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_ERR_clearErrors(c->ctx);
	if (c == NULL || opt >= __NOF_KSI_ASYNC_OPT || param == NULL) {
		KSI_pushError(c->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	switch (opt) {
		/*** Options with type size_t. ***/
		/* Public options. */
		case KSI_ASYNC_OPT_CON_TIMEOUT:
		case KSI_ASYNC_OPT_RCV_TIMEOUT:
		case KSI_ASYNC_OPT_SND_TIMEOUT:
		case KSI_ASYNC_OPT_MAX_REQUEST_COUNT:
		/* Private options. */
		case KSI_ASYNC_PRIVOPT_ROUND_DURATION:
			*(size_t*)param = c->options[opt];
			break;
		case KSI_ASYNC_OPT_REQUEST_CACHE_SIZE:
			*(size_t*)param = c->options[opt] - KSI_ASYNC_CACHE_START_POS;
			break;

		default:
			KSI_pushError(c->ctx, res = KSI_INVALID_ARGUMENT, "Unhandled option.");
			goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_setDefaultOptions(KSI_AsyncClient *c) {
	int res = KSI_INVALID_ARGUMENT;
	if (c == NULL) goto cleanup;

	/* Public options. */
	if ((res = asyncClient_setOption(c, KSI_ASYNC_OPT_CON_TIMEOUT, (void *)KSI_ASYNC_DEFAULT_TIMEOUT_SEC)) != KSI_OK) goto cleanup;
	if ((res = asyncClient_setOption(c, KSI_ASYNC_OPT_RCV_TIMEOUT, (void *)KSI_ASYNC_DEFAULT_TIMEOUT_SEC)) != KSI_OK) goto cleanup;
	if ((res = asyncClient_setOption(c, KSI_ASYNC_OPT_SND_TIMEOUT, (void *)KSI_ASYNC_DEFAULT_TIMEOUT_SEC)) != KSI_OK) goto cleanup;
	if ((res = asyncClient_setOption(c, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)KSI_ASYNC_DEFAULT_REQUEST_CACHE_SIZE)) != KSI_OK) goto cleanup;
	if ((res = asyncClient_setOption(c, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, (void *)KSI_ASYNC_DEFAULT_ROUND_MAX_COUNT)) != KSI_OK) goto cleanup;
	/* Private options. */
	if ((res = asyncClient_setOption(c, KSI_ASYNC_PRIVOPT_ROUND_DURATION, (void *)KSI_ASYNC_ROUND_DURATION_SEC)) != KSI_OK) goto cleanup;
cleanup:
	return res;
}

void KSI_AsyncClient_free(KSI_AsyncClient *c) {
	if (c != NULL) {
		if (c->clientImpl_free) c->clientImpl_free(c->clientImpl);

		/* Clear cached handles. */
		if (c->reqCache != NULL) {
			size_t i;
			for (i = 0; i < c->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE]; i++) KSI_AsyncHandle_free(c->reqCache[i]);
			KSI_free(c->reqCache);
		}
		KSI_AsyncHandle_free(c->serverConf);

		KSI_free(c);
	}
}

int KSI_AbstractAsyncClient_new(KSI_CTX *ctx, KSI_AsyncClient **c) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncClient *tmp = NULL;

	if (ctx == NULL || c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_malloc(sizeof(KSI_AsyncClient));
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	tmp->ctx = ctx;
	tmp->clientImpl = NULL;
	tmp->clientImpl_free = NULL;

	tmp->requestCountOffset = 0;
	tmp->requestCount = 0;
	tmp->tail = 1;

	tmp->reqCache = NULL;
	tmp->pending = 0;
	tmp->received = 0;
	tmp->serverConf = NULL;

	tmp->addRequest = NULL;
	tmp->getResponse = NULL;
	tmp->dispatch = NULL;
	tmp->getCredentials = NULL;

	tmp->instanceId = time(NULL);
	tmp->messageId = 0;

	res = asyncClient_setDefaultOptions(tmp);
	if (res != KSI_OK) goto cleanup;

	tmp->reqCache = KSI_calloc(tmp->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE], sizeof(KSI_AsyncHandle *));
	if (tmp->reqCache == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	*c = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_AsyncClient_free(tmp);
	return res;
}

int KSI_AsyncService_addRequest(KSI_AsyncService *s, KSI_AsyncHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;

	if (s == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(s->ctx);

	if (s->impl == NULL || s->addRequest == NULL) {
		KSI_pushError(s->ctx, res = KSI_INVALID_STATE, "Async service client is not properly initialized.");
		goto cleanup;
	}

	res = s->addRequest(s->impl, handle);
	if (res != KSI_OK) {
		KSI_pushError(s->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncService_run(KSI_AsyncService *service, KSI_AsyncHandle **handle, size_t *waiting) {
	int res = KSI_UNKNOWN_ERROR;

	if (service == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(service->ctx);

	if (service->impl == NULL || service->run == NULL) {
		KSI_pushError(service->ctx, res = KSI_INVALID_STATE, "Async service client is not properly initialized.");
		goto cleanup;
	}

	res = service->run(service->impl, service->responseHandler, handle, waiting);
	if (res != KSI_OK) {
		KSI_pushError(service->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

void KSI_AsyncService_free(KSI_AsyncService *service) {
	if (service != NULL) {
		if (service->impl_free) service->impl_free(service->impl);
		KSI_free(service);
	}
}

int KSI_SigningAsyncService_new(KSI_CTX *ctx, KSI_AsyncService **service) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncService *tmp = NULL;

	if (ctx == NULL || service == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(ctx);

	res = KSI_AbstractAsyncService_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->addRequest = (int (*)(void *, KSI_AsyncHandle *))asyncClient_addAggregatorRequest;
	tmp->responseHandler = (int (*)(void *))asyncClient_processAggregationResponseQueue;
	tmp->run = (int (*)(void *, int (*)(void *), KSI_AsyncHandle **, size_t *))asyncClient_run;

	tmp->getPendingCount = (int (*)(void *, size_t *))asyncClient_getPendingCount;
	tmp->getReceivedCount = (int (*)(void *, size_t *))asyncClient_getReceivedCount;

	tmp->setOption = (int (*)(void *, int, void *))asyncClient_setOption;
	tmp->getOption = (int (*)(void *, int, void *))asyncClient_getOption;

	*service = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncService_free(tmp);
	return res;
}

int KSI_ExtendingAsyncService_new(KSI_CTX *ctx, KSI_AsyncService **service) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncService *tmp = NULL;

	if (ctx == NULL || service == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(ctx);

	res = KSI_AbstractAsyncService_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->addRequest = (int (*)(void *, KSI_AsyncHandle *))asyncClient_addExtenderRequest;
	tmp->responseHandler = (int (*)(void *))asyncClient_processExtenderResponseQueue;
	tmp->run = (int (*)(void *, int (*)(void *), KSI_AsyncHandle **, size_t *))asyncClient_run;

	tmp->getPendingCount = (int (*)(void *, size_t *))asyncClient_getPendingCount;
	tmp->getReceivedCount = (int (*)(void *, size_t *))asyncClient_getReceivedCount;

	tmp->setOption = (int (*)(void *, int, void *))asyncClient_setOption;
	tmp->getOption = (int (*)(void *, int, void *))asyncClient_getOption;

	*service = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncService_free(tmp);
	return res;
}

int KSI_AsyncService_getPendingCount(KSI_AsyncService *s, size_t *count) {
	if (s == NULL || s->impl == NULL || s->getPendingCount == NULL) return KSI_INVALID_ARGUMENT;
	return s->getPendingCount(s->impl, count);
}

int KSI_AsyncService_getReceivedCount(KSI_AsyncService *s, size_t *count) {
	if (s == NULL || s->impl == NULL || s->getReceivedCount == NULL) return KSI_INVALID_ARGUMENT;
	return s->getReceivedCount(s->impl, count);
}

int KSI_AsyncService_setOption(KSI_AsyncService *s, const KSI_AsyncOption option, void *value) {
	if ((s == NULL || s->impl == NULL || s->setOption == NULL) || option >= __KSI_ASYNC_OPT_COUNT) return KSI_INVALID_ARGUMENT;
	return s->setOption(s->impl, option, value);
}

int KSI_AsyncService_getOption(const KSI_AsyncService *s, const KSI_AsyncOption option, void *value) {
	if ((s == NULL || s->impl == NULL || s->getOption == NULL) || option >= __KSI_ASYNC_OPT_COUNT) return KSI_INVALID_ARGUMENT;
	return s->getOption(s->impl, option, value);
}
