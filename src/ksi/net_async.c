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

#include "net_async.h"

#include <string.h>

#include "internal.h"
#include "net_impl.h"
#include "ctx_impl.h"


void KSI_AsyncHandle_free(KSI_AsyncHandle *o) {
	if (o != NULL && --o->ref == 0) {
		if (o->reqCtx_free) o->reqCtx_free(o->reqCtx);
		if (o->respCtx_free) o->respCtx_free(o->respCtx);
		if (o->userCtx_free) o->userCtx_free(o->userCtx);
		KSI_free(o->raw);
		KSI_Utf8String_free(o->errMsg);

		KSI_free(o);
	}
}

int KSI_AsyncAggregationHandle_new(KSI_CTX *ctx, KSI_AggregationReq *req, KSI_AsyncHandle **o) {
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

	tmp->reqCtx = (void *)req;
	tmp->reqCtx_free = (void (*)(void*))KSI_AggregationReq_free;

	tmp->respCtx = NULL;
	tmp->respCtx_free = NULL;

	tmp->reqTime = 0;
	tmp->sndTime = 0;
	tmp->rcvTime = 0;

	tmp->userCtx = NULL;
	tmp->userCtx_free = NULL;

	tmp->state = KSI_ASYNC_STATE_UNDEFINED;

	tmp->err = KSI_OK;
	tmp->errMsg = NULL;

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncHandle_free(tmp);
	return res;
}

KSI_IMPLEMENT_REF(KSI_AsyncHandle);

KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, int, state, State)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, int, err, Error)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, KSI_Utf8String *, errMsg, ErrorMsg)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, const void *, userCtx, RequestCtx)

int KSI_AsyncHandle_getAggregationResp(const KSI_AsyncHandle *h, KSI_AggregationResp **resp) {
	int res = KSI_UNKNOWN_ERROR;

	if (h == NULL || resp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*resp = (KSI_AggregationResp*)h->respCtx;
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


static int asyncClient_calculateRequestId(KSI_AsyncClient *c, KSI_uint64_t *id) {
	int res = KSI_UNKNOWN_ERROR;
	size_t last = 0;

	if (c == NULL || c->reqCache == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	last = c->requestCount;

	do {
		if ((++c->requestCount % c->maxParallelRequests) == 0) c->requestCount = 1;
		if (c->requestCount == last) {
			res = KSI_ASYNC_MAX_PARALLEL_COUNT_REACHED;
			goto cleanup;
		}
	} while (c->reqCache[c->requestCount] != NULL);

	*id = c->requestCount;
	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_addAggregationRequest(KSI_AsyncClient *c, KSI_AsyncHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationReq *reqRef = NULL;
	KSI_AggregationPdu *pdu = NULL;
	unsigned char *raw = NULL;
	size_t len;
	KSI_AsyncHandle *hndlRef = NULL;
	KSI_Integer *reqId = NULL;
	const char *user = NULL;
	const char *pass = NULL;
	KSI_uint64_t id = 0;
	void *impl = NULL;
	KSI_AggregationReq *aggrReq = NULL;

	if (c == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (handle->reqCtx == NULL ||
			c->clientImpl == NULL || c->addRequest == NULL || c->getCredentials == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}
	impl = c->clientImpl;
	aggrReq = (KSI_AggregationReq*)handle->reqCtx;

	/* Cleanup the handle in case it has been added repeteadly. */
	KSI_free(handle->raw);
	KSI_Utf8String_free(handle->errMsg);
	if (handle->respCtx_free) handle->respCtx_free(handle->respCtx);


	res = KSI_AggregationReq_getRequestId(aggrReq, &reqId);
	if (res != KSI_OK) goto cleanup;

	/* Clear the request id that was set  */
	if (reqId != NULL) {
		KSI_Integer_free(reqId);
		reqId = NULL;
		res = KSI_AggregationReq_setRequestId(aggrReq, reqId);
		if (res != KSI_OK) goto cleanup;
	}

	res = asyncClient_calculateRequestId(c, &id);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(c->ctx, id, &reqId);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AggregationReq_setRequestId(aggrReq, reqId);
	if (res != KSI_OK) goto cleanup;
	reqId = NULL;

	res = c->getCredentials(impl, &user, &pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AggregationReq_enclose((reqRef = KSI_AggregationReq_ref(aggrReq)), user, pass, &pdu);
	if (res != KSI_OK) {
		KSI_AggregationReq_free(reqRef);
		goto cleanup;
	}

	res = KSI_AggregationPdu_serialize(pdu, &raw, &len);
	if (res != KSI_OK) goto cleanup;

	handle->id = id;
	handle->raw = raw;
	raw = NULL;
	handle->len = len;

	/* Add request to the impl output queue. The query might fail if the queue is full. */
	res = c->addRequest(impl, (hndlRef = KSI_AsyncHandle_ref(handle)));
	if (res != KSI_OK) {
		KSI_AsyncHandle_free(hndlRef);
		goto cleanup;
	}

	/* Set into local cache. */
	c->reqCache[id] = handle;
	c->pending++;

	res = KSI_OK;
cleanup:
	KSI_free(raw);
	KSI_Integer_free(reqId);
	KSI_AggregationPdu_free(pdu);

	return res;
}

static int asyncClient_processAggregationResponse(KSI_AsyncClient *c) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ErrorPdu *error = NULL;
	KSI_Header *header = NULL;
	KSI_DataHash *respHmac = NULL;
	const char *pass = NULL;
	KSI_OctetString *resp = NULL;
	const unsigned char *raw = NULL;
	size_t len = 0;
	KSI_AggregationPdu *pdu = NULL;
	KSI_Config *tmpConf = NULL;
	void *impl = NULL;
	size_t left = 0;

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
		KSI_AggregationPdu_free(pdu);
		pdu = NULL;

		res = c->getResponse(impl, &resp, &left);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
		}

		if (resp != NULL) {
			KSI_Integer *reqId = NULL;
			KSI_AsyncHandle *handle = NULL;
			KSI_AggregationResp *aggrResp = NULL;

			res = KSI_OctetString_extract(resp, &raw, &len);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			KSI_LOG_logBlob(c->ctx, KSI_LOG_DEBUG, "Parsing aggregation response", raw, len);

			/* Get PDU object. */
			res = KSI_AggregationPdu_parse(c->ctx, raw, len, &pdu);
			if(res != KSI_OK){
				KSI_pushError(c->ctx, res, "Unable to parse aggregation pdu.");
				goto cleanup;
			}

			res = KSI_AggregationPdu_getError(pdu, &error);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			if (error != NULL) {
				KSI_Utf8String *errorMsg = NULL;
				KSI_Integer *status = NULL;
				KSI_ErrorPdu_getErrorMessage(error, &errorMsg);
				KSI_ErrorPdu_getStatus(error, &status);
				KSI_ERR_push(c->ctx, res = KSI_convertAggregatorStatusCode(status), (long)KSI_Integer_getUInt64(status), __FILE__, __LINE__, KSI_Utf8String_cstr(errorMsg));
				goto cleanup;
			}

			res = KSI_AggregationPdu_getHeader(pdu, &header);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}
			if (header == NULL){
				KSI_pushError(c->ctx, res = KSI_INVALID_FORMAT, "A successful aggregation response must have a Header.");
				goto cleanup;
			}

			res = KSI_AggregationPdu_getHmac(pdu, &respHmac);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}
			if (respHmac == NULL){
				KSI_pushError(c->ctx, res = KSI_INVALID_FORMAT, "A successful aggregation response must have a HMAC.");
				goto cleanup;
			}

			res = c->getCredentials(impl, NULL, &pass);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			res = KSI_AggregationPdu_verifyHmac(pdu, pass);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			res = KSI_AggregationPdu_getConfResponse(pdu, &tmpConf);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			/* The push config is handled only via callback. */
			if (tmpConf != NULL) {
				KSI_Config_Callback confCallback = (KSI_Config_Callback)(c->ctx->options[KSI_OPT_AGGR_CONF_RECEIVED_CALLBACK]);
				/* It is push conf which was not explicitly requested. Invoke the user conf receive callback. */
				if (confCallback != NULL) {
					res = confCallback(c->ctx, tmpConf);
					if (res != KSI_OK) {
						KSI_pushError(c->ctx, res, NULL);
						goto cleanup;
					}
				}
			}

			/*Get response object*/
			res = KSI_AggregationPdu_getResponse(pdu, &aggrResp);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			if (aggrResp == NULL) continue;

			res = KSI_AggregationResp_getRequestId(aggrResp, &reqId);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res , NULL);
				goto cleanup;
			}

			if (c->maxParallelRequests <= KSI_Integer_getUInt64(reqId) || c->reqCache[KSI_Integer_getUInt64(reqId)] == NULL) {
				KSI_LOG_warn(c->ctx, "Unexpected async aggregation response received.");
				continue;
			}
			handle = c->reqCache[KSI_Integer_getUInt64(reqId)];

			if (handle->state == KSI_ASYNC_STATE_WAITING_FOR_RESPONSE) {
				KSI_Integer *status = NULL;

				/* Verify response status. */
				res = KSI_AggregationResp_getStatus(aggrResp, &status);
				if (res != KSI_OK) {
					KSI_pushError(c->ctx, res, NULL);
					goto cleanup;
				}

				res = KSI_convertAggregatorStatusCode(status);
				if (res != KSI_OK) {
					KSI_Utf8String *errorMessage = NULL;

					KSI_AggregationResp_getErrorMsg(aggrResp, &errorMessage);
					KSI_LOG_error(c->ctx, "Async aggregation failed: [%x] %s", KSI_Integer_getUInt64(status), KSI_Utf8String_cstr(errorMessage));

					handle->state = KSI_ASYNC_STATE_ERROR;
					handle->err = res;
					handle->errMsg = KSI_Utf8String_ref(errorMessage);
					continue;
				}

				handle->respCtx = (void*)aggrResp;
				handle->respCtx_free = (void (*)(void*))KSI_AggregationResp_free;

				res = KSI_AggregationPdu_setResponse(pdu, NULL);
				if (res != KSI_OK) {
					KSI_pushError(c->ctx, res, NULL);
					goto cleanup;
				}

				handle->state = KSI_ASYNC_STATE_RESPONSE_RECEIVED;
				c->pending--;
				c->received++;
			}
		}
	} while (left != 0);

cleanup:
	KSI_Config_free(tmpConf);
	KSI_OctetString_free(resp);
	KSI_AggregationPdu_free(pdu);

	return res;
}

int asyncClient_findNextResponse(KSI_AsyncClient *c, KSI_AsyncHandle **handle) {
	int res;
	size_t last;

	if (c == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (c->reqCache == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	if ((c->pending + c->received) == 0) {
		*handle = NULL;
		res = KSI_OK;
		goto cleanup;
	}

	last = c->tail;
	for (;;) {
		if (c->reqCache[c->tail] != NULL) {
			switch (c->reqCache[c->tail]->state) {
				case KSI_ASYNC_STATE_WAITING_FOR_RESPONSE:
					if (c->rTimeout == 0 || difftime(time(NULL), c->reqCache[c->tail]->sndTime) > c->rTimeout) {
						c->reqCache[c->tail]->state = KSI_ASYNC_STATE_ERROR;
						c->reqCache[c->tail]->err = KSI_NETWORK_RECIEVE_TIMEOUT;
						*handle = c->reqCache[c->tail];
						c->reqCache[c->tail] = NULL;
						c->pending--;
						res = KSI_OK;
						goto cleanup;
					}
					break;
				case KSI_ASYNC_STATE_ERROR:
					*handle = c->reqCache[c->tail];
					c->reqCache[c->tail] = NULL;
					c->pending--;
					res = KSI_OK;
					goto cleanup;
				case KSI_ASYNC_STATE_RESPONSE_RECEIVED:
					*handle = c->reqCache[c->tail];
					c->reqCache[c->tail] = NULL;
					c->received--;
					res = KSI_OK;
					goto cleanup;
				default:
					/* do nothing. */
					break;
			}
		}
		if ((++c->tail % c->maxParallelRequests) == 0) c->tail = 1;
		if (c->tail == last) break;
	}
	*handle = NULL;
	res = KSI_OK;
cleanup:
	return res;
}

int asyncClient_run(KSI_AsyncClient *c, int (*handleResp)(KSI_AsyncClient *), KSI_AsyncHandle **handle, size_t *waiting) {
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

	res = c->dispatch(c->clientImpl);
	if (res == KSI_ASYNC_CONNECTION_CLOSED) {
		connClosed = true;
	} else if (res != KSI_OK) {
		KSI_pushError(c->ctx, res, NULL);
		goto cleanup;
	}

	/* Handle responses. */
	res = handleResp(c);
	if (res != KSI_OK) {
		KSI_pushError(c->ctx, res, NULL);
		goto cleanup;
	}

	/* Update request state if connection has been closed remotely. */
	if (connClosed) {
		size_t i;
		for (i = 1; i < c->maxParallelRequests; i++) {
			if (c->reqCache[i] != NULL && c->reqCache[i]->state == KSI_ASYNC_STATE_WAITING_FOR_RESPONSE) {
				c->reqCache[i]->state = KSI_ASYNC_STATE_ERROR;
				c->reqCache[i]->err = KSI_ASYNC_CONNECTION_CLOSED;
			}
		}
	}

	if (handle != NULL) {
		res = asyncClient_findNextResponse(c, handle);
		if (res != KSI_OK)  {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
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

int asyncClient_getReceivedCount(KSI_AsyncClient *c, size_t *count) {
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

static int asyncClient_setConnectTimeout(KSI_AsyncClient *c, size_t timeout) {
	if (c == NULL || c->clientImpl == NULL || c->setConnectTimeout == NULL) return KSI_INVALID_ARGUMENT;
	return c->setConnectTimeout(c->clientImpl, timeout);
}

static int asyncClient_setSendTimeout(KSI_AsyncClient *c, size_t timeout) {
	if (c == NULL || c->clientImpl == NULL || c->setSendTimeout == NULL) return KSI_INVALID_ARGUMENT;
	return c->setSendTimeout(c->clientImpl, timeout);
}

static int asyncClient_setReceiveTimeout(KSI_AsyncClient *c, size_t timeout) {
	if (c == NULL) return KSI_INVALID_ARGUMENT;
	c->rTimeout = timeout;
	return KSI_OK;
}

static int asyncClient_setMaxRequestCount(KSI_AsyncClient *c, size_t count) {
	if (c == NULL || c->clientImpl == NULL || c->setMaxRequestCount == NULL) return KSI_INVALID_ARGUMENT;
	return c->setMaxRequestCount(c->clientImpl, count);
}

void KSI_AsyncClient_free(KSI_AsyncClient *c) {
	if (c != NULL) {
		size_t i;

		if (c->clientImpl_free) c->clientImpl_free(c->clientImpl);

		for (i = 0; i < c->maxParallelRequests; i++) KSI_AsyncHandle_free(c->reqCache[i]);
		KSI_free(c->reqCache);

		KSI_free(c);
	}
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

	res = KSI_AsyncService_construct(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->addRequest = (int (*)(void *, KSI_AsyncHandle *))asyncClient_addAggregationRequest;
	tmp->responseHandler = (int (*)(void *))asyncClient_processAggregationResponse;
	tmp->run = (int (*)(void *, int (*)(void *), KSI_AsyncHandle **, size_t *))asyncClient_run;
	tmp->getPendingCount = (int (*)(void *, size_t *))asyncClient_getPendingCount;
	tmp->getReceivedCount = (int (*)(void *, size_t *))asyncClient_getReceivedCount;
	tmp->setConnectTimeout = (int (*)(void *, size_t))asyncClient_setConnectTimeout;
	tmp->setSendTimeout = (int (*)(void *, size_t))asyncClient_setSendTimeout;
	tmp->setReceiveTimeout = (int (*)(void *, size_t))asyncClient_setReceiveTimeout;
	tmp->setMaxRequestCount = (int (*)(void *, size_t))asyncClient_setMaxRequestCount;

	*service = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncService_free(tmp);
	return res;
}

int KSI_AsyncService_setMaxParallelRequests(KSI_AsyncService *service, size_t count){
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncHandle **tmp = NULL;
	KSI_AsyncClient *client = NULL;
	size_t i;

	if (service == NULL || service->impl == NULL || (client = service->impl)->maxParallelRequests > count) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_calloc(count, sizeof(KSI_AsyncHandle *));
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	for (i = 0; i < client->maxParallelRequests; i++) {
		tmp[i] = client->reqCache[i];
	}
	KSI_free(client->reqCache);
	client->reqCache = tmp;
	tmp = NULL;
	client->maxParallelRequests = count;

	res = KSI_OK;
cleanup:
	return res;
}

#define KSI_ASYNC_SERVICE_OBJ_IMPLEMENT_SETTER(obj, name, type)	\
int obj##_set##name(obj *s, type val) {							\
	int res = KSI_UNKNOWN_ERROR;								\
	if (s == NULL || s->impl == NULL || s->set##name == NULL) {	\
		res = KSI_INVALID_ARGUMENT;								\
		goto cleanup;											\
	}															\
	res = s->set##name(s->impl, val);							\
cleanup:														\
	return res;													\
}

KSI_ASYNC_SERVICE_OBJ_IMPLEMENT_SETTER(KSI_AsyncService, ConnectTimeout, const size_t)
KSI_ASYNC_SERVICE_OBJ_IMPLEMENT_SETTER(KSI_AsyncService, ReceiveTimeout, const size_t)
KSI_ASYNC_SERVICE_OBJ_IMPLEMENT_SETTER(KSI_AsyncService, SendTimeout, const size_t)
KSI_ASYNC_SERVICE_OBJ_IMPLEMENT_SETTER(KSI_AsyncService, MaxRequestCount, const size_t)

#define KSI_ASYNC_SERVICE_OBJ_IMPLEMENT_GETTER(obj, name, type)	\
int obj##_get##name(obj *s, type val) {							\
	int res = KSI_UNKNOWN_ERROR;								\
	if (s == NULL || s->impl == NULL || s->get##name == NULL) {	\
		res = KSI_INVALID_ARGUMENT;								\
		goto cleanup;											\
	}															\
	res = s->get##name(s->impl, val);							\
cleanup:														\
	return res;													\
}

KSI_ASYNC_SERVICE_OBJ_IMPLEMENT_GETTER(KSI_AsyncService, PendingCount, size_t*)
KSI_ASYNC_SERVICE_OBJ_IMPLEMENT_GETTER(KSI_AsyncService, ReceivedCount, size_t*)

