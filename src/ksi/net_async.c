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


void KSI_AsyncPayload_free(KSI_AsyncPayload *o) {
	if (o != NULL && --o->ref == 0) {
		if (o->pldCtx_free) o->pldCtx_free(o->pldCtx);
		if (o->reqCtx_free) o->reqCtx_free(o->reqCtx);
		KSI_free(o->raw);
		KSI_free(o);
	}
}

int KSI_AsyncPayload_new(KSI_CTX *ctx, const unsigned char *payload, const size_t payload_len, KSI_AsyncPayload **o) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncPayload *tmp = NULL;

	if (ctx == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_malloc(sizeof(KSI_AsyncPayload));
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;

	tmp->id = 0;
	tmp->raw = NULL;
	tmp->len = 0;
	tmp->pldCtx = NULL;
	tmp->pldCtx_free = NULL;
	tmp->reqTime = 0;
	tmp->sndTime = 0;

	tmp->reqCtx = NULL;
	tmp->reqCtx_free = NULL;

	tmp->state = KSI_ASYNC_REQ_UNDEFINED;
	tmp->error = KSI_OK;

	if (payload_len > 0) {
		tmp->raw = KSI_malloc(payload_len);
		if (tmp->raw == NULL) {
			KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		memcpy(tmp->raw, payload, payload_len);
		tmp->len = payload_len;
	}

	*o = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncPayload_free(tmp);
	return res;
}

KSI_IMPLEMENT_REF(KSI_AsyncPayload);
KSI_IMPLEMENT_SETTER(KSI_AsyncPayload, KSI_AsyncHandle, id, PayloadId);

int KSI_AsyncPayload_setPayloadCtx(KSI_AsyncPayload *o, void *pldCtx, void (*pldCtx_free)(void*)) {
	int res = KSI_UNKNOWN_ERROR;

	if (o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (o->pldCtx_free) o->pldCtx_free(o->pldCtx);

	o->pldCtx = pldCtx;
	o->pldCtx_free = pldCtx_free;

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncPayload_setRequestCtx(KSI_AsyncPayload *o, void *reqCtx, void (*reqCtx_free)(void*)) {
	int res = KSI_UNKNOWN_ERROR;

	if (o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (o->reqCtx_free) o->reqCtx_free(o->reqCtx);

	o->reqCtx = reqCtx;
	o->reqCtx_free = reqCtx_free;

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncPayload_getRequestCtx(KSI_AsyncPayload *o, void **reqCtx) {
	int res = KSI_UNKNOWN_ERROR;

	if (o == NULL || reqCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	*reqCtx = o->reqCtx;
	res = KSI_OK;
cleanup:
	return res;
}

static int calculateRequestId(KSI_AsyncClient *c, KSI_uint64_t *id) {
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

static int asyncClient_addAggregationRequest(KSI_AsyncClient *c, KSI_AsyncRequest *req, KSI_AsyncHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationReq *reqRef = NULL;
	KSI_AggregationPdu *pdu = NULL;
	unsigned char *raw = NULL;
	size_t len;
	KSI_AsyncPayload *tmp = NULL;
	KSI_AsyncPayload *pldRef = NULL;
	KSI_Integer *reqId = NULL;
	const char *user = NULL;
	const char *pass = NULL;
	KSI_uint64_t id = 0;
	void *impl = NULL;

	if (c == NULL || req == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (req->aggregationReq == NULL || req->extendReq != NULL ||
			c->clientImpl == NULL || c->addRequest == NULL || c->getCredentials == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}
	impl = c->clientImpl;

	res = KSI_AggregationReq_getRequestId(req->aggregationReq, &reqId);
	if (res != KSI_OK) goto cleanup;

	/* Clear the request id that was set  */
	if (reqId != NULL) {
		KSI_Integer_free(reqId);
		reqId = NULL;

		res = KSI_AggregationReq_setRequestId(req->aggregationReq, reqId);
		if (res != KSI_OK) goto cleanup;
	}

	res = calculateRequestId(c, &id);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(c->ctx, id, &reqId);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AggregationReq_setRequestId(req->aggregationReq, reqId);
	if (res != KSI_OK) goto cleanup;
	reqId = NULL;

	res = c->getCredentials(impl, &user, &pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AggregationReq_enclose((reqRef = KSI_AggregationReq_ref(req->aggregationReq)), user, pass, &pdu);
	if (res != KSI_OK) {
		KSI_AggregationReq_free(reqRef);
		goto cleanup;
	}

	res = KSI_AggregationPdu_serialize(pdu, &raw, &len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AsyncPayload_new(c->ctx, raw, len, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_AsyncPayload_setPayloadId(tmp, id);
	if (res != KSI_OK) goto cleanup;

	/* Add request to the impl output queue. The query might fail if the queue is full. */
	res = c->addRequest(impl, (pldRef = KSI_AsyncPayload_ref(tmp)));
	if (res != KSI_OK) {
		KSI_AsyncPayload_free(pldRef);
		goto cleanup;
	}

	/* Set payload related contexts. */
	KSI_AsyncPayload_setPayloadCtx(tmp, req->aggregationReq, (void (*)(void*))KSI_AggregationReq_free);
	req->aggregationReq = NULL;
	KSI_AsyncPayload_setRequestCtx(tmp, req->reqCtx, req->reqCtx_free);
	req->reqCtx = NULL;
	req->reqCtx_free = NULL;

	/* Release the request object. */
	KSI_AsyncRequest_free(req);

	/* Set into local cache. */
	c->reqCache[id] = tmp;
	tmp = NULL;
	c->pending++;

	*handle = id;

	res = KSI_OK;
cleanup:
	KSI_free(raw);
	KSI_Integer_free(reqId);
	KSI_AggregationPdu_free(pdu);
	KSI_AsyncPayload_free(tmp);

	return res;
}

static int asyncClient_handleAggregationResponse(KSI_AsyncClient *c) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncResponse *tmp = NULL;
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
		/* Leftovers from previous cycle. */
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
			KSI_AsyncPayload *pld = NULL;
			KSI_AggregationResp *aggrResp = NULL;

			res = KSI_OctetString_extract(resp, &raw, &len);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}

			KSI_LOG_logBlob(c->ctx, KSI_LOG_DEBUG, "Parsing aggregation response:", raw, len);

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
				KSI_LOG_warn(c->ctx, "Unexpected async aggregator response received.");
				continue;
			}
			pld = c->reqCache[KSI_Integer_getUInt64(reqId)];

			if (pld->state == KSI_ASYNC_REQ_WAITING_FOR_RESPONSE) {
				res = KSI_AsyncResponse_new(c->ctx, &tmp);
				if (res != KSI_OK) {
					KSI_pushError(c->ctx, res, NULL);
					goto cleanup;
				}

				res = KSI_AsyncResponse_setAggregationResp(tmp, aggrResp);
				if (res != KSI_OK) {
					KSI_pushError(c->ctx, res, NULL);
					goto cleanup;
				}

				res = KSI_AggregationPdu_setResponse(pdu, NULL);
				if (res != KSI_OK) {
					KSI_pushError(c->ctx, res, NULL);
					goto cleanup;
				}

				res = KSI_AsyncPayload_setPayloadCtx(pld, (void*)tmp, (void (*)(void*))KSI_AsyncResponse_free);
				if (res != KSI_OK) {
					KSI_pushError(c->ctx, res, NULL);
					goto cleanup;
				}
				pld->state = KSI_ASYNC_REQ_RESPONSE_RECEIVED;
				tmp = NULL;
				c->pending--;
				c->received++;
			}
		}
	} while (left != 0);

cleanup:
	KSI_AsyncResponse_free(tmp);
	KSI_Config_free(tmpConf);
	KSI_OctetString_free(resp);
	KSI_AggregationPdu_free(pdu);

	return res;
}

static int asyncClient_getResponse(KSI_AsyncClient *c, KSI_AsyncHandle handle, KSI_AsyncResponse **response) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncResponse *tmp = NULL;

	if (c == NULL || response == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (handle >= c->maxParallelRequests || c->reqCache == NULL || c->reqCache[handle] == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	switch (c->reqCache[handle]->state) {
		case KSI_ASYNC_REQ_RESPONSE_RECEIVED:
			/* Get async response from the cache payload context. The context is set in response handler. */
			tmp = c->reqCache[handle]->pldCtx;
			c->reqCache[handle]->pldCtx = NULL;
			c->reqCache[handle]->pldCtx_free = NULL;

			if (tmp == NULL) {
				res = KSI_INVALID_STATE;
				goto cleanup;
			}

			/* Update async response request context. */
			KSI_AsyncResponse_setRequestContext(tmp, c->reqCache[handle]->reqCtx, c->reqCache[handle]->reqCtx_free);
			c->reqCache[handle]->reqCtx = NULL;
			c->reqCache[handle]->reqCtx_free = NULL;

			/* Remove the payload object from the cache. */
			KSI_AsyncPayload_free(c->reqCache[handle]);
			c->reqCache[handle] = NULL;

			c->received--;
			break;

		case KSI_ASYNC_REQ_WAITING_FOR_RESPONSE:
			tmp = NULL;
			/* Check if the response is overdue. */
			if (c->rTimeout == 0 || difftime(time(NULL), c->reqCache[handle]->sndTime) > c->rTimeout) {
				/* Just update the error state. */
				c->reqCache[c->tail]->state = KSI_ASYNC_REQ_ERROR;
				c->reqCache[c->tail]->error = KSI_NETWORK_RECIEVE_TIMEOUT;
				res = KSI_OK;
				goto cleanup;
			}
			break;

		default:
			tmp = NULL;
			break;
	}

	*response = tmp;
	res = KSI_OK;
cleanup:
	return res;
}

int asyncClient_findNextResponse(KSI_AsyncClient *c, KSI_AsyncHandle *handle) {
	int res;
	size_t last;

	if (c == NULL || c->reqCache == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	if ((c->pending + c->received) == 0) {
		*handle = KSI_ASYNC_HANDLE_NULL;
		res = KSI_OK;
		goto cleanup;
	}

	last = c->tail;
	for (;;) {
		if (c->reqCache[c->tail] != NULL) {
			switch (c->reqCache[c->tail]->state) {
				case KSI_ASYNC_REQ_WAITING_FOR_RESPONSE:
					if (c->rTimeout == 0 || difftime(time(NULL), c->reqCache[c->tail]->sndTime) > c->rTimeout) {
						*handle = c->reqCache[c->tail]->id;
						c->reqCache[c->tail]->state = KSI_ASYNC_REQ_ERROR;
						c->reqCache[c->tail]->error = KSI_NETWORK_RECIEVE_TIMEOUT;
						res = KSI_OK;
						goto cleanup;
					}
					break;

				case KSI_ASYNC_REQ_ERROR:
				case KSI_ASYNC_REQ_RESPONSE_RECEIVED:
					*handle = c->reqCache[c->tail]->id;
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
	*handle = KSI_ASYNC_HANDLE_NULL;
	res = KSI_OK;
cleanup:
	return res;
}

int asyncClient_run(KSI_AsyncClient *c, int (*handleResp)(KSI_AsyncClient *), KSI_AsyncHandle *handle, size_t *waiting) {
	int res = KSI_UNKNOWN_ERROR;
	bool connClosed = false;

	if (c == NULL) {
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
			if (c->reqCache[i] != NULL && c->reqCache[i]->state == KSI_ASYNC_REQ_WAITING_FOR_RESPONSE) {
				c->reqCache[c->tail]->state = KSI_ASYNC_REQ_ERROR;
				c->reqCache[c->tail]->error = KSI_ASYNC_CONNECTION_CLOSED;
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

static int asyncClient_getState(KSI_AsyncClient *c, KSI_AsyncHandle h, int *state) {
	int res = KSI_UNKNOWN_ERROR;

	if (c == NULL || state == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (h >= c->maxParallelRequests || c->reqCache == NULL || c->reqCache[h] == NULL)  {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	*state = c->reqCache[h]->state;

	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_getError(KSI_AsyncClient *c, KSI_AsyncHandle h, int *error) {
	int res = KSI_UNKNOWN_ERROR;

	if (c == NULL || error == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (h >= c->maxParallelRequests || c->reqCache == NULL || c->reqCache[h] == NULL)  {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	*error = c->reqCache[h]->error;

	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_getReqCtx(KSI_AsyncClient *c, KSI_AsyncHandle h, void **reqCtx) {
	int res = KSI_UNKNOWN_ERROR;

	if (c == NULL || reqCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (h >= c->maxParallelRequests || c->reqCache == NULL || c->reqCache[h] == NULL)  {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	res = KSI_AsyncPayload_getRequestCtx(c->reqCache[h], reqCtx);
cleanup:
	return res;
}

static int asyncClient_setReqCtx(KSI_AsyncClient *c, KSI_AsyncHandle h, void *reqCtx, void (*reqCtx_free)(void*)) {
	int res = KSI_UNKNOWN_ERROR;

	if (c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (h >= c->maxParallelRequests || c->reqCache == NULL || c->reqCache[h] == NULL)  {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	res = KSI_AsyncPayload_setRequestCtx(c->reqCache[h], reqCtx, reqCtx_free);
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

static int asyncClient_recover(KSI_AsyncClient *c, KSI_AsyncHandle h, int policy) {
	int res = KSI_UNKNOWN_ERROR;
	int state;

	if (c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(c->ctx);

	if (c->clientImpl == NULL || c->dispatch == NULL) {
		KSI_pushError(c->ctx, res = KSI_INVALID_STATE, "Async client is not properly initialized.");
		goto cleanup;
	}

	res = asyncClient_getState(c, h, &state);
	if (res != KSI_OK)  {
		KSI_pushError(c->ctx, res, NULL);
		goto cleanup;
	}

	if (state != KSI_ASYNC_REQ_ERROR) {
		KSI_pushError(c->ctx, res = KSI_INVALID_STATE, "Payload can not be recovered.");
		goto cleanup;
	}

	switch (policy) {
		case KSI_ASYNC_REC_DROP:
			KSI_AsyncPayload_free(c->reqCache[h]);
			c->reqCache[h] = NULL;
			c->pending--;
			break;

		case KSI_ASYNC_REC_RESEND:
			c->reqCache[h]->state = KSI_ASYNC_REQ_WAITING_FOR_DISPATCH;
			res = c->addRequest(c->clientImpl, c->reqCache[h]);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}
			break;

		default:
			KSI_pushError(c->ctx, res = KSI_INVALID_ARGUMENT, "Invalid recovery policy.");
			goto cleanup;
	}

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

		for (i = 0; i < c->maxParallelRequests; i++) KSI_AsyncPayload_free(c->reqCache[i]);
		KSI_free(c->reqCache);

		KSI_free(c);
	}
}

int KSI_AsyncService_addRequest(KSI_AsyncService *s, KSI_AsyncRequest *req, KSI_AsyncHandle *handle) {
	int res = KSI_UNKNOWN_ERROR;

	if (s == NULL || req == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(s->ctx);

	if (s->impl == NULL || s->addRequest == NULL) {
		KSI_pushError(s->ctx, res = KSI_INVALID_STATE, "Async service client is not properly initialized.");
		goto cleanup;
	}

	res = s->addRequest(s->impl, req, handle);
	if (res != KSI_OK) {
		KSI_pushError(s->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncService_getResponse(KSI_AsyncService *s, KSI_AsyncHandle handle, KSI_AsyncResponse **resp) {
	int res = KSI_UNKNOWN_ERROR;

	if (s == NULL || resp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(s->ctx);

	if (s->impl == NULL || s->getResponse == NULL) {
		KSI_pushError(s->ctx, res = KSI_INVALID_STATE, "Async service client is not properly initialized.");
		goto cleanup;
	}

	res = s->getResponse(s->impl, handle, resp);
	if (res != KSI_OK) {
		KSI_pushError(s->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AsyncService_run(KSI_AsyncService *service, KSI_AsyncHandle *handle, size_t *waiting) {
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

int KSI_AsyncService_recover(KSI_AsyncService *service, KSI_AsyncHandle handle, int policy) {
	int res = KSI_UNKNOWN_ERROR;

	if (service == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(service->ctx);

	if (service->impl == NULL || service->recover == NULL) {
		KSI_pushError(service->ctx, res = KSI_INVALID_STATE, "Async service client is not properly initialized.");
		goto cleanup;
	}

	res = service->recover(service->impl, handle, policy);
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

	tmp->addRequest = (int (*)(void *, KSI_AsyncRequest *, KSI_AsyncHandle *))asyncClient_addAggregationRequest;
	tmp->getResponse = (int (*)(void *, KSI_AsyncHandle, KSI_AsyncResponse **))asyncClient_getResponse;
	tmp->responseHandler = (int (*)(void *))asyncClient_handleAggregationResponse;

	tmp->run = (int (*)(void *, int (*)(void *), KSI_AsyncHandle *, size_t *))asyncClient_run;
	tmp->recover = (int (*)(void *, KSI_AsyncHandle, int))asyncClient_recover;

	tmp->getRequestState = (int (*)(void *, KSI_AsyncHandle, int *))asyncClient_getState;
	tmp->getRequestError = (int (*)(void *, KSI_AsyncHandle, int *))asyncClient_getError;
	tmp->getRequestContext = (int (*)(void *, KSI_AsyncHandle, void **))asyncClient_getReqCtx;
	tmp->getPendingCount = (int (*)(void *, size_t *))asyncClient_getPendingCount;
	tmp->getReceivedCount = (int (*)(void *, size_t *))asyncClient_getReceivedCount;

	tmp->setConnectTimeout = (int (*)(void *, size_t))asyncClient_setConnectTimeout;
	tmp->setSendTimeout = (int (*)(void *, size_t))asyncClient_setSendTimeout;
	tmp->setReceiveTimeout = (int (*)(void *, size_t))asyncClient_setReceiveTimeout;
	tmp->setMaxRequestCount = (int (*)(void *, size_t))asyncClient_setMaxRequestCount;
	tmp->setRequestContext = (int (*)(void *, KSI_AsyncHandle, void *, void (*)(void*)))asyncClient_setReqCtx;

	*service = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncService_free(tmp);
	return res;
}

int KSI_AsyncService_setMaxParallelRequests(KSI_AsyncService *service, size_t count){
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncPayload **tmp = NULL;
	KSI_AsyncClient *client = NULL;
	size_t i;

	if (service == NULL || service->impl == NULL || (client = service->impl)->maxParallelRequests > count) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_calloc(count, sizeof(KSI_AsyncPayload *));
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

int KSI_AsyncService_setRequestContext(KSI_AsyncService *s, KSI_AsyncHandle h, void *ctx, void (*ctx_free)(void*)) {
	int res = KSI_UNKNOWN_ERROR;
	if (s == NULL || s->impl == NULL || s->setRequestContext == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	res = s->setRequestContext(s->impl, h, ctx, ctx_free);
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


#define KSI_ASYNC_SERVICE_OBJ_HANDLE_IMPLEMENT_GETTER(obj, name, type)	\
int obj##_get##name(obj *s, KSI_AsyncHandle h, type val) {		\
	int res = KSI_UNKNOWN_ERROR;								\
	if (s == NULL || s->impl == NULL || s->get##name == NULL) {	\
		res = KSI_INVALID_ARGUMENT;								\
		goto cleanup;											\
	}															\
	res = s->get##name(s->impl, h, val);						\
cleanup:														\
	return res;													\
}

KSI_ASYNC_SERVICE_OBJ_HANDLE_IMPLEMENT_GETTER(KSI_AsyncService, RequestState, int*)
KSI_ASYNC_SERVICE_OBJ_HANDLE_IMPLEMENT_GETTER(KSI_AsyncService, RequestError, int*)
KSI_ASYNC_SERVICE_OBJ_HANDLE_IMPLEMENT_GETTER(KSI_AsyncService, RequestContext, void**)

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


void KSI_AsyncRequest_free(KSI_AsyncRequest *ar) {
	if (ar != NULL) {
		if (ar->reqCtx_free) ar->reqCtx_free(ar->reqCtx);
		KSI_AggregationReq_free(ar->aggregationReq);
		KSI_ExtendReq_free(ar->extendReq);
		KSI_free(ar);
	}
}

int KSI_AsyncRequest_new(KSI_CTX *ctx, KSI_AsyncRequest **ar) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncRequest *tmp = NULL;

	if (ctx == NULL || ar == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(ctx);

	tmp = KSI_malloc(sizeof(KSI_AsyncRequest));
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;

	tmp->aggregationReq = NULL;
	tmp->extendReq = NULL;

	tmp->reqCtx = NULL;
	tmp->reqCtx_free = NULL;

	*ar = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncRequest_free(tmp);
	return res;
}

KSI_IMPLEMENT_SETTER(KSI_AsyncRequest, KSI_AggregationReq *, aggregationReq, AggregationReq);
KSI_IMPLEMENT_SETTER(KSI_AsyncRequest, KSI_ExtendReq *, extendReq, ExtendReq);

int KSI_AsyncRequest_setRequestContext(KSI_AsyncRequest *ar, void *reqCtx, void (*reqCtx_free)(void*)) {
	int res = KSI_UNKNOWN_ERROR;

	if (ar == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (ar->reqCtx_free) ar->reqCtx_free(ar->reqCtx);

	ar->reqCtx = reqCtx;
	ar->reqCtx_free = reqCtx_free;

	res = KSI_OK;
cleanup:
	return res;
}

void KSI_AsyncResponse_free(KSI_AsyncResponse *ar) {
	if (ar != NULL) {
		if (ar->reqCtx_free) ar->reqCtx_free(ar->reqCtx);
		KSI_AggregationResp_free(ar->aggregationResp);
		KSI_ExtendResp_free(ar->extendResp);
		KSI_free(ar);
	}
}

int KSI_AsyncResponse_new(KSI_CTX *ctx, KSI_AsyncResponse **ar) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncResponse *tmp = NULL;

	if (ctx == NULL || ar == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(ctx);

	tmp = KSI_malloc(sizeof(KSI_AsyncResponse));
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;

	tmp->aggregationResp = NULL;
	tmp->extendResp = NULL;

	tmp->reqCtx = NULL;
	tmp->reqCtx_free = NULL;

	*ar = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncResponse_free(tmp);
	return res;
}


KSI_IMPLEMENT_GETTER(KSI_AsyncResponse, KSI_AggregationResp *, aggregationResp, AggregationResp);
KSI_IMPLEMENT_GETTER(KSI_AsyncResponse, KSI_ExtendResp *, extendResp, ExtendResp);
KSI_IMPLEMENT_GETTER(KSI_AsyncResponse, void *, reqCtx, RequestContext);

KSI_IMPLEMENT_SETTER(KSI_AsyncResponse, KSI_AggregationResp *, aggregationResp, AggregationResp);
KSI_IMPLEMENT_SETTER(KSI_AsyncResponse, KSI_ExtendResp *, extendResp, ExtendResp);

int KSI_AsyncResponse_setRequestContext(KSI_AsyncResponse *ar, void *reqCtx, void (*reqCtx_free)(void*)) {
	int res = KSI_UNKNOWN_ERROR;

	if (ar == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (ar->reqCtx_free) ar->reqCtx_free(ar->reqCtx);

	ar->reqCtx = reqCtx;
	ar->reqCtx_free = reqCtx_free;

	res = KSI_OK;
cleanup:
	return res;
}
