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
#include "net_impl.h"
#include "ctx_impl.h"
#include "signature_builder.h"
#include "signature_builder_impl.h"

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
		if (o->respCtx_free) o->respCtx_free(o->respCtx);
		if (o->userCtx_free) o->userCtx_free(o->userCtx);
		KSI_free(o->raw);
		KSI_Utf8String_free(o->errMsg);
		KSI_nofree(o->next);

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

	tmp->next = NULL;

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

KSI_IMPLEMENT_REF(KSI_AsyncHandle)

KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, int, state, State)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, int, err, Error)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, long, errExt, ExtError)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, KSI_Utf8String *, errMsg, ErrorMessage)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, const void *, userCtx, RequestCtx)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, KSI_uint64_t, id, RequestId)
KSI_IMPLEMENT_GETTER(KSI_AsyncHandle, KSI_AggregationReq *, aggrReq, AggregationReq)

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
	} else {
		KSI_pushError(h->ctx, res = KSI_INVALID_STATE, "Request is missing.");
		goto cleanup;
	}
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

	res = KSI_Header_new(c->ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = c->getCredentials(c->clientImpl, &user, NULL);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Utf8String_new(c->ctx, user, strlen(user) + 1, &loginId);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Header_setLoginId(tmp, loginId);
	if (res != KSI_OK) goto cleanup;
	loginId = NULL;

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

static int asyncClient_addAggregationRequest(KSI_AsyncClient *c, KSI_AsyncHandle *handle) {
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

	if (c == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (handle->aggrReq == NULL ||
			c->clientImpl == NULL || c->addRequest == NULL || c->getCredentials == NULL) {
		res = KSI_INVALID_STATE;
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

	/* Set into local cache. */
	c->reqCache[id] = handle;
	c->pending++;

	res = KSI_OK;
cleanup:
	KSI_Header_free(hdr);
	KSI_free(raw);
	KSI_Integer_free(reqId);
	KSI_AggregationPdu_free(pdu);

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

static int asyncClient_handleAggregationResp(KSI_AsyncClient *c, KSI_AggregationPdu *pdu) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *reqId = NULL;
	KSI_AsyncHandle *handle = NULL;
	KSI_uint64_t id = 0;
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

	if (resp == NULL) {
		/* The response PDU does not include aggregation response. */
		goto cleanup;
	}

	res = KSI_AggregationResp_getRequestId(resp, &reqId);
	if (res != KSI_OK) {
		KSI_pushError(c->ctx, res , NULL);
		goto cleanup;
	}

	id = KSI_Integer_getUInt64(reqId) & KSI_ASYNC_REQUEST_ID_MASK;
	if (c->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE] <= id ||
			(handle = c->reqCache[id]) == NULL || handle->id != KSI_Integer_getUInt64(reqId)) {
		KSI_LOG_warn(c->ctx, "Unexpected async aggregation response received.");
		goto cleanup;
	}

	if (handle->state == KSI_ASYNC_STATE_WAITING_FOR_RESPONSE) {
		KSI_Integer *status = NULL;

		res = KSI_AggregationResp_verifyWithRequest(resp, handle->aggrReq);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		/* Verify response status. */
		res = KSI_AggregationResp_getStatus(resp, &status);
		if (res != KSI_OK) {
			KSI_pushError(c->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_convertAggregatorStatusCode(status);
		if (res != KSI_OK) {
			KSI_Utf8String *errorMsg = NULL;

			KSI_AggregationResp_getErrorMsg(resp, &errorMsg);
			KSI_LOG_error(c->ctx, "Async aggregation request failed: [%x] %s", KSI_Integer_getUInt64(status), KSI_Utf8String_cstr(errorMsg));

			handle->state = KSI_ASYNC_STATE_ERROR;
			handle->err = res;
			handle->errExt = (long)KSI_Integer_getUInt64(status);
			handle->errMsg = KSI_Utf8String_ref(errorMsg);
		} else {
			res = KSI_AggregationPdu_setResponse(pdu, NULL);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}
			handle->respCtx = (void*)resp;
			handle->respCtx_free = (void (*)(void*))KSI_AggregationResp_free;

			handle->state = KSI_ASYNC_STATE_RESPONSE_RECEIVED;
			c->pending--;
			c->received++;
		}
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int asyncClient_processAggregationResponseQueue(KSI_AsyncClient *c) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_OctetString *resp = NULL;
	KSI_AggregationPdu *pdu = NULL;
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
		KSI_AggregationPdu_free(pdu);
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

			KSI_LOG_logBlob(c->ctx, KSI_LOG_DEBUG, "Parsing aggregation response", raw, len);

			/* Get PDU object. */
			res = KSI_AggregationPdu_parse(c->ctx, raw, len, &pdu);
			if(res != KSI_OK){
				KSI_pushError(c->ctx, res, "Unable to parse aggregation pdu.");
				goto cleanup;
			}

			/* Check for error PDU. */
			res = KSI_AggregationPdu_getError(pdu, &error);
			if (res != KSI_OK) {
				KSI_pushError(c->ctx, res, NULL);
				goto cleanup;
			}
			if (error != NULL) {
				res = KSI_AggregationPdu_setError(pdu, NULL);
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

			res = KSI_AggregationPdu_verify(pdu, pass);
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

			res = asyncClient_handleAggregationResp(c, pdu);
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

		KSI_LOG_error(c->ctx, "Async received error PDU: [%x:%x] %s",
				KSI_convertAggregatorStatusCode(status), (long)KSI_Integer_getUInt64(status), KSI_Utf8String_cstr(errorMsg));

		/* Set all handles that are still in response wait state into error state. */
		asyncClient_setResponseError(c, KSI_ASYNC_STATE_WAITING_FOR_RESPONSE,
				KSI_convertAggregatorStatusCode(status), (long)KSI_Integer_getUInt64(status), errorMsg);
	}

	res = KSI_OK;
cleanup:
	KSI_OctetString_free(resp);
	KSI_AggregationPdu_free(pdu);

	return res;
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

	if (c->pending == 0 && c->received == 0) {
		/* There are no handles on hold. */
		*handle = NULL;
		res = KSI_OK;
		goto cleanup;
	}

	last = c->tail;
	for (;;) {
		if (c->reqCache[c->tail] != NULL) {
			switch (c->reqCache[c->tail]->state) {
				case KSI_ASYNC_STATE_WAITING_FOR_RESPONSE:
					/* Verify that the handle has not been waiting a response for too long. */
					if (c->options[KSI_ASYNC_OPT_RCV_TIMEOUT] == 0 ||
							difftime(time(NULL), c->reqCache[c->tail]->sndTime) > c->options[KSI_ASYNC_OPT_RCV_TIMEOUT]) {
						/* Set handle into error state and return it. */
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
					/* Dont care about other states. */
					break;
			}
		}
		if (++c->tail == c->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE]) c->tail = KSI_ASYNC_CACHE_START_POS;
		if (c->tail == last) {
			/* We are back at where we began the search. There are no finalized requests to return yet. */
			break;
		}
	}
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
		if (c->reqCache != NULL) {
			size_t i;
			for (i = 0; i < c->options[KSI_ASYNC_OPT_REQUEST_CACHE_SIZE]; i++) KSI_AsyncHandle_free(c->reqCache[i]);
			KSI_free(c->reqCache);
		}
		if (c->clientImpl_free) c->clientImpl_free(c->clientImpl);
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

	tmp->addRequest = (int (*)(void *, KSI_AsyncHandle *))asyncClient_addAggregationRequest;
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
