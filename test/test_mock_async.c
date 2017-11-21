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

#include <string.h>
#include <sys/types.h>

#include "../src/ksi/io.h"
#include "../src/ksi/tlv.h"
#include "../src/ksi/fast_tlv.h"
#include "../src/ksi/types.h"
#include "../src/ksi/net_async.h"
#include "../src/ksi/impl/net_impl.h"

#include "support_tests.h"


#define KSI_TLV_MAX_SIZE (0xffff + 4)

typedef struct {
	KSI_CTX *ctx;
	/* File descriptor. */
	FILE *file;
	/* Output queue. */
	KSI_AsyncHandleList *reqQueue;
	/* Input queue. */
	KSI_OctetStringList *respQueue;

	/* Round throttling. */
	time_t roundStartAt;
	size_t roundCount;

	/* Poiter to the async options. */
	size_t *options;

	/* Endpoint data. */
	const char **paths;
	size_t nofPaths;
	size_t pathCount;
	const char *ksi_user;
	const char *ksi_pass;
} KSITest_FileAsyncClientCtx;

static void reqQueue_clearWithError(KSI_AsyncHandleList *reqQueue, int err, long ext) {
	size_t size = 0;

	if (reqQueue == NULL) return;

	while ((size = KSI_AsyncHandleList_length(reqQueue)) > 0) {
		int res;
		KSI_AsyncHandle *req = NULL;

		res = KSI_AsyncHandleList_elementAt(reqQueue, size - 1, &req);
		if (res != KSI_OK || req == NULL) return;

		/* Update request state. */
		req->state = KSI_ASYNC_STATE_ERROR;
		req->err = err;
		req->errExt = ext;

		KSI_AsyncHandle_free(req);
	}
}

static int dispatch(KSITest_FileAsyncClientCtx *clientCtx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_OctetString *resp = NULL;

	if (clientCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(clientCtx->ctx);

	/* Handle output. */
	while (KSI_AsyncHandleList_length(clientCtx->reqQueue) > 0) {
		KSI_AsyncHandle *req = NULL;
		time_t curTime = 0;

		time(&curTime);
#if 0
		/* Check if the request count can be restarted. */
		if (difftime(time(&curTime), clientCtx->roundStartAt) >= clientCtx->options[KSI_ASYNC_PRIVOPT_ROUND_DURATION]) {
			KSI_LOG_info(clientCtx->ctx, "Async FILE round request count: %u", clientCtx->roundCount);
			clientCtx->roundCount = 0;
			clientCtx->roundStartAt = curTime;
		}
		/* Check if more requests can be sent within the given timeframe. */
		if (!(clientCtx->roundCount < clientCtx->options[KSI_ASYNC_OPT_MAX_REQUEST_COUNT])) {
			KSI_LOG_debug(clientCtx->ctx, "Async FILE round max request count reached.");
			break;
		}
#endif

		res = KSI_AsyncHandleList_elementAt(clientCtx->reqQueue, 0, &req);
		if (res != KSI_OK) {
			KSI_LOG_error(clientCtx->ctx, "Async FILE. Unable to extract async handle from request queue. Error: 0x%x.", res);
			res = KSI_OK;
			goto cleanup;
		}
		KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG, "Async FILE. Sending request", req->raw, req->len);

		if (req->state == KSI_ASYNC_STATE_WAITING_FOR_DISPATCH) {
			clientCtx->roundCount++;

			/* Release the serialized payload. */
			KSI_free(req->raw);
			req->raw = NULL;
			req->len = 0;
			req->sentCount = 0;

			/* Update state. */
			req->state = KSI_ASYNC_STATE_WAITING_FOR_RESPONSE;
			/* Start receive timeout. */
			req->sndTime = curTime;
			/* The request has been successfully dispatched. Remove it from the request queue. */
			KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
		} else {
			/* The state could have been changed in application layer. Just remove the request from the request queue. */
			KSI_AsyncHandleList_remove(clientCtx->reqQueue, 0, NULL);
		}
	}

	if (clientCtx->pathCount < clientCtx->nofPaths) {
		const char *path = getFullResourcePath(clientCtx->paths[clientCtx->pathCount]);

		if (clientCtx->file == NULL) {
			KSI_LOG_debug(clientCtx->ctx, "Async FILE. Reading from: %s", path);
			clientCtx->file = fopen(path, "rb");
			/* Check if the file has been opened. */
			if (clientCtx->file == NULL) {
				KSI_pushError(clientCtx->ctx, res = KSI_IO_ERROR, "Unable to open file.");
				res = KSI_IO_ERROR;
				goto cleanup;
			}
		}

		/* Handle input. */
		do {
			KSI_FTLV ftlv;
			size_t count = 0;
			unsigned char buf[KSI_TLV_MAX_SIZE];

			res = KSI_FTLV_fileRead(clientCtx->file, buf, KSI_TLV_MAX_SIZE,  &count, &ftlv);
			if (res != KSI_OK && count != 0) {
				reqQueue_clearWithError(clientCtx->reqQueue, res, 0);
				KSI_LOG_error(clientCtx->ctx, "Unable to read TLV from file. Error: 0x%x.", res);
				res = KSI_OK;
				goto cleanup;
			}

			if (count != 0) {
				if (count > KSI_TLV_MAX_SIZE){
					reqQueue_clearWithError(clientCtx->reqQueue, res = KSI_BUFFER_OVERFLOW, 0);
					KSI_LOG_error(clientCtx->ctx, "Too much data read from file. Error: 0x%x.", res);
					res = KSI_OK;
					goto cleanup;
				}

				KSI_LOG_logBlob(clientCtx->ctx, KSI_LOG_DEBUG, "Async FILE received response", buf, count);

				/* A complete PDU is in cache. Move it into the receive queue. */
				res = KSI_OctetString_new(clientCtx->ctx, buf, count, &resp);
				if (res != KSI_OK) {
					KSI_LOG_error(clientCtx->ctx, "Async FILE unable to create new KSI_OctetString object. Error: 0x%x.", res);
					res = KSI_OK;
					goto cleanup;
				}

				res = KSI_OctetStringList_append(clientCtx->respQueue, resp);
				if (res != KSI_OK) {
					KSI_LOG_error(clientCtx->ctx, "Async FILE unable to add new response to queue. Error: 0x%x.", res);
					res = KSI_OK;
					goto cleanup;
				}
				resp = NULL;
			}
		} while (!feof(clientCtx->file));
	}

	res = KSI_OK;
cleanup:
	if (clientCtx->file != NULL) {
		fclose(clientCtx->file);
		clientCtx->file = NULL;
		clientCtx->pathCount++;
	}

	KSI_OctetString_free(resp);
	return res;
}

static int addToSendQueue(KSITest_FileAsyncClientCtx *clientCtx, KSI_AsyncHandle *request) {
	int res = KSI_UNKNOWN_ERROR;

	if (clientCtx == NULL || clientCtx->reqQueue == NULL || request == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	request->state = KSI_ASYNC_STATE_WAITING_FOR_DISPATCH;
	/* Start send timeout. */
	time(&request->reqTime);

	res = KSI_AsyncHandleList_append(clientCtx->reqQueue, request);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;
cleanup:
	return res;
}

static int getResponse(KSITest_FileAsyncClientCtx *clientCtx, KSI_OctetString **response, size_t *left) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_OctetString *tmp = NULL;

	if (clientCtx == NULL || clientCtx->respQueue == NULL || response == NULL || left == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (KSI_OctetStringList_length(clientCtx->respQueue)) {
		/* Responses should be processed in the same order as received. */
		res = KSI_OctetStringList_remove(clientCtx->respQueue, 0, &tmp);
		if (res != KSI_OK) goto cleanup;
	}

	*response = tmp;
	*left = KSI_OctetStringList_length(clientCtx->respQueue);

	res = KSI_OK;
cleanup:
	return res;
}

static int setService(KSITest_FileAsyncClientCtx *clientCtx, const char **paths, size_t count, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;

	if (clientCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	clientCtx->paths = paths;
	clientCtx->nofPaths = count;
	clientCtx->ksi_user = user;
	clientCtx->ksi_pass = pass;

	res = KSI_OK;
cleanup:
	return res;
}

static int FileAsyncClient_setService(KSI_AsyncClient *c, const char **paths, size_t count, const char *user, const char *pass) {
	if (c == NULL || c->clientImpl == NULL) return KSI_INVALID_ARGUMENT;
	return setService(c->clientImpl, paths, count, user, pass);
}

static int getCredentials(KSITest_FileAsyncClientCtx *clientCtx, const char **user, const char **pass) {
	if (clientCtx == NULL) return KSI_INVALID_ARGUMENT;
	if (user != NULL) *user = clientCtx->ksi_user;
	if (pass != NULL) *pass = clientCtx->ksi_pass;
	return KSI_OK;
}

static void FileAsyncCtx_free(KSITest_FileAsyncClientCtx *t) {
	if (t != NULL) {
		KSI_AsyncHandleList_free(t->reqQueue);
		KSI_OctetStringList_free(t->respQueue);
		if (t->file != NULL) fclose(t->file);
		KSI_nofree(t->paths);
		KSI_nofree(t->ksi_user);
		KSI_nofree(t->ksi_pass);
		KSI_free(t);
	}
}

static int FileAsyncCtx_new(KSI_CTX *ctx, KSITest_FileAsyncClientCtx **clientCtx) {
	int res = KSI_UNKNOWN_ERROR;
	KSITest_FileAsyncClientCtx *tmp = NULL;

	if (ctx == NULL || clientCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_malloc(sizeof(KSITest_FileAsyncClientCtx));
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	tmp->ctx = ctx;
	tmp->file = NULL;

	tmp->reqQueue = NULL;
	tmp->respQueue = NULL;

	tmp->ksi_user = NULL;
	tmp->ksi_pass = NULL;
	tmp->paths = NULL;
	tmp->nofPaths = 0;
	tmp->pathCount = 0;

	tmp->roundStartAt = 0;
	tmp->roundCount = 0;

	/* Initialize io queues. */
	res = KSI_AsyncHandleList_new(&tmp->reqQueue);
	if (res != KSI_OK) goto cleanup;
	res = KSI_OctetStringList_new(&tmp->respQueue);
	if (res != KSI_OK) goto cleanup;

	*clientCtx = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	FileAsyncCtx_free(tmp);
	return res;
}

static int FileAsyncClient_new(KSI_CTX *ctx, KSI_AsyncClient **c) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncClient *tmp = NULL;
	KSITest_FileAsyncClientCtx *clientImpl = NULL;

	if (ctx == NULL || c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_AbstractAsyncClient_new(ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	tmp->addRequest = (int (*)(void *, KSI_AsyncHandle *))addToSendQueue;
	tmp->getResponse = (int (*)(void *, KSI_OctetString **, size_t *))getResponse;
	tmp->dispatch = (int (*)(void *))dispatch;
	tmp->getCredentials = (int (*)(void *, const char **, const char **))getCredentials;


	res = FileAsyncCtx_new(ctx, &clientImpl);
	if (res != KSI_OK) goto cleanup;

	clientImpl->options = tmp->options;

	tmp->clientImpl_free = (void (*)(void*))FileAsyncCtx_free;
	tmp->clientImpl = clientImpl;
	clientImpl = NULL;

	*c = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	FileAsyncCtx_free(clientImpl);
	KSI_AsyncClient_free(tmp);

	return res;
}

int KSITest_MockAsyncService_setEndpoint(KSI_AsyncService *service, const char **paths, size_t nofPaths, const char *loginId, const char *key) {
	int res = KSI_UNKNOWN_ERROR;

	if (service == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (service->impl == NULL) {
		service->impl_free = (void (*)(void*))KSI_AsyncClient_free;
		res = FileAsyncClient_new(service->ctx, (KSI_AsyncClient **)&service->impl);
		if (res != KSI_OK) goto cleanup;
	}

	res = FileAsyncClient_setService(service->impl, paths, nofPaths, loginId, key);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;
cleanup:
	return res;
}
