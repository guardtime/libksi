/*
 * Copyright 2013-2016 Guardtime, Inc.
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
#include "internal.h"
#include "ctx_impl.h"
#include "net_file_impl.h"
#include "net_file.h"
#include "sys/types.h"
#include "fast_tlv.h"

#define TLV_BUFFER_SIZE     (0xffff + 4)

typedef struct FsClient_Endpoint_st FsClientCtx, FsClient_Endpoint;

static int FsClient_Endpoint_new(FsClient_Endpoint **fs) {
	FsClient_Endpoint *tmp = NULL;

	if (fs == NULL) return KSI_INVALID_ARGUMENT;

	tmp = KSI_new(FsClient_Endpoint);
	if (tmp == NULL) return KSI_OUT_OF_MEMORY;

	tmp->path = NULL;

	*fs = tmp;
	return KSI_OK;
}

static void FsClientCtx_free(FsClientCtx *fs) {
	if (fs != NULL) {
		KSI_free(fs->path);
		KSI_free(fs);
	}
}

#define FsClient_Endpoint_free FsClientCtx_free

static int readResponse(KSI_RequestHandle *handle) {
	int res;
	FsClientCtx *fs = NULL;
	size_t count = 0;
	unsigned char *buffer = NULL;
	KSI_FTLV ftlv;
	FILE *f = NULL;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	fs = handle->implCtx;

	KSI_LOG_debug(handle->ctx, "File: Read response from: %s", fs->path);
	f = fopen(fs->path, "rb");
	if (f == NULL) {
		KSI_pushError(handle->ctx, res = KSI_IO_ERROR, "Unable to open file.");
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	buffer = KSI_calloc(TLV_BUFFER_SIZE, sizeof(unsigned char));
	if (buffer == NULL) {
		KSI_pushError(handle->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = KSI_FTLV_fileRead(f, buffer, TLV_BUFFER_SIZE,  &count, &ftlv);
	if (res != KSI_OK || count == 0) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_ARGUMENT, "Unable to read TLV from file.");
		goto cleanup;
	}

	if (count > TLV_BUFFER_SIZE){
		KSI_pushError(handle->ctx, res = KSI_BUFFER_OVERFLOW, "Too much data read from file.");
		goto cleanup;
	}

	res = KSI_RequestHandle_setResponse(handle, buffer, count);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	if (f != NULL) fclose(f);
	if (buffer != NULL) KSI_free(buffer);

	return res;
}

static int sendRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *path) {
	int res;
	FsClientCtx *fs = NULL;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	if (client == NULL || path == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	fs = KSI_new(FsClientCtx);
	if (fs == NULL) {
		KSI_pushError(handle->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	fs->path = NULL;

	res = KSI_strdup(path, &fs->path);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	handle->readResponse = readResponse;
	handle->client = client;

	res = KSI_RequestHandle_setImplContext(handle, fs, (void (*)(void *))FsClientCtx_free);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	fs = NULL;
	res = KSI_OK;

cleanup:

	FsClientCtx_free(fs);

	return res;
}

static int prepareRequest(KSI_NetworkClient *client,
						  void *pdu,
						  int (*serialize)(void *, unsigned char **, size_t *),
						  KSI_RequestHandle **handle,
						  char *path,
						  const char *desc) {
	int res;
	KSI_FsClient *fsClient = client->impl;
	KSI_RequestHandle *tmp = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;

	if (client == NULL || pdu == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(client->ctx);

	KSI_LOG_debug(client->ctx, "File: %s", desc);

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

	if (fsClient->sendRequest == NULL) {
		KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}

	res = fsClient->sendRequest(client, tmp, path);
	if (res != KSI_OK) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	*handle = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_RequestHandle_free(tmp);

	return res;
}

static int prepareExtendRequest(KSI_NetworkClient *client, KSI_ExtendReq *req, KSI_RequestHandle **handle) {
	int res;
	FsClient_Endpoint *endp = NULL;
	KSI_Integer *pReqId = NULL;
	KSI_Integer *reqId = NULL;
	KSI_ExtendPdu *pdu = NULL;

	if (client == NULL || req == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	endp = client->extender->implCtx;

	if (endp->path == NULL) {
		res = KSI_EXTENDER_NOT_CONFIGURED;
		goto cleanup;
	}

	res = KSI_ExtendReq_getRequestId(req, &pReqId);
	if (res != KSI_OK) goto cleanup;

	if (pReqId == NULL) {
		res = KSI_Integer_new(client->ctx, ++client->ctx->netProvider->requestCount, &reqId);
		if (res != KSI_OK) goto cleanup;

		res = KSI_ExtendReq_setRequestId(req, reqId);
		if (res != KSI_OK) goto cleanup;

		reqId = NULL;
	}

	res = KSI_ExtendReq_enclose(req, client->extender->ksi_user, client->extender->ksi_pass, &pdu);
	if (res != KSI_OK) goto cleanup;

	res = prepareRequest(
			  client,
			  pdu,
			  (int (*)(void *, unsigned char **, size_t *))KSI_ExtendPdu_serialize,
			  handle,
			  endp->path,
			  "Extend request");
	if (res != KSI_OK) goto cleanup;
	res = KSI_OK;

cleanup:
	KSI_Integer_free(reqId);

	return res;
}

static int prepareAggregationRequest(KSI_NetworkClient *client, KSI_AggregationReq *req, KSI_RequestHandle **handle) {
	int res;
	FsClient_Endpoint *endp = NULL;
	KSI_Integer *pReqId = NULL;
	KSI_Integer *reqId = NULL;
	KSI_AggregationPdu *pdu = NULL;

	if (client == NULL || req == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	endp = client->aggregator->implCtx;

	if (endp->path == NULL) {
		res = KSI_AGGREGATOR_NOT_CONFIGURED;
		goto cleanup;
	}

	res = KSI_AggregationReq_getRequestId(req, &pReqId);
	if (res != KSI_OK) goto cleanup;

	if (pReqId == NULL) {
		res = KSI_Integer_new(client->ctx, ++client->ctx->netProvider->requestCount, &reqId);
		if (res != KSI_OK) goto cleanup;

		res = KSI_AggregationReq_setRequestId(req, reqId);
		if (res != KSI_OK) goto cleanup;

		reqId = NULL;
	}

	res = KSI_AggregationReq_enclose(req, client->aggregator->ksi_user, client->aggregator->ksi_pass, &pdu);
	if (res != KSI_OK) goto cleanup;

	res = prepareRequest(
			  client,
			  pdu,
			  (int (*)(void *, unsigned char **, size_t *))KSI_AggregationPdu_serialize,
			  handle,
			  endp->path,
			  "Aggregation request");
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:
	KSI_Integer_free(reqId);
	KSI_AggregationPdu_setRequest(pdu, NULL);
	KSI_AggregationPdu_free(pdu);

	return res;
}

static int publicationFileReceive(KSI_RequestHandle *handle) {
	int res;
	FsClientCtx *fs = NULL;
	size_t count = 0;
	size_t size = 0;
	unsigned char *buffer = NULL;
	FILE *f = NULL;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	fs = handle->implCtx;

	KSI_LOG_debug(handle->ctx, "File: Read publication file response from: %s", fs->path);
	f = fopen(fs->path, "rb");
	if (f == NULL) {
		KSI_pushError(handle->ctx, res = KSI_IO_ERROR, "Unable to open file.");
		res = KSI_IO_ERROR;
		goto cleanup;
	}

	/* Find size of the file */
	res = fseek(f, 0, SEEK_END);
	if (res != 0) {
		KSI_pushError(handle->ctx, res = KSI_IO_ERROR, NULL);
		goto cleanup;
	}
	size = ftell(f);
	if (size < 0) {
		KSI_pushError(handle->ctx, res = KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	if (size > INT_MAX) {
		KSI_pushError(handle->ctx, res = KSI_IO_ERROR, NULL);
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	res = fseek(f, 0, SEEK_SET);
	if (res != 0) {
		KSI_pushError(handle->ctx, res = KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	buffer = KSI_calloc(size, sizeof(unsigned char));
	if (buffer == NULL) {
		KSI_pushError(handle->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	count = fread(buffer, sizeof(unsigned char), size, f);
	if (count != size) {
		KSI_pushError(handle->ctx, res = KSI_IO_ERROR, "Failed to read publications file.");
		goto cleanup;
	}

	res = KSI_RequestHandle_setResponse(handle, buffer, count);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:
	if (f != NULL)      fclose(f);
	if (buffer != NULL) KSI_free(buffer);

	return res;
}

static int sendPublicationRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *path) {
	int res;
	FsClientCtx *fs = NULL;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	if (client == NULL || path == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	fs = KSI_new(FsClientCtx);
	if (fs == NULL) {
		KSI_pushError(handle->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	fs->path = NULL;

	res = KSI_strdup(path, &fs->path);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	handle->readResponse = publicationFileReceive;
	handle->client = client;

	res = KSI_RequestHandle_setImplContext(handle, fs, (void (*)(void *))FsClientCtx_free);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}
	fs = NULL;

	res = KSI_OK;

cleanup:

	FsClientCtx_free(fs);

	return res;
}

static int preparePublicationRequest(KSI_NetworkClient *client, KSI_RequestHandle **handle) {
	int res;
	KSI_RequestHandle *tmp = NULL;
	FsClient_Endpoint *endp = NULL;

	if (handle == NULL) {
		KSI_pushError(client->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_RequestHandle_new(client->ctx, NULL, 0, &tmp);
	if (tmp == NULL) {
		KSI_pushError(client->ctx, res, NULL);
		goto cleanup;
	}

	endp = client->publicationsFile->implCtx;

	if (endp->path == NULL) {
		res = KSI_EXTENDER_NOT_CONFIGURED;
		goto cleanup;
	}

	sendPublicationRequest(client, tmp, endp->path);

	*handle = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_RequestHandle_free(tmp);

	return res;
}

static void FsClient_free(KSI_FsClient *fs) {
	if (fs != NULL) {
		KSI_NetworkClient_free(fs->http);
		KSI_free(fs);
	}
}

int KSI_FsClient_new(KSI_CTX *ctx, KSI_NetworkClient **client) {
	int res;
	KSI_NetworkClient *tmp = NULL;
	KSI_FsClient *fs = NULL;
	FsClient_Endpoint *endp_aggr = NULL;
	FsClient_Endpoint *endp_ext = NULL;
	FsClient_Endpoint *endp_pub = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || client == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_AbstractNetworkClient_new(ctx, &tmp);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	fs = KSI_new(KSI_FsClient);
	if (fs == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	fs->sendRequest = sendRequest;
	fs->http = NULL;

	res = KSI_HttpClient_new(ctx, &fs->http);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Create implementations for abstract endpoints. */
	res = FsClient_Endpoint_new(&endp_aggr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = FsClient_Endpoint_new(&endp_ext);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = FsClient_Endpoint_new(&endp_pub);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Set implementations for abstract endpoints. */
	res = KSI_NetEndpoint_setImplContext(tmp->aggregator, endp_aggr, (void (*)(void*))FsClient_Endpoint_free);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	endp_aggr = NULL;

	res = KSI_NetEndpoint_setImplContext(tmp->extender, endp_ext, (void (*)(void*))FsClient_Endpoint_free);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	endp_ext = NULL;

	res = KSI_NetEndpoint_setImplContext(tmp->publicationsFile, endp_pub, (void (*)(void*))FsClient_Endpoint_free);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	endp_pub = NULL;

	tmp->sendExtendRequest = prepareExtendRequest;
	tmp->sendSignRequest = prepareAggregationRequest;
	tmp->sendPublicationRequest = preparePublicationRequest;

	tmp->impl = fs;
	tmp->implFree = (void (*)(void *))FsClient_free;
	fs = NULL;

	tmp->requestCount = 0;

	*client = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	FsClient_free(fs);
	KSI_NetworkClient_free(tmp);
	FsClient_Endpoint_free(endp_aggr);
	FsClient_Endpoint_free(endp_ext);
	FsClient_Endpoint_free(endp_pub);

	return res;
}

static int setService(KSI_NetworkClient *client, KSI_NetEndpoint *abs_endp, const char *path, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;
	FsClient_Endpoint *endp = NULL;

	if (abs_endp == NULL || path == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	endp = abs_endp->implCtx;

	/* Set path to the file */
	res = client->setStringParam(&endp->path, path);
	if (res != KSI_OK) goto cleanup;

	res = client->setStringParam(&abs_endp->ksi_user, (user != NULL ? user : ""));
	if (res != KSI_OK) goto cleanup;
	res = client->setStringParam(&abs_endp->ksi_pass, (pass != NULL ? pass : ""));
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_FsClient_setExtender(KSI_NetworkClient *client, const char *path, const char *user, const char *pass) {
	if (client == NULL || client->extender == NULL) return KSI_INVALID_ARGUMENT;
	return setService(client, client->extender, path, user, pass);
}

int KSI_FsClient_setAggregator(KSI_NetworkClient *client, const char *path, const char *user, const char *pass) {
	if (client == NULL || client->aggregator == NULL) return KSI_INVALID_ARGUMENT;
	return setService(client, client->aggregator, path, user, pass);
}

int KSI_FsClient_setPublicationUrl(KSI_NetworkClient *client, const char *path) {
	if (client == NULL || client->publicationsFile == NULL) return KSI_INVALID_ARGUMENT;
	return setService(client, client->publicationsFile, path, NULL, NULL);
}

int KSI_FsClient_extractPath(const char *uri, char **path) {
	int res = KSI_UNKNOWN_ERROR;
	const char *scheme = "file://";
	char *pathStart = strstr(uri, scheme) + strlen(scheme);
	char *tmpPath = NULL;

	if (path == NULL || pathStart == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmpPath = KSI_malloc(strlen(pathStart) + 1);
	if (tmpPath == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	*tmpPath = '\0';
	strcpy(tmpPath, pathStart);

	if (*path != NULL) KSI_free(*path);
	*path = tmpPath;
	tmpPath = NULL;

	res = KSI_OK;

cleanup:
	if (tmpPath) KSI_free(tmpPath);
	return res;
}
