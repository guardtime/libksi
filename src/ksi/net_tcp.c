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
#include "internal.h"
#include "net_http_impl.h"
#include "ctx_impl.h"
#include "net_tcp_impl.h"
#include "net_tcp.h"
#include "sys/types.h"
#include "io.h"
#include "tlv.h"
#include "fast_tlv.h"

#ifndef _WIN32
#  include <unistd.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  ifndef __USE_MISC
#    define __USE_MISC
#    include <netdb.h>
#    undef __USE_MISC
#  else
#    include <netdb.h>
#  endif
#  include <sys/time.h>
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  define close(soc) closesocket(soc)
#endif

typedef struct TcpClient_Endpoint_st TcpClientCtx, TcpClient_Endpoint;

static int TcpClient_Endpoint_new(TcpClient_Endpoint **t) {
	TcpClient_Endpoint *tmp = NULL;
	if (t == NULL) return KSI_INVALID_ARGUMENT;

	tmp = KSI_new(TcpClient_Endpoint);
	if (tmp == NULL) return KSI_OUT_OF_MEMORY;

	tmp->host = NULL;
	tmp->port = 0;

	*t = tmp;
	return KSI_OK;
}

static void TcpClientCtx_free(TcpClientCtx *t) {
	if (t != NULL) {
		KSI_free(t->host);
		KSI_free(t);
	}
}

#define TcpClient_Endpoint_free TcpClientCtx_free

static int readResponse(KSI_RequestHandle *handle) {
	int res;
	TcpClientCtx *tcp = NULL;
	KSI_TcpClient *client = NULL;
	int sockfd = -1;
	struct sockaddr_in serv_addr;
	struct hostent *server = NULL;
	size_t count;
	unsigned char buffer[0xffff + 4];
	KSI_FTLV ftlv;
#ifdef _WIN32
	DWORD transferTimeout = 0;
#else
	struct timeval  transferTimeout;
#endif

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	tcp = handle->implCtx;
	client = handle->client->impl;

	sockfd = (int)socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		KSI_pushError(handle->ctx, res = KSI_NETWORK_ERROR, "Unable to open socket.");
		goto cleanup;
	}
#ifdef _WIN32
	transferTimeout = client->transferTimeoutSeconds * 1000;
#else
	transferTimeout.tv_sec = client->transferTimeoutSeconds;
	transferTimeout.tv_usec = 0;
#endif

	/*Set socket options*/
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (void*)&transferTimeout, sizeof(transferTimeout));
	setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (void*)&transferTimeout, sizeof(transferTimeout));

	server = gethostbyname(tcp->host);
	if (server == NULL) {
		KSI_pushError(handle->ctx, res = KSI_NETWORK_ERROR, "Unable to open host.");
		goto cleanup;
	}

	memset((char *) &serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;

	if (server->h_length <= sizeof(serv_addr.sin_addr.s_addr)) {
		memmove((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);
	} else {
		KSI_pushError(handle->ctx, res = KSI_BUFFER_OVERFLOW, "Host address too long.");
		goto cleanup;
	}

	serv_addr.sin_port = htons(tcp->port);

	if ((res = connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) < 0) {
		KSI_ERR_push(handle->ctx, KSI_NETWORK_ERROR, res, __FILE__, __LINE__, "Unable to connect.");
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	KSI_LOG_logBlob(handle->ctx, KSI_LOG_DEBUG, "Sending request", handle->request, handle->request_length);
	count = 0;
	while (count < handle->request_length) {
		int c;

#ifdef _WIN32
		if (handle->request_length > INT_MAX) {
			KSI_pushError(handle->ctx, res = KSI_BUFFER_OVERFLOW, "Unable to send more than MAX_INT bytes.");
			goto cleanup;
		}
		c = send(sockfd, (char *) handle->request, (int) handle->request_length, 0);
#else
		c = send(sockfd, (char *) handle->request, handle->request_length, 0);
#endif
		if (c < 0) {
			KSI_pushError(handle->ctx, res = KSI_NETWORK_ERROR, "Unable to write to socket.");
			goto cleanup;
		}
		count += c;
	}

	res = KSI_FTLV_socketRead(sockfd, buffer, sizeof(buffer), &count, &ftlv);
	if (res != KSI_OK || count == 0) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_ARGUMENT, "Unable to read TLV from socket.");
		goto cleanup;
	}

	if(count > UINT_MAX){
		KSI_pushError(handle->ctx, res = KSI_BUFFER_OVERFLOW, "Too much data read from socket.");
		goto cleanup;
	}

	handle->response = KSI_malloc(count);
	if (handle->response == NULL) {
		KSI_pushError(handle->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	memcpy(handle->response, buffer, count);
	handle->response_length = count;

	handle->completed = true;

	res = KSI_OK;

cleanup:

	if (sockfd >= 0) close(sockfd);

	return res;
}

static int sendRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *host, unsigned port) {
	int res;
	TcpClientCtx *tc = NULL;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

	if (client == NULL || host == NULL) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tc = KSI_new(TcpClientCtx);
	if (tc == NULL) {
		KSI_pushError(handle->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	tc->host = NULL;
	tc->port = 0;

	KSI_LOG_debug(handle->ctx, "Tcp: Sending request to: %s:%u", host, port);

	res = KSI_strdup(host, &tc->host);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}
	tc->port = port;


	handle->readResponse = readResponse;
	handle->client = client;

	res = KSI_RequestHandle_setImplContext(handle, tc, (void (*)(void *))TcpClientCtx_free);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

	tc = NULL;

	res = KSI_OK;

cleanup:

	TcpClientCtx_free(tc);

	return res;
}

static int prepareRequest(
		KSI_NetworkClient *client,
		void *pdu,
		int (*serialize)(void *, unsigned char **, size_t *),
		KSI_RequestHandle **handle,
		char *host,
		unsigned port,
		const char *desc) {
	int res;
	KSI_TcpClient *tcp = client->impl;
	KSI_RequestHandle *tmp = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;

	if (client->ctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(client->ctx);

	if (pdu == NULL || handle == NULL) {
		KSI_pushError(client->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

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

	if (tcp->sendRequest == NULL) {
		KSI_pushError(client->ctx, res = KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}

	res = tcp->sendRequest(client, tmp, host, port);
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
	TcpClient_Endpoint *endp = NULL;

	if (client == NULL || req == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	endp = client->extender->implCtx;

	if (endp->host == NULL || endp->port == 0) {
		res = KSI_EXTENDER_NOT_CONFIGURED;
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

	res = KSI_ExtendReq_enclose(req, client->extender->ksi_user, client->extender->ksi_pass, &pdu);
	if (res != KSI_OK) goto cleanup;

	res = prepareRequest(
			client,
			pdu,
			(int (*)(void *, unsigned char **, size_t *))KSI_ExtendPdu_serialize,
			handle,
			endp->host,
			endp->port,
			"Extend request");
	if (res != KSI_OK) goto cleanup;
	res = KSI_OK;

cleanup:

	KSI_ExtendPdu_setRequest(pdu, NULL);
	KSI_ExtendPdu_free(pdu);

	return res;
}

static int prepareAggregationRequest(KSI_NetworkClient *client, KSI_AggregationReq *req, KSI_RequestHandle **handle) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationPdu *pdu = NULL;
	KSI_Integer *pReqId = NULL;
	KSI_Integer *reqId = NULL;
	TcpClient_Endpoint *endp = NULL;

	if (client == NULL || req == NULL || handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	endp = client->aggregator->implCtx;

	if (endp->host == NULL || endp->port == 0) {
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

	res = KSI_AggregationReq_enclose(req, client->aggregator->ksi_user, client->aggregator->ksi_pass, &pdu);
	if (res != KSI_OK) goto cleanup;

	res = prepareRequest(
			client,
			pdu,
			(int (*)(void *, unsigned char **, size_t *))KSI_AggregationPdu_serialize,
			handle,
			endp->host,
			endp->port,
			"Aggregation request");
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	KSI_AggregationPdu_setRequest(pdu, NULL);
	KSI_AggregationPdu_free(pdu);

	return res;
}

static int sendPublicationRequest(KSI_NetworkClient *client, KSI_RequestHandle **handle) {
	int res;
	KSI_TcpClient *tcpClient = client->impl;

	res = KSI_NetworkClient_sendPublicationsFileRequest(tcpClient->http, handle);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static void tcpClient_free(KSI_TcpClient *tcp) {
	if (tcp != NULL) {
		KSI_NetworkClient_free(tcp->http);
		KSI_free(tcp);
	}
}

/**
 *
 */
int KSI_TcpClient_new(KSI_CTX *ctx, KSI_NetworkClient **tcp) {
	int res;
	KSI_NetworkClient *tmp = NULL;
	KSI_TcpClient *t = NULL;
	TcpClient_Endpoint *endp_aggr = NULL;
	TcpClient_Endpoint *endp_ext = NULL;
	TcpClient_Endpoint *endp_pub = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || tcp == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_AbstractNetworkClient_new(ctx, &tmp);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	t = KSI_new(KSI_TcpClient);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	t->sendRequest = sendRequest;
	t->transferTimeoutSeconds = 10;
	t->http = NULL;

	res = KSI_HttpClient_new(ctx, &t->http);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Create implementations for abstract endpoints. */
	res = TcpClient_Endpoint_new(&endp_aggr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = TcpClient_Endpoint_new(&endp_ext);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = TcpClient_Endpoint_new(&endp_pub);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Set implementations for abstract endpoints. */
	res = KSI_NetEndpoint_setImplContext(tmp->aggregator, endp_aggr, (void (*)(void*))TcpClient_Endpoint_free);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	endp_aggr = NULL;

	res = KSI_NetEndpoint_setImplContext(tmp->extender, endp_ext, (void (*)(void*))TcpClient_Endpoint_free);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	endp_ext = NULL;

	res = KSI_NetEndpoint_setImplContext(tmp->publicationsFile, endp_pub, (void (*)(void*))TcpClient_Endpoint_free);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	endp_pub = NULL;

	tmp->sendExtendRequest = prepareExtendRequest;
	tmp->sendSignRequest = prepareAggregationRequest;
	tmp->sendPublicationRequest = sendPublicationRequest;
	tmp->implFree = (void (*)(void *))tcpClient_free;
	tmp->requestCount = 0;

	tmp->impl = t;
	t = NULL;

	*tcp = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	tcpClient_free(t);
	KSI_NetworkClient_free(tmp);
	TcpClient_Endpoint_free(endp_aggr);
	TcpClient_Endpoint_free(endp_ext);
	TcpClient_Endpoint_free(endp_pub);

	return res;
}

static int ksi_TcpClient_setService(KSI_NetworkClient *client, KSI_NetEndpoint *abs_endp, const char *host, unsigned port, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;
	TcpClient_Endpoint *endp = NULL;

	if (abs_endp == NULL || host == NULL || user == NULL || pass == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	endp = abs_endp->implCtx;

	res = client->setStringParam(&endp->host, host);
	if (res != KSI_OK) goto cleanup;

	endp->port = port;

	res = client->setStringParam(&abs_endp->ksi_user, user);
	if (res != KSI_OK) goto cleanup;

	res = client->setStringParam(&abs_endp->ksi_pass, pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}
int KSI_TcpClient_setExtender(KSI_NetworkClient *client, const char *host, unsigned port, const char *user, const char *pass) {
	if (client == NULL || client->extender == NULL) return KSI_INVALID_ARGUMENT;
	return ksi_TcpClient_setService(client, client->extender, host, port, user, pass);
}

int KSI_TcpClient_setAggregator(KSI_NetworkClient *client, const char *host, unsigned port, const char *user, const char *pass) {
	if (client == NULL || client->aggregator == NULL) return KSI_INVALID_ARGUMENT;
	return ksi_TcpClient_setService(client, client->aggregator, host, port, user, pass);
}

int KSI_TcpClient_setPublicationUrl(KSI_NetworkClient *client, const char *val) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TcpClient *tcp = NULL;

	if (client == NULL || val == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tcp = client->impl;

	res = KSI_HttpClient_setPublicationUrl(tcp->http, val);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_TcpClient_setTransferTimeoutSeconds (KSI_NetworkClient *client, int transferTimeoutSeconds ) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TcpClient *tcp = NULL;

	if (client == NULL || transferTimeoutSeconds < 0) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tcp = client->impl;

	tcp->transferTimeoutSeconds = transferTimeoutSeconds ;

	res = KSI_OK;

cleanup:

	return res;
}
