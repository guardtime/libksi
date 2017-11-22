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
#include <sys/types.h>

#include "net_tcp.h"
#include "io.h"
#include "tlv.h"
#include "fast_tlv.h"

#include "internal.h"

#include "impl/ctx_impl.h"
#include "impl/net_http_impl.h"
#include "impl/net_tcp_impl.h"

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
#  pragma comment (lib, "Ws2_32.lib") /* Link with Ws2_32.lib. */
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
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	struct addrinfo *pr = NULL;
	size_t count;
	unsigned char buffer[0xffff + 4];
	KSI_FTLV ftlv;
#ifdef _WIN32
	DWORD transferTimeout = 0;
#else
	struct timeval  transferTimeout;
#endif
	char portStr[6];
	int rc;

	if (handle == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(handle->ctx);

#ifdef _WIN32
	if (handle->request_length > INT_MAX) {
		KSI_pushError(handle->ctx, res = KSI_BUFFER_OVERFLOW, "Unable to send more than MAX_INT bytes.");
		goto cleanup;
	}
#endif

	tcp = handle->implCtx;
	client = handle->client->impl;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = IPPROTO_TCP;

	KSI_snprintf(portStr, sizeof(portStr), "%u", tcp->port);
	if ((res = getaddrinfo(tcp->host, portStr, &hints, &result)) != 0) {
		KSI_ERR_push(handle->ctx, KSI_NETWORK_ERROR, res, __FILE__, __LINE__, gai_strerror(res));
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	for (pr = result; pr != NULL; pr = pr->ai_next) {
		if (pr->ai_protocol != IPPROTO_TCP) continue;

		sockfd = (int)socket(pr->ai_family, pr->ai_socktype, pr->ai_protocol);
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

#ifdef _WIN32
		KSI_SCK_TEMP_FAILURE_RETRY(rc, connect(sockfd, pr->ai_addr, (int)pr->ai_addrlen));
#else
		KSI_SCK_TEMP_FAILURE_RETRY(rc, connect(sockfd, pr->ai_addr, pr->ai_addrlen));
#endif
		if (rc == KSI_SCK_SOCKET_ERROR) {
			KSI_ERR_push(handle->ctx, res = KSI_NETWORK_ERROR, KSI_SCK_errno, __FILE__, __LINE__, "Unable to connect.");
			goto cleanup;
		}
		/* Succeedded to connect. */
		break;
	}
	if (pr == NULL) {
		KSI_pushError(handle->ctx, res = KSI_NETWORK_ERROR, "Unable to connect, no address succeeded.");
		goto cleanup;
	}

	KSI_LOG_logBlob(handle->ctx, KSI_LOG_DEBUG, "Sending request", handle->request, handle->request_length);
	count = 0;
	while (count < handle->request_length) {
		int c;

#ifdef _WIN32
		KSI_SCK_TEMP_FAILURE_RETRY(c, send(sockfd, (char *) handle->request + count, (int)(handle->request_length - count), 0));
#else
		KSI_SCK_TEMP_FAILURE_RETRY(c, send(sockfd, (char *) handle->request + count, handle->request_length - count, 0));
#endif
		if (c == KSI_SCK_SOCKET_ERROR) {
			KSI_ERR_push(handle->ctx, res = KSI_NETWORK_ERROR, KSI_SCK_errno, __FILE__, __LINE__, "Unable to write to socket.");
			goto cleanup;
		}
		count += c;
	}

	res = KSI_FTLV_socketRead(sockfd, buffer, sizeof(buffer), &count, &ftlv);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, "Failed to read TLV from socket.");
		goto cleanup;
	}
	if (count == 0) {
		KSI_pushError(handle->ctx, res = KSI_INVALID_FORMAT, "Unable to read TLV from socket.");
		goto cleanup;
	} else if(count > UINT_MAX){
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
	if (result) freeaddrinfo(result);
	if (sockfd >= 0) {
		KSI_SCK_TEMP_FAILURE_RETRY(rc, close(sockfd));
		if (rc == KSI_SCK_SOCKET_ERROR) {
			KSI_ERR_push(handle->ctx, res = KSI_IO_ERROR, KSI_SCK_errno, __FILE__, __LINE__, "Unable to close socket.");
		}
	}

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
	KSI_NetEndpoint *ext = NULL;

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
	if (endp == NULL || endp->host == NULL || endp->port == 0) {
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

	res = KSI_ExtendReq_enclose(req, ext->ksi_user, ext->ksi_pass, &pdu);
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

	(*handle)->reqCtx = (void*)KSI_ExtendReq_ref(req);
	(*handle)->reqCtx_free = (void (*)(void *))KSI_ExtendReq_free;

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
	KSI_NetEndpoint *aggr = NULL;

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
	if (endp == NULL || endp->host == NULL || endp->port == 0) {
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

	res = KSI_AggregationReq_enclose(req, aggr->ksi_user, aggr->ksi_pass, &pdu);
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

	(*handle)->reqCtx = (void*)KSI_AggregationReq_ref(req);
	(*handle)->reqCtx_free = (void (*)(void *))KSI_AggregationReq_free;

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
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
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
