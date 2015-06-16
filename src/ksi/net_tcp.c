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

#ifndef _WIN32
#  include <unistd.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <netdb.h>
#else
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  define close(soc) closesocket(soc)
#endif

typedef struct TcpClientCtx_st {
	char *host;
	unsigned port;
} TcpClientCtx;

static void TcpClientCtx_free(TcpClientCtx *t) {
	if (t != NULL) {
		KSI_free(t->host);
		KSI_free(t);
	}
}

static int setStringParam(char **param, const char *val) {
	char *tmp = NULL;
	int res = KSI_UNKNOWN_ERROR;


	tmp = KSI_calloc(strlen(val) + 1, 1);
	if (tmp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	memcpy(tmp, val, strlen(val) + 1);

	if (*param != NULL) {
		KSI_free(*param);
	}

	*param = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);

	return res;
}

static int setIntParam(int *param, int val) {
	*param = val;
	return KSI_OK;
}

static int readResponse(KSI_RequestHandle *handle) {
	int res;
	TcpClientCtx *tcp = NULL;
	KSI_TcpClient *client = NULL;
	int sockfd = -1;
    struct sockaddr_in serv_addr;
    struct hostent *server = NULL;
    size_t count;
    unsigned char buffer[0xffff + 4];
    KSI_RDR *rdr = NULL;
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
	client = (KSI_TcpClient*)handle->client;

    sockfd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
    	KSI_pushError(handle->ctx, res = KSI_NETWORK_ERROR, "Unable to open socket.");
    	goto cleanup;
    }
#ifdef _WIN32
	transferTimeout = client->transferTimeoutSeconds*1000;
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

	memmove((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);

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
		c = send(sockfd, (char*)handle->request, handle->request_length, 0);
		if (c < 0) {
			KSI_pushError(handle->ctx, res = KSI_NETWORK_ERROR, "Unable to write to socket.");
			goto cleanup;
		}
		count += c;
    }

    res = KSI_RDR_fromSocket(handle->ctx, sockfd, &rdr);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}

    res = KSI_TLV_readTlv(rdr, buffer, sizeof(buffer), &count);
    if (res != KSI_OK || count == 0){
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
	handle->response_length = (unsigned)count;

	res = KSI_OK;

cleanup:

	if (sockfd >= 0) close(sockfd);
	KSI_RDR_close(rdr);

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

	tc->host = KSI_malloc(strlen(host) + 1);
	if (tc->host == NULL) {
		KSI_pushError(handle->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		TcpClientCtx_free(tc);
		goto cleanup;
	}
	KSI_strncpy(tc->host, host, strlen(host) + 1);
	tc->port = port;

	handle->readResponse = readResponse;
	handle->client = client;

    res = KSI_RequestHandle_setImplContext(handle, tc, (void (*)(void *))TcpClientCtx_free);
	if (res != KSI_OK) {
		KSI_pushError(handle->ctx, res, NULL);
		goto cleanup;
	}


	res = KSI_OK;

cleanup:

	return res;
}

static int prepareRequest(
		KSI_NetworkClient *client,
		void *pdu,
		int (*serialize)(void *, unsigned char **, unsigned *),
		KSI_RequestHandle **handle,
		char *host,
		unsigned port,
		const char *desc) {
	int res;
	KSI_TcpClient *tcp = (KSI_TcpClient *)client;
	KSI_RequestHandle *tmp = NULL;
	unsigned char *raw = NULL;
	unsigned raw_len = 0;

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

	res = KSI_ExtendReq_enclose(req, client->extUser, client->extPass, &pdu);
	if (res != KSI_OK) goto cleanup;


	res = prepareRequest(
			client,
			pdu,
			(int (*)(void *, unsigned char **, unsigned *))KSI_ExtendPdu_serialize,
			handle,
			((KSI_TcpClient*)client)->extHost,
			((KSI_TcpClient*)client)->extPort,
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

	res = KSI_AggregationReq_enclose(req, client->aggrUser, client->aggrPass, &pdu);
	if (res != KSI_OK) goto cleanup;

	res = prepareRequest(
			client,
			pdu,
			(int (*)(void *, unsigned char **, unsigned *))KSI_AggregationPdu_serialize,
			handle,
			((KSI_TcpClient*)client)->aggrHost,
			((KSI_TcpClient*)client)->aggrPort,
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
	KSI_TcpClient *tcpClient = (KSI_TcpClient *)client;

	res = KSI_NetworkClient_sendPublicationsFileRequest((KSI_NetworkClient *)tcpClient->http, handle);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static void tcpClient_free(KSI_TcpClient *tcp) {
	if (tcp != NULL) {
		KSI_free(tcp->aggrHost);
		KSI_free(tcp->extHost);
		KSI_HttpClient_free(tcp->http);
		KSI_free(tcp);
	}
}

void KSI_TcpClient_free(KSI_TcpClient *tcp) {
	KSI_NetworkClient_free((KSI_NetworkClient*)tcp);
}


/**
 *
 */
int KSI_TcpClient_init(KSI_CTX *ctx, KSI_TcpClient *client) {
	int res;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || client == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_NetworkClient_init(ctx, &client->parent);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	client->sendRequest = sendRequest;
	client->aggrHost = NULL;
	client->aggrPort = 0;
	client->extHost = NULL;
	client->extPort = 0;
	client->http = NULL;

	client->transferTimeoutSeconds = 10;

	res = KSI_HttpClient_new(ctx, &client->http);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	client->parent.sendExtendRequest = prepareExtendRequest;
	client->parent.sendSignRequest = prepareAggregationRequest;
	client->parent.sendPublicationRequest = sendPublicationRequest;
	client->parent.getStausCode = NULL;
	client->parent.implFree = (void (*)(void *))tcpClient_free;

	res = KSI_OK;

cleanup:

	return res;
}

/**
 *
 */
int KSI_TcpClient_new(KSI_CTX *ctx, KSI_TcpClient **tcp) {
	int res;
	KSI_TcpClient *tmp = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || tcp == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	tmp = KSI_new(KSI_TcpClient);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = KSI_TcpClient_init(ctx, tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*tcp = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TcpClient_free(tmp);

	return res;
}

int KSI_TcpClient_setExtender(KSI_TcpClient *client, const char *host, unsigned port, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;
	if (client == NULL || host == NULL || user == NULL || pass == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = setStringParam(&client->extHost, host);
	if (res != KSI_OK) goto cleanup;

	client->extPort = port;

	res = setStringParam(&client->parent.extUser, user);
	if (res != KSI_OK) goto cleanup;

	res = setStringParam(&client->parent.extPass, pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_TcpClient_setAggregator(KSI_TcpClient *client, const char *host, unsigned port, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;

	if (client == NULL || host == NULL || user == NULL || pass == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = setStringParam(&client->aggrHost, host);
	if (res != KSI_OK) goto cleanup;

	client->aggrPort = port;

	res = setStringParam(&client->parent.aggrUser, user);
	if (res != KSI_OK) goto cleanup;

	res = setStringParam(&client->parent.aggrPass, pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_TcpClient_setPublicationUrl(KSI_TcpClient *client, const char *val) {
	int res = KSI_UNKNOWN_ERROR;

	if (client == NULL || val == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_HttpClient_setPublicationUrl(client->http, val);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_TcpClient_setTransferTimeoutSeconds (KSI_TcpClient *client, int transferTimeoutSeconds ) {
	int res = KSI_UNKNOWN_ERROR;

	if (client == NULL || transferTimeoutSeconds < 0) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

    client->transferTimeoutSeconds = transferTimeoutSeconds ;

    res = KSI_OK;

cleanup:

	return res;
}
