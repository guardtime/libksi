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
	KSI_ERR err;
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
	
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	tcp = handle->implCtx;
	client = (KSI_TcpClient*)handle->client;
	
    sockfd = (int)socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
    	KSI_FAIL(&err, KSI_NETWORK_ERROR, "Unable to open socket.");
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
    	KSI_FAIL(&err, KSI_NETWORK_ERROR, "Unable to open host.");
    	goto cleanup;
    }

	memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;

	memmove((char *)&serv_addr.sin_addr.s_addr, (char *)server->h_addr, server->h_length);

    serv_addr.sin_port = htons(tcp->port);

    if ((res = connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr))) < 0) {
    	KSI_FAIL_EXT(&err, KSI_NETWORK_ERROR, res, "Unable to connect.");
    	goto cleanup;
    }

    KSI_LOG_logBlob(handle->ctx, KSI_LOG_DEBUG, "Sending request", handle->request, handle->request_length);
    count = 0;
    while (count < handle->request_length) {
    	int c;
		c = send(sockfd, handle->request, handle->request_length, 0);
		if (c < 0) {
			KSI_FAIL(&err, KSI_NETWORK_ERROR, "Unable to write to socket.");
			goto cleanup;
		}
		count += c;
    }
	
    res = KSI_RDR_fromSocket(handle->ctx, sockfd, &rdr);
    KSI_CATCH(&err, res) goto cleanup;

    res = KSI_TLV_readTlv(rdr, buffer, sizeof(buffer), &count);
    if (res != KSI_OK || count == 0){
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "Unable to read TLV from socket.");
		goto cleanup;
	}

	handle->response = KSI_malloc(count);
	if (handle->response == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	memcpy(handle->response, buffer, count);
	handle->response_length = count;

	KSI_SUCCESS(&err);

cleanup:

	if (sockfd >= 0) close(sockfd);
	KSI_RDR_close(rdr);

	return KSI_RETURN(&err);
}

static int sendRequest(KSI_NetworkClient *client, KSI_RequestHandle *handle, char *host, unsigned port) {
	KSI_ERR err;
	int res;
	TcpClientCtx *tc = NULL;

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(handle->ctx, &err);

	tc = KSI_new(TcpClientCtx);
	if (tc == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	tc->host = NULL;
	tc->port = 0;

	KSI_LOG_debug(handle->ctx, "Tcp: Sending request to: %s:%u", host, port);

	tc->host = KSI_malloc(strlen(host) + 1);
	if (tc->host == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	KSI_strncpy(tc->host, host, strlen(host) + 1);
	tc->port = port;

	handle->readResponse = readResponse;
	handle->client = client;

    res = KSI_RequestHandle_setImplContext(handle, tc, (void (*)(void *))TcpClientCtx_free);
    KSI_CATCH(&err, res) goto cleanup;


	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int prepareRequest(
		KSI_NetworkClient *client,
		void *pdu,
		int (*serialize)(void *, unsigned char **, unsigned *),
		KSI_RequestHandle **handle,
		char *host,
		unsigned port,
		const char *desc) {
	KSI_ERR err;
	int res;
	KSI_TcpClient *tcp = (KSI_TcpClient *)client;
	KSI_RequestHandle *tmp = NULL;
	unsigned char *raw = NULL;
	unsigned raw_len = 0;
	int defaultAlgo = KSI_getHashAlgorithmByName("default");

	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_PRE(&err, pdu != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;
	KSI_BEGIN(client->ctx, &err);

	res = serialize(pdu, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logBlob(client->ctx, KSI_LOG_DEBUG, desc, raw, raw_len);

	/* Create a new request handle */
	res = KSI_RequestHandle_new(client->ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	if (tcp->sendRequest == NULL) {
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Send request not initialized.");
		goto cleanup;
	}

	res = tcp->sendRequest(client, tmp, host, port);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RequestHandle_free(tmp);
	KSI_free(raw);

	return KSI_RETURN(&err);
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

void KSI_TcpClient_free(KSI_TcpClient *tcp) {
	if (tcp != NULL) {
		KSI_free(tcp->aggrHost);
		KSI_free(tcp->extHost);
		KSI_HttpClient_free(tcp->http);
		KSI_free(tcp);
	}
}

/**
 *
 */
int KSI_TcpClient_init(KSI_CTX *ctx, KSI_TcpClient *client) {
	KSI_ERR err;

	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_NetworkClient_init(ctx, &client->parent);
	KSI_CATCH(&err, res) goto cleanup;

	client->sendRequest = sendRequest;
	client->aggrHost = NULL;
	client->aggrPort = 0;
	client->extHost = NULL;
	client->extPort = 0;
	client->http = NULL;
	
	client->transferTimeoutSeconds = 10;
	
	res = KSI_HttpClient_new(ctx, &client->http);
	KSI_CATCH(&err, res) goto cleanup;

	client->parent.sendExtendRequest = prepareExtendRequest;
	client->parent.sendSignRequest = prepareAggregationRequest;
	client->parent.sendPublicationRequest = sendPublicationRequest;
	client->parent.implFree = (void (*)(void *))KSI_TcpClient_free;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_TcpClient_new(KSI_CTX *ctx, KSI_TcpClient **tcp) {
	KSI_ERR err;
	int res;
	KSI_TcpClient *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_TcpClient);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = KSI_TcpClient_init(ctx, tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*tcp = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TcpClient_free(tmp);

	return KSI_RETURN(&err);
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
    KSI_ERR err;
	
	KSI_PRE(&err, client != NULL) goto cleanup;
	KSI_BEGIN(((KSI_NetworkClient*)client)->ctx, &err);
	
    client->transferTimeoutSeconds = transferTimeoutSeconds ;
    
	KSI_SUCCESS(&err);
	
cleanup:

	return KSI_RETURN(&err);
}
