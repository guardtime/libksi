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

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment (lib, "Ws2_32.lib") /* Link with Ws2_32.lib. */
#  define close(soc) closesocket(soc)
#  define poll WSAPoll
#  define ioctl ioctlsocket
#  define socket_error WSAGetLastError()
#  define KSI_SOC_ETIMEDOUT   WSAETIMEDOUT
#  define KSI_SOC_EWOULDBLOCK WSAEWOULDBLOCK
#  define KSI_SOC_EINPROGRESS WSAEINPROGRESS
#else
#  include <unistd.h>
#  include <sys/socket.h>
#  include <sys/ioctl.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
# include <errno.h>
#  ifndef __USE_MISC
#    define __USE_MISC
#    include <netdb.h>
#    undef __USE_MISC
#  else
#    include <netdb.h>
#  endif
#  include <sys/time.h>
#  define socket_error errno
#  define KSI_SOC_ETIMEDOUT   ETIMEDOUT
#  define KSI_SOC_EWOULDBLOCK EWOULDBLOCK
#  define KSI_SOC_EINPROGRESS EINPROGRESS
#endif

#include "internal.h"
#include "net_http_impl.h"
#include "ctx_impl.h"
#include "net_tcp_impl.h"
#include "net_tcp.h"
#include "io.h"
#include "tlv.h"
#include "fast_tlv.h"
#include "types.h"

#define TCP_INVALID_SOCKET_FD (-1)

static const int optSet = 1;
static const int optClr = 0;

typedef struct TcpClientCtx_st {
	KSI_CTX *ctx;
	int sockfd;
	KSI_AsyncPayloadList *reqQueue;
	KSI_OctetStringList *respQueue;

	char *ksi_user;
	char *ksi_pass;
	char *host;
	unsigned port;
} TcpAsyncCtx;


static int openSocket(TcpAsyncCtx *tcpCtx, int *sockfd) {
	int res;
	int tmpfd = TCP_INVALID_SOCKET_FD;
	struct addrinfo hints;
	struct addrinfo *result = NULL;
	struct addrinfo *pr = NULL;
	char portStr[6];

	if (tcpCtx == NULL || sockfd == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(tcpCtx->ctx);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = IPPROTO_TCP;

	KSI_snprintf(portStr, sizeof(portStr), "%u", tcpCtx->port);
	res = getaddrinfo(tcpCtx->host, portStr, &hints, &result);
	if (res != 0) {
		KSI_ERR_push(tcpCtx->ctx, KSI_NETWORK_ERROR, res, __FILE__, __LINE__, gai_strerror(res));
		res = KSI_NETWORK_ERROR;
		goto cleanup;
	}

	for (pr = result; pr != NULL; pr = pr->ai_next) {
		unsigned nbMode = 1;

		if (pr->ai_protocol != IPPROTO_TCP) continue;

		tmpfd = (int)socket(pr->ai_family, pr->ai_socktype, pr->ai_protocol);
		if (tmpfd < 0) {
			KSI_pushError(tcpCtx->ctx, res = KSI_NETWORK_ERROR, "Unable to open socket.");
			goto cleanup;
		}

		/* Set socket into non-blocking mode. */
		res = ioctl(tmpfd, FIONBIO, &nbMode);
		if (res < 0) {
			KSI_pushError(tcpCtx->ctx, res = KSI_IO_ERROR, NULL);
			goto cleanup;
		}

#ifdef _WIN32
		res = connect(tmpfd, pr->ai_addr, (int) pr->ai_addrlen);
#else
		res = connect(tmpfd, pr->ai_addr, pr->ai_addrlen);
#endif
		if (res < 0) {
			if (!(socket_error == KSI_SOC_EINPROGRESS || socket_error == KSI_SOC_EWOULDBLOCK)) {
				KSI_ERR_push(tcpCtx->ctx, KSI_NETWORK_ERROR, socket_error, __FILE__, __LINE__, "Unable to connect.");
				res = KSI_NETWORK_ERROR;
				goto cleanup;
			}
		}

		/* Succeedded to connect. */
		break;
	}
	if (pr == NULL) {
		KSI_pushError(tcpCtx->ctx, res = KSI_NETWORK_ERROR, "Unable to connect, no address succeeded.");
		goto cleanup;
	}

	*sockfd = tmpfd;
	tmpfd = TCP_INVALID_SOCKET_FD;

	res = KSI_OK;

cleanup:
	if (result) freeaddrinfo(result);
	if (tmpfd >= 0) close(tmpfd);

	return res;
}

static int checkConnection(TcpAsyncCtx *tcpCtx) {
	int res = KSI_UNKNOWN_ERROR;

	if (tcpCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(tcpCtx->ctx);

	if (tcpCtx->sockfd < 0) {
		res = openSocket(tcpCtx, &tcpCtx->sockfd);
		if (res != KSI_OK) {
			KSI_pushError(tcpCtx->ctx, res, NULL);
			goto cleanup;
		}
	} else {
		struct pollfd pfd;

		pfd.fd = tcpCtx->sockfd;
		pfd.events = POLLIN;
		pfd.revents = 0;

		res = poll(&pfd, 1, 0);
		if (res < 0) {
			KSI_pushError(tcpCtx->ctx, res = KSI_IO_ERROR, "Failed to test socket.");
			goto cleanup;
		}

		if (pfd.revents & POLLIN) {
			unsigned char buffer[0xffff + 4];
			res = recv(tcpCtx->sockfd, buffer, sizeof(buffer), MSG_PEEK);
			if (res == 0) {
				tcpCtx->sockfd = TCP_INVALID_SOCKET_FD;
				KSI_pushError(tcpCtx->ctx, res = KSI_ASYNC_CONNECTION_CLOSED, "Server closed TCP connection.");
				goto cleanup;
			}
		}
	}

	res = KSI_OK;
cleanup:
	return res;
}

static int dispatch(TcpAsyncCtx *tcpCtx) {
	int res = KSI_UNKNOWN_ERROR;
	size_t count;
	struct pollfd pfd;
	KSI_OctetString *resp = NULL;

	if (tcpCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(tcpCtx->ctx);

	res = checkConnection(tcpCtx);
	if (res != KSI_OK) {
		KSI_pushError(tcpCtx->ctx, res, NULL);
		goto cleanup;
	}

	pfd.fd = tcpCtx->sockfd;
	pfd.events = POLLIN | POLLOUT;
	pfd.revents = 0;

	res = poll(&pfd, 1, 0);
	if (res == 0) {
		res = KSI_ASYNC_NOT_READY;
		goto cleanup;
	} else if (res < 0) {
		KSI_pushError(tcpCtx->ctx, res = KSI_IO_ERROR, "Failed to test socket.");
		goto cleanup;
	}


	/* Handle output. */
	if (KSI_AsyncPayloadList_length(tcpCtx->reqQueue) > 0) {
		if (pfd.revents & POLLOUT) {
			int sockOpt = 0;
			size_t len = sizeof(sockOpt);
			char dummy;

			/* Check whether the socket is ready. */
#ifdef _WIN32
			res = getsockopt(tcpCtx->sockfd, SOL_SOCKET, SO_ERROR, (char *) &sockOpt, (int *) &len);
#else
			res = getsockopt(tcpCtx->sockfd, SOL_SOCKET, SO_ERROR, &sockOpt, (socklen_t *) &len);
#endif
			if (res < 0) {
				KSI_pushError(tcpCtx->ctx, res = KSI_IO_ERROR, NULL);
				goto cleanup;
			}
			if (sockOpt == KSI_SOC_EINPROGRESS || sockOpt == KSI_SOC_EWOULDBLOCK) {
				res = KSI_ASYNC_NOT_READY;
				goto cleanup;
			}

			/* Clear TCP_NODELAY flag in order to accumulate outgoing request. */
#ifdef _WIN32
			setsockopt(tcpCtx->sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *) &optClr, (int) sizeof(optClr));
#else
			setsockopt(tcpCtx->sockfd, IPPROTO_TCP, TCP_NODELAY, &optClr, sizeof(optClr));
#endif

			do {
				KSI_AsyncPayload *req = NULL;

				res = KSI_AsyncPayloadList_elementAt(tcpCtx->reqQueue, 0, &req);
				if (res != KSI_OK) {
					KSI_pushError(tcpCtx->ctx, res, NULL);
					goto cleanup;
				}

				KSI_LOG_logBlob(tcpCtx->ctx, KSI_LOG_DEBUG, "Sending request", req->raw, req->len);

				count = 0;
				while (count < req->len) {
					int c;

#ifdef _WIN32
					if (req->len > INT_MAX) {
						KSI_pushError(tcpCtx->ctx, res = KSI_BUFFER_OVERFLOW, "Unable to send more than MAX_INT bytes.");
						goto cleanup;
					}
					c = send(tcpCtx->sockfd, (char *) req->raw + count, (int) (req->len - count), 0);
#else
					c = send(tcpCtx->sockfd, (char *) req->raw + count, req->len - count, 0);
#endif
					if (c < 0) {
						KSI_LOG_debug(tcpCtx->ctx, "Unable to write to socket.");
						break;
					}
					count += c;
				}

				if (count == req->len) {
					/* The request has been successfully dispatched. Remove it from the output queue. */
					res = KSI_AsyncPayloadList_remove(tcpCtx->reqQueue, 0, NULL);
					if (res != KSI_OK) {
						KSI_pushError(tcpCtx->ctx, res, NULL);
						goto cleanup;
					}
				}
			} while (KSI_AsyncPayloadList_length(tcpCtx->reqQueue));

			/* Set TCP_NODELAY flag to send the accumulated requests. */
#ifdef _WIN32
			setsockopt(tcpCtx->sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *) &optSet, (int) sizeof(optSet));
#else
			setsockopt(tcpCtx->sockfd, IPPROTO_TCP, TCP_NODELAY, &optSet, sizeof(optSet));
#endif
			/* Trigger send (required on some systems). */
			send(tcpCtx->sockfd, &dummy, 0, 0);
		} else {
			res = KSI_ASYNC_OUTPUT_BUFFER_FULL;
			goto cleanup;
		}
	}

	/* Handle intput. */
	if (pfd.revents & POLLIN) {
		unsigned char buffer[0xffff + 4];
		KSI_FTLV ftlv;

		res = KSI_FTLV_socketRead(tcpCtx->sockfd, buffer, sizeof(buffer), &count, &ftlv);
		if (res != KSI_OK || count == 0) {
			KSI_pushError(tcpCtx->ctx, res = KSI_INVALID_ARGUMENT, "Unable to read TLV from socket.");
			goto cleanup;
		}

		if(count > UINT_MAX){
			KSI_pushError(tcpCtx->ctx, res = KSI_BUFFER_OVERFLOW, "Too much data read from socket.");
			goto cleanup;
		}

		res = KSI_OctetString_new(tcpCtx->ctx, buffer, count, &resp);
		if (res != KSI_OK) {
			KSI_pushError(tcpCtx->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_OctetStringList_append(tcpCtx->respQueue, resp);
		if (res != KSI_OK) {
			KSI_pushError(tcpCtx->ctx, res, NULL);
			goto cleanup;
		}
		resp = NULL;
	}

	res = KSI_OK;
cleanup:
	KSI_OctetString_free(resp);
	return res;
}

static int addToSendQueue(TcpAsyncCtx *tcpCtx, KSI_AsyncPayload *request) {
	int res = KSI_UNKNOWN_ERROR;

	if (tcpCtx == NULL || tcpCtx->reqQueue == NULL || request == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_AsyncPayloadList_append(tcpCtx->reqQueue, request);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;
cleanup:
	return res;
}

static int getQueueStatus(TcpAsyncCtx *tcpCtx, size_t *reqQueueLen, size_t *respQueueLen) {
	if (tcpCtx == NULL) return KSI_INVALID_ARGUMENT;
	if (reqQueueLen != NULL) *reqQueueLen = KSI_AsyncPayloadList_length(tcpCtx->reqQueue);
	if (respQueueLen != NULL) *respQueueLen = KSI_OctetStringList_length(tcpCtx->respQueue);
	return KSI_OK;
}

static int isCompleted(TcpAsyncCtx *tcpCtx, KSI_AsyncHandle handle) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	for (i = 0; i < KSI_AsyncPayloadList_length(tcpCtx->reqQueue); i++) {
		KSI_AsyncPayload *req = NULL;

		res = KSI_AsyncPayloadList_elementAt(tcpCtx->reqQueue, i, &req);
		if (res != KSI_OK) goto cleanup;

		if (req->id == handle) {
			res = KSI_ASYNC_NOT_FINISHED;
			goto cleanup;
		}
	}
	res = KSI_ASYNC_COMPLETED;
cleanup:
	return res;
}

static int getResponse(TcpAsyncCtx *tcpCtx, KSI_OctetString **response) {
	int res = KSI_UNKNOWN_ERROR;
	size_t len = 0;
	KSI_OctetString *tmp = NULL;

	if (tcpCtx == NULL || tcpCtx->respQueue == NULL || response == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	len = KSI_OctetStringList_length(tcpCtx->respQueue);
	if (len == 0) {
		res = KSI_ASYNC_QUEUE_EMPTY;
		goto cleanup;
	}

	res = KSI_OctetStringList_remove(tcpCtx->respQueue, (len - 1), &tmp);
	if (res != KSI_OK) goto cleanup;

	*response = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_OctetString_free(tmp);
	return res;
}

static void closeSocket(TcpAsyncCtx *tcpCtx) {
	if (tcpCtx == NULL || tcpCtx->sockfd < 0) return;
	close(tcpCtx->sockfd);
	tcpCtx->sockfd = TCP_INVALID_SOCKET_FD;
}

static int reset(TcpAsyncCtx *tcpCtx) {
	int res = KSI_UNKNOWN_ERROR;

	if (tcpCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (tcpCtx->sockfd >= 0) closeSocket(tcpCtx);

	KSI_AsyncPayloadList_free(tcpCtx->reqQueue);
	tcpCtx->reqQueue = NULL;
	KSI_OctetStringList_free(tcpCtx->respQueue);
	tcpCtx->respQueue = NULL;

	res = KSI_AsyncPayloadList_new(&tcpCtx->reqQueue);
	if (res != KSI_OK) goto cleanup;
	res = KSI_OctetStringList_new(&tcpCtx->respQueue);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;
cleanup:
	return res;
}

static int setService(TcpAsyncCtx *tcpCtx, const char *host, unsigned port, const char *user, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;

	if (tcpCtx == NULL || host == NULL || user == NULL || pass == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (tcpCtx->host) KSI_free(tcpCtx->host);
	res = KSI_strdup(host, &tcpCtx->host);
	if (res != KSI_OK) goto cleanup;

	tcpCtx->port = port;

	if (tcpCtx->ksi_user) KSI_free(tcpCtx->ksi_user);
	res = KSI_strdup(user, &tcpCtx->ksi_user);
	if (res != KSI_OK) goto cleanup;

	if (tcpCtx->ksi_pass) KSI_free(tcpCtx->ksi_pass);
	res = KSI_strdup(pass, &tcpCtx->ksi_pass);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;
cleanup:
	return res;
}

static int getCredentials(TcpAsyncCtx *tcpCtx, const char **user, const char **pass) {
	if (tcpCtx == NULL || user == NULL || pass == NULL) return KSI_INVALID_ARGUMENT;
	*user = tcpCtx->ksi_user;
	*pass = tcpCtx->ksi_pass;
	return KSI_OK;
}

static void TcpAsyncCtx_free(TcpAsyncCtx *t) {
	if (t != NULL) {
		KSI_AsyncPayloadList_free(t->reqQueue);
		KSI_OctetStringList_free(t->respQueue);
		if (t->sockfd >= 0) close(t->sockfd);

		KSI_free(t->host);
		KSI_free(t->ksi_user);
		KSI_free(t->ksi_pass);

		KSI_free(t);
	}
}

static int TcpAsyncCtx_new(KSI_CTX *ctx, TcpAsyncCtx **tcpCtx) {
	int res = KSI_UNKNOWN_ERROR;
	TcpAsyncCtx *tmp = NULL;

	if (ctx == NULL || tcpCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_malloc(sizeof(TcpAsyncCtx));
	if (tcpCtx == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	tmp->ctx = ctx;
	tmp->sockfd = TCP_INVALID_SOCKET_FD;
	/* Queue */
	tmp->reqQueue = NULL;
	tmp->respQueue = NULL;
	/* Endpoint. */
	tmp->ksi_user = NULL;
	tmp->ksi_pass = NULL;
	tmp->host = NULL;
	tmp->port = 0;

	res = KSI_AsyncPayloadList_new(&tmp->reqQueue);
	if (res != KSI_OK) goto cleanup;
	res = KSI_OctetStringList_new(&tmp->respQueue);
	if (res != KSI_OK) goto cleanup;

	*tcpCtx = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	TcpAsyncCtx_free(tmp);
	return res;
}

int KSI_TcpAsyncClient_new(KSI_CTX *ctx, KSI_AsyncClient **c) {
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

	tmp->addRequest = (int (*)(void *, KSI_AsyncPayload *))addToSendQueue;
	tmp->getResponse = (int (*)(void *, KSI_OctetString **))getResponse;
	tmp->dispatch = (int (*)(void *))dispatch;
	tmp->closeConnection = (void (*)(void*))closeSocket;
	tmp->getQueueStatus = (int (*)(void *, size_t *, size_t *))getQueueStatus;
	tmp->isCompleted = (int (*)(void *, KSI_AsyncHandle))isCompleted;
	tmp->reset = (int (*)(void *))reset;
	tmp->getCredentials = (int (*)(void *, const char **, const char **))getCredentials;

	tmp->clientImpl_free = (void (*)(void*))TcpAsyncCtx_free;
	res = TcpAsyncCtx_new(ctx, (TcpAsyncCtx **)&tmp->clientImpl);
	if (res != KSI_OK) goto cleanup;

	*c = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_AsyncClient_free(tmp);

	return res;
}

int KSI_TcpAsyncClient_setService(KSI_AsyncClient *c, const char *host, unsigned port, const char *user, const char *pass) {
	if (c == NULL || c->clientImpl == NULL) return KSI_INVALID_ARGUMENT;
	return setService(c->clientImpl, host, port, user, pass);
}


