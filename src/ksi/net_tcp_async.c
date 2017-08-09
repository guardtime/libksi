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
#  define KSI_SOC_error WSAGetLastError()
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
#  define KSI_SOC_error errno
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
#define KSI_TLV_MAX_SIZE (0xffff + 4)
#define TCP_DEFAULT_TIMEOUT 10

static const int optSet = 1;
static const int optClr = 0;

typedef struct TcpClientCtx_st {
	KSI_CTX *ctx;
	/* Socket descriptor. */
	int sockfd;
	/* Output queue. */
	KSI_AsyncPayloadList *reqQueue;
	/* Input queue. */
	KSI_OctetStringList *respQueue;
	/* Input read buffer. */
	unsigned char inBuf[KSI_TLV_MAX_SIZE * 2];
	size_t inLen;

	/* Round throttling. */
	time_t roundStartAt;
	size_t roundCount;
	size_t roundMaxCount;

	/* Endpoint data. */
	char *ksi_user;
	char *ksi_pass;
	char *host;
	unsigned port;

	/* Connect timeout. */
	size_t cTimeout;
	time_t conOpenAt;
	/* Send timeout. */
	size_t sTimeout;
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
			if (!(KSI_SOC_error == KSI_SOC_EINPROGRESS || KSI_SOC_error == KSI_SOC_EWOULDBLOCK)) {
				KSI_ERR_push(tcpCtx->ctx, KSI_NETWORK_ERROR, KSI_SOC_error, __FILE__, __LINE__, "Unable to connect.");
				res = KSI_NETWORK_ERROR;
				goto cleanup;
			}
		}
		time(&tcpCtx->conOpenAt);

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

static int clearReqQueueWithError(KSI_AsyncPayloadList *list, int err) {
	int res;

	while (KSI_AsyncPayloadList_length(list) > 0) {
		KSI_AsyncPayload *req = NULL;

		/* Get element from request queue. Remove from the end to avoid tail shift. */
		res = KSI_AsyncPayloadList_remove(list, KSI_AsyncPayloadList_length(list) - 1, &req);
		if (res != KSI_OK) goto cleanup;

		/* Update request state. */
		req->state = KSI_ASYNC_REQ_ERROR;
		req->error = err;

		/* Decrease payload ref count. */
		KSI_AsyncPayload_free(req);
	}
	res = KSI_OK;
cleanup:
	return res;
}

static int dispatch(TcpAsyncCtx *tcpCtx) {
	int res = KSI_UNKNOWN_ERROR;
	struct pollfd pfd;
	KSI_OctetString *resp = NULL;

	if (tcpCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(tcpCtx->ctx);

	/* Check connection. */
	if (tcpCtx->sockfd < 0) {
		/* Only open connection if there is anything in request queue. */
		if (KSI_AsyncPayloadList_length(tcpCtx->reqQueue) == 0) {
			KSI_LOG_debug(tcpCtx->ctx, "Async TCP connection not ready.");
			res = KSI_OK;
			goto cleanup;
		}

		res = openSocket(tcpCtx, &tcpCtx->sockfd);
		if (res != KSI_OK) {
			KSI_pushError(tcpCtx->ctx, res, NULL);
			clearReqQueueWithError(tcpCtx->reqQueue, res);
			goto cleanup;
		}
	}

	pfd.fd = tcpCtx->sockfd;
	pfd.events = POLLIN | POLLOUT;
	pfd.revents = 0;

	res = poll(&pfd, 1, 0);
	if (res == 0) {
		if (difftime(time(NULL), tcpCtx->conOpenAt) > tcpCtx->cTimeout) {
			KSI_LOG_debug(tcpCtx->ctx, "Async TCP connection timeout.");
			res = KSI_NETWORK_CONNECTION_TIMEOUT;
			clearReqQueueWithError(tcpCtx->reqQueue, res);
		} else {
			KSI_LOG_debug(tcpCtx->ctx, "Async TCP connection not ready.");
			res = KSI_OK;
		}
		goto cleanup;
	} else if (res < 0) {
		KSI_pushError(tcpCtx->ctx, res = KSI_IO_ERROR, "Failed to test socket.");
		clearReqQueueWithError(tcpCtx->reqQueue, res);
		goto cleanup;
	}

	/* Handle intput. */
	if (pfd.revents & POLLIN) {
		int c = 0;

		c = recv(tcpCtx->sockfd, (tcpCtx->inBuf + tcpCtx->inLen), KSI_TLV_MAX_SIZE, 0);
		if (c == 0) {
			/* Connection has been closed unexpectedly. */
			tcpCtx->sockfd = TCP_INVALID_SOCKET_FD;
			/* Clear input buffer. */
			tcpCtx->inLen = 0;
			KSI_LOG_debug(tcpCtx->ctx, "Async TCP connection closed.");
			res = KSI_ASYNC_CONNECTION_CLOSED;
			clearReqQueueWithError(tcpCtx->reqQueue, res);
			goto cleanup;
		} else if ((c < 0) && !(KSI_SOC_error == KSI_SOC_EINPROGRESS || KSI_SOC_error == KSI_SOC_EWOULDBLOCK)) {
			/* Non-recoverable error has occurred. */
			KSI_ERR_push(tcpCtx->ctx, res = KSI_NETWORK_ERROR, KSI_SOC_error, __FILE__, __LINE__, "Unable to receive data.");
			clearReqQueueWithError(tcpCtx->reqQueue, res);
			goto cleanup;
		} else {
			tcpCtx->inLen += c;
			if (tcpCtx->inLen > sizeof(tcpCtx->inBuf)) {
				KSI_pushError(tcpCtx->ctx, res = KSI_BUFFER_OVERFLOW, "Too much data read from socket.");
				goto cleanup;
			}
		}
	}
	/* Handle read buffer. */
	while (tcpCtx->inLen > 0) {
		KSI_FTLV ftlv;
		size_t count = 0;

		/* Read next response data from input cache. */
		res = KSI_FTLV_memRead(tcpCtx->inBuf, tcpCtx->inLen, &ftlv);
		count = ftlv.hdr_len + ftlv.dat_len;
		if (res != KSI_OK && (tcpCtx->inLen >= count)) {
			KSI_pushError(tcpCtx->ctx, res = KSI_INVALID_ARGUMENT, "Unable to read TLV.");
			goto cleanup;
		}

		/* Check whether there is enougth data on the input side. */
		if (count > tcpCtx->inLen) break;

		if (count > UINT_MAX){
			KSI_pushError(tcpCtx->ctx, res = KSI_BUFFER_OVERFLOW, "Too much data read from socket.");
			goto cleanup;
		}

		KSI_LOG_logBlob(tcpCtx->ctx, KSI_LOG_DEBUG, "TCP async received response", tcpCtx->inBuf, count);

		/* A complete PDU is in cache. Move it into the receive queue. */
		res = KSI_OctetString_new(tcpCtx->ctx, tcpCtx->inBuf, count, &resp);
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

		/* The response has been successfully moved to the input queue. Remove the data from the input cache. */
		tcpCtx->inLen -= count;
		memmove(tcpCtx->inBuf, tcpCtx->inBuf + count, tcpCtx->inLen);
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
				if (difftime(time(NULL), tcpCtx->conOpenAt) > tcpCtx->cTimeout) {
					KSI_LOG_debug(tcpCtx->ctx, "Async TCP connection timeout.");
					res = KSI_NETWORK_CONNECTION_TIMEOUT;
					clearReqQueueWithError(tcpCtx->reqQueue, res);
				} else {
					KSI_LOG_debug(tcpCtx->ctx, "Async TCP connection not ready.");
					res = KSI_OK;
				}
				goto cleanup;
			}

			/* Clear TCP_NODELAY flag in order to accumulate outgoing request. */
#ifdef _WIN32
			setsockopt(tcpCtx->sockfd, IPPROTO_TCP, TCP_NODELAY, (const char *) &optClr, (int) sizeof(optClr));
#else
			setsockopt(tcpCtx->sockfd, IPPROTO_TCP, TCP_NODELAY, &optClr, sizeof(optClr));
#endif

			do {
				const size_t at = 0;
				KSI_AsyncPayload *req = NULL;
				size_t count  = 0;

				/* Check if more requests can be sent within the given timeframe. */
				if (difftime(time(NULL), tcpCtx->roundStartAt) >= KSI_ASYNC_ROUND_DURATION_SEC) {
					tcpCtx->roundCount = 0;
					time(&tcpCtx->roundStartAt);
				}
				if (tcpCtx->roundCount >= tcpCtx->roundMaxCount) {
					KSI_LOG_debug(tcpCtx->ctx, "Async TCP round max request count reached.");
					break;
				}

				/* Send the requests in the same order as they have been cached. */
				res = KSI_AsyncPayloadList_elementAt(tcpCtx->reqQueue, at, &req);
				if (res != KSI_OK) {
					KSI_pushError(tcpCtx->ctx, res, NULL);
					goto cleanup;
				}

				if (req->state == KSI_ASYNC_REQ_WAITING_FOR_DISPATCH) {
					/* Verify that the send timeout has not elapsed. */
					if (difftime(time(NULL), req->reqTime) >= tcpCtx->sTimeout) {
						/* Set error. */
						req->state = KSI_ASYNC_REQ_ERROR;
						req->error = KSI_NETWORK_SEND_TIMEOUT;
						/* Just remove the request from the request queue. */
						res = KSI_AsyncPayloadList_remove(tcpCtx->reqQueue, at, NULL);
						if (res != KSI_OK) {
							KSI_pushError(tcpCtx->ctx, res, NULL);
							goto cleanup;
						}
					} else {
						KSI_LOG_logBlob(tcpCtx->ctx, KSI_LOG_DEBUG, "Sending request", req->raw, req->len);

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
							tcpCtx->roundCount++;

							req->state = KSI_ASYNC_REQ_WAITING_FOR_RESPONSE;
							/* Start receive timeout. */
							time(&req->sndTime);
							/* The request has been successfully dispatched. Remove it from the request queue. */
							res = KSI_AsyncPayloadList_remove(tcpCtx->reqQueue, at, NULL);
							if (res != KSI_OK) {
								KSI_pushError(tcpCtx->ctx, res, NULL);
								goto cleanup;
							}
						}
					}
				} else {
					/* The state could have been changed in upper layer. Just remove the request from the request queue. */
					res = KSI_AsyncPayloadList_remove(tcpCtx->reqQueue, at, NULL);
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
			KSI_LOG_debug(tcpCtx->ctx, "Async TCP output buffer not ready.");
		}
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

	request->state = KSI_ASYNC_REQ_WAITING_FOR_DISPATCH;
	/* Start send timeout. */
	time(&request->reqTime);

	res = KSI_AsyncPayloadList_append(tcpCtx->reqQueue, request);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;
cleanup:
	return res;
}

static int getResponse(TcpAsyncCtx *tcpCtx, KSI_OctetString **response, size_t *left) {
	int res = KSI_UNKNOWN_ERROR;
	size_t len = 0;
	KSI_OctetString *tmp = NULL;

	if (tcpCtx == NULL || tcpCtx->respQueue == NULL || response == NULL || left == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	len = KSI_OctetStringList_length(tcpCtx->respQueue);
	if (len != 0) {
		/* Get last from queue to avoid list element shift. */
		res = KSI_OctetStringList_remove(tcpCtx->respQueue, (len - 1), &tmp);
		if (res != KSI_OK) goto cleanup;
	}
	*response = tmp;
	tmp = NULL;
	*left = KSI_OctetStringList_length(tcpCtx->respQueue);

	res = KSI_OK;
cleanup:
	KSI_OctetString_free(tmp);
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

static int setConnectTimeout(TcpAsyncCtx *tcpCtx, const size_t timeout) {
	if (tcpCtx == NULL) return KSI_INVALID_ARGUMENT;
	tcpCtx->cTimeout = timeout;
	return KSI_OK;
}

static int setSendTimeout(TcpAsyncCtx *tcpCtx, const size_t timeout) {
	if (tcpCtx == NULL) return KSI_INVALID_ARGUMENT;
	tcpCtx->sTimeout = timeout;
	return KSI_OK;
}

static int setMaxRequestCount(TcpAsyncCtx *tcpCtx, const size_t count) {
	if (tcpCtx == NULL) return KSI_INVALID_ARGUMENT;
	tcpCtx->roundMaxCount = count;
	return KSI_OK;
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
	/* Queues */
	tmp->reqQueue = NULL;
	tmp->respQueue = NULL;
	/* Input cache. */
	tmp->inLen = 0;
	/* Endpoint. */
	tmp->ksi_user = NULL;
	tmp->ksi_pass = NULL;
	tmp->host = NULL;
	tmp->port = 0;
	/* Timeout. */
	tmp->cTimeout = TCP_DEFAULT_TIMEOUT;
	tmp->conOpenAt = 0;
	tmp->sTimeout = TCP_DEFAULT_TIMEOUT;

	tmp->roundStartAt = 0;
	tmp->roundCount = 0;
	tmp->roundMaxCount = KSI_ASYNC_DEFAULT_ROUND_MAX_COUNT;

	/* Initialize io queues. */
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

	tmp->requestCount = 0;
	tmp->tail = 1;
	tmp->maxParallelRequests = KSI_ASYNC_DEFAULT_PARALLEL_REQUESTS;
	tmp->reqCache = NULL;
	tmp->pending = 0;
	tmp->received = 0;
	tmp->rTimeout = TCP_DEFAULT_TIMEOUT;

	tmp->addRequest = (int (*)(void *, KSI_AsyncPayload *))addToSendQueue;
	tmp->getResponse = (int (*)(void *, KSI_OctetString **, size_t *))getResponse;
	tmp->dispatch = (int (*)(void *))dispatch;
	tmp->getCredentials = (int (*)(void *, const char **, const char **))getCredentials;
	tmp->setConnectTimeout = (int (*)(void *, const size_t))setConnectTimeout;
	tmp->setSendTimeout = (int (*)(void *, const size_t))setSendTimeout;
	tmp->setMaxRequestCount = (int (*)(void *, const size_t))setMaxRequestCount;

	tmp->reqCache = KSI_calloc(tmp->maxParallelRequests, sizeof(KSI_AsyncPayload *));
	if (tmp->reqCache == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

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


