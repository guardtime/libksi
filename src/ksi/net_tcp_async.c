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
#  define close(sock) closesocket(sock)
#  define poll WSAPoll
#  define ioctl ioctlsocket
#  define KSI_SCK_SOCKET_ERROR SOCKET_ERROR
#  define KSI_SCK_errno       WSAGetLastError()
#  define KSI_SCK_strerror(no) "n/a"
#  define KSI_SCK_ETIMEDOUT   WSAETIMEDOUT
#  define KSI_SCK_EAGAIN      WSAEWOULDBLOCK
#  define KSI_SCK_EWOULDBLOCK WSAEWOULDBLOCK
#  define KSI_SCK_EINPROGRESS WSAEINPROGRESS
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
#  define KSI_SCK_SOCKET_ERROR (-1)
#  define KSI_SCK_errno       (errno)
#  define KSI_SCK_strerror(no) strerror(no)
#  define KSI_SCK_ETIMEDOUT   ETIMEDOUT
#  define KSI_SCK_EAGAIN      EAGAIN
#  define KSI_SCK_EWOULDBLOCK EWOULDBLOCK
#  define KSI_SCK_EINPROGRESS EINPROGRESS
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
#include "net_async.h"

#define TCP_INVALID_SOCKET_FD (-1)
#define KSI_TLV_MAX_SIZE (0xffff + 4)
#define TCP_DEFAULT_TIMEOUT (KSI_ASYNC_DEFAULT_TIMEOUT_SEC)

static const int optSet = 1;
static const int optClr = 0;

typedef struct TcpClientCtx_st {
	KSI_CTX *ctx;
	/* Socket descriptor. */
	int sockfd;
	/* Output queue. */
	KSI_AsyncHandle *reqQueueFront;
	KSI_AsyncHandle *reqQueueBack;
	/* Input queue. */
	KSI_OctetStringList *respQueue;
	/* Input read buffer. */
	unsigned char inBuf[KSI_TLV_MAX_SIZE * 2];
	size_t inLen;

	/* Round throttling. */
	time_t roundStartAt;
	size_t roundCount;

	/* Connect timeout. */
	time_t connectedAt;
	bool socketReady;

	/* Poiter to the async options. */
	size_t *options;

	/* Endpoint data. */
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
			KSI_pushError(tcpCtx->ctx, res = KSI_NETWORK_ERROR, "Async TCP unable to open socket.");
			goto cleanup;
		}

		/* Set socket into non-blocking mode. */
		res = ioctl(tmpfd, FIONBIO, &nbMode);
		if (res == KSI_SCK_SOCKET_ERROR) {
			KSI_ERR_push(tcpCtx->ctx, res = KSI_IO_ERROR, KSI_SCK_errno, __FILE__, __LINE__, "Async TCP unable to set non-blocking mode.");
			goto cleanup;
		}

#ifdef _WIN32
		res = connect(tmpfd, pr->ai_addr, (int) pr->ai_addrlen);
#else
		res = connect(tmpfd, pr->ai_addr, pr->ai_addrlen);
#endif
		if (res == KSI_SCK_SOCKET_ERROR) {
			if (!(KSI_SCK_errno == KSI_SCK_EINPROGRESS || KSI_SCK_errno == KSI_SCK_EWOULDBLOCK)) {
				KSI_ERR_push(tcpCtx->ctx, res = KSI_NETWORK_ERROR, KSI_SCK_errno, __FILE__, __LINE__, "Async TCP unable to connect.");
				goto cleanup;
			}
		}
		time(&tcpCtx->connectedAt);

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

static void closeSocket(TcpAsyncCtx *tcpCtx, unsigned int lineNr) {
	if (tcpCtx != NULL) {
		KSI_LOG_debug(tcpCtx->ctx, "Async TCP close socket at: L%u", lineNr);

		/* Close socket */
		if (tcpCtx->sockfd != TCP_INVALID_SOCKET_FD) close(tcpCtx->sockfd);
		tcpCtx->sockfd = TCP_INVALID_SOCKET_FD;
		tcpCtx->socketReady = false;
		/* Clear input buffer. */
		tcpCtx->inLen = 0;
	}
}

static int reqQueue_getFront(TcpAsyncCtx *tcpCtx, KSI_AsyncHandle **r) {
	int res = KSI_UNKNOWN_ERROR;

	if (tcpCtx == NULL || r == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*r = tcpCtx->reqQueueFront;
	res = KSI_OK;
cleanup:
	return res;
}

static int reqQueue_popFront(TcpAsyncCtx *tcpCtx, KSI_AsyncHandle **r) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AsyncHandle *req = NULL;

	if (tcpCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	req = tcpCtx->reqQueueFront;

	tcpCtx->reqQueueFront = req->next;
	/* Check if this is the last element in queue. */
	if (req == tcpCtx->reqQueueBack) {
		tcpCtx->reqQueueBack = NULL;
	}

	if (r != NULL) {
		/* Return the popped value. */
		*r = req;
	} else {
		KSI_AsyncHandle_free(req);
	}
	res = KSI_OK;
cleanup:
	return res;
}

static int reqQueue_pushBack(TcpAsyncCtx *tcpCtx, KSI_AsyncHandle *r) {
	int res = KSI_UNKNOWN_ERROR;

	if (tcpCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (tcpCtx->reqQueueFront != NULL) {
		tcpCtx->reqQueueBack->next = r;
	} else {
		tcpCtx->reqQueueFront = r;
	}
	tcpCtx->reqQueueBack = r;
	res = KSI_OK;
cleanup:
	return res;
}

static void reqQueue_clearWithError(TcpAsyncCtx *tcpCtx, int err) {
	if (tcpCtx == NULL) return;

	while (tcpCtx->reqQueueFront) {
		KSI_AsyncHandle *req = tcpCtx->reqQueueFront;

		/* Update request state. */
		req->state = KSI_ASYNC_STATE_ERROR;
		req->err = err;

		reqQueue_popFront(tcpCtx, NULL);
	}
}


static int dispatch(TcpAsyncCtx *tcpCtx) {
	int res = KSI_UNKNOWN_ERROR;
	struct pollfd pfd;
	KSI_OctetString *resp = NULL;
	bool inputProcessed = true;

	if (tcpCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(tcpCtx->ctx);

	/* Check connection. */
	if (tcpCtx->sockfd == TCP_INVALID_SOCKET_FD) {
		/* Only open connection if there is anything in request queue. */
		if (tcpCtx->reqQueueFront == NULL) {
			KSI_LOG_debug(tcpCtx->ctx, "Async TCP connection not ready.");
			res = KSI_OK;
			goto cleanup;
		}

		res = openSocket(tcpCtx, &tcpCtx->sockfd);
		if (res != KSI_OK) {
			reqQueue_clearWithError(tcpCtx, res);
			closeSocket(tcpCtx, __LINE__);
			res = KSI_OK;
			goto cleanup;
		}
	}

	pfd.fd = tcpCtx->sockfd;
	pfd.events = POLLIN | POLLOUT;
	pfd.revents = 0;

	res = poll(&pfd, 1, 0);
	if (res == 0) {
		if (!tcpCtx->socketReady &&
					(tcpCtx->options[KSI_ASYNC_OPT_CON_TIMEOUT] == 0 ||
					(difftime(time(NULL), tcpCtx->connectedAt) > tcpCtx->options[KSI_ASYNC_OPT_CON_TIMEOUT]))) {
			closeSocket(tcpCtx, __LINE__);
			KSI_LOG_debug(tcpCtx->ctx, "Async TCP connection timeout.");
			reqQueue_clearWithError(tcpCtx, KSI_NETWORK_CONNECTION_TIMEOUT);
			res = KSI_OK;
		} else {
			KSI_LOG_debug(tcpCtx->ctx, "Async TCP connection not ready.");
			res = KSI_OK;
		}
		goto cleanup;
	} else if (res == KSI_SCK_SOCKET_ERROR) {
		closeSocket(tcpCtx, __LINE__);
		KSI_LOG_error(tcpCtx->ctx, "Async TCP failed to test socket. Error: %d (%s).", KSI_SCK_errno, KSI_SCK_strerror(KSI_SCK_errno));
		res = KSI_ASYNC_CONNECTION_CLOSED;
		goto cleanup;
	}
	tcpCtx->socketReady = true;

	/* Handle input. */
	do {
		if (pfd.revents & POLLIN) {
			inputProcessed = false;
			if ((tcpCtx->inLen + KSI_TLV_MAX_SIZE) <= sizeof(tcpCtx->inBuf)) {
				int c = 0;
				/* Read data from socket. */
				c = recv(tcpCtx->sockfd, (tcpCtx->inBuf + tcpCtx->inLen), KSI_TLV_MAX_SIZE, 0);
				if (c == 0) {
					/* Connection has been closed unexpectedly. */
					KSI_LOG_debug(tcpCtx->ctx, "Async TCP connection closed.");
					closeSocket(tcpCtx, __LINE__);
					res = KSI_ASYNC_CONNECTION_CLOSED;
					goto cleanup;
				} else if (c == KSI_SCK_SOCKET_ERROR) {
					if (KSI_SCK_errno == KSI_SCK_EWOULDBLOCK || KSI_SCK_errno == KSI_SCK_EAGAIN) {
						/* All data has been read out from socket. */
						inputProcessed = true;
					} else {
						/* Non-recoverable error has occurred. */
						KSI_LOG_error(tcpCtx->ctx,
									  "Async TCP closing connection. Unrecoverable error has occured: %d (%s).",
									  KSI_SCK_errno, KSI_SCK_strerror(KSI_SCK_errno));
						closeSocket(tcpCtx, __LINE__);
						res = KSI_ASYNC_CONNECTION_CLOSED;
						goto cleanup;
					}
				} else {
					tcpCtx->inLen += c;
					if (tcpCtx->inLen > sizeof(tcpCtx->inBuf)) {
						KSI_pushError(tcpCtx->ctx, res = KSI_BUFFER_OVERFLOW, "Too much data read from socket.");
						goto cleanup;
					}
				}
			} else {
				inputProcessed = true;
				KSI_LOG_debug(tcpCtx->ctx, "Async TCP input stream would not fit into buffer.");
			}
		}

		/* Handle read buffer. */
		while (tcpCtx->inLen > 0) {
			KSI_FTLV ftlv;
			size_t count = 0;

			/* Traverse through the input stream and verify that a complete TLV is present. */
			memset(&ftlv, 0, sizeof(KSI_FTLV));
			res = KSI_FTLV_memRead(tcpCtx->inBuf, tcpCtx->inLen, &ftlv);
			count = ftlv.hdr_len + ftlv.dat_len;
			/* Verify if the input byte stream is long enought for extacting a PDU. */
			if (count != 0 && tcpCtx->inLen >= count) {
				if (res != KSI_OK) {
					KSI_LOG_logBlob(tcpCtx->ctx, KSI_LOG_ERROR,
									"Async TCP closing connection. Unable to extract TLV from input stream",
									tcpCtx->inBuf, tcpCtx->inLen);
					closeSocket(tcpCtx, __LINE__);
					res = KSI_ASYNC_CONNECTION_CLOSED;
					goto cleanup;
				}
			} else {
				/* Do nothing. Not enought data received yet. */
				break;
			}

			if (count > UINT_MAX){
				KSI_pushError(tcpCtx->ctx, res = KSI_BUFFER_OVERFLOW, "Too much data read from socket.");
				goto cleanup;
			}

			KSI_LOG_logBlob(tcpCtx->ctx, KSI_LOG_DEBUG, "Async TCP received response", tcpCtx->inBuf, count);

			/* A complete PDU is in cache. Move it into the receive queue. */
			res = KSI_OctetString_new(tcpCtx->ctx, tcpCtx->inBuf, count, &resp);
			if (res != KSI_OK) {
				KSI_LOG_error(tcpCtx->ctx, "Async TCP unable to create new KSI_OctetString object. Error: 0x%x.", res);
				res = KSI_OK;
				goto cleanup;
			}

			res = KSI_OctetStringList_append(tcpCtx->respQueue, resp);
			if (res != KSI_OK) {
				KSI_LOG_error(tcpCtx->ctx, "Async TCP unable to add new response to queue. Error: 0x%x.", res);
				res = KSI_OK;
				goto cleanup;
			}
			resp = NULL;

			/* The response has been successfully moved to the input queue. Remove the data from the input stream. */
			tcpCtx->inLen -= count;
			memmove(tcpCtx->inBuf, tcpCtx->inBuf + count, tcpCtx->inLen);
		}
	} while (!inputProcessed);

	/* Handle output. */
	if (tcpCtx->reqQueueFront != NULL) {
		if (pfd.revents & POLLOUT) {
			do {
				KSI_AsyncHandle *req = NULL;
				time_t curTime = 0;

				/* Check if the request count can be restarted. */
				if (difftime(time(&curTime), tcpCtx->roundStartAt) >= KSI_ASYNC_ROUND_DURATION_SEC) {
					KSI_LOG_info(tcpCtx->ctx, "Async TCP round request count: %u", tcpCtx->roundCount);
					tcpCtx->roundCount = 0;
					tcpCtx->roundStartAt = curTime;
				}
				/* Check if more requests can be sent within the given timeframe. */
				if (!(tcpCtx->roundCount < tcpCtx->options[KSI_ASYNC_OPT_MAX_REQUEST_COUNT])) {
					KSI_LOG_debug(tcpCtx->ctx, "Async TCP round max request count reached.");
					break;
				}

				res = reqQueue_getFront(tcpCtx, &req);
				if (res != KSI_OK) {
					KSI_LOG_error(tcpCtx->ctx, "Async TCP unable to extract async handle from request queue. Error: 0x%x.", res);
					res = KSI_OK;
					goto cleanup;
				}

				if (req->state == KSI_ASYNC_STATE_WAITING_FOR_DISPATCH) {
					/* Verify that the send timeout has not elapsed. */
					if (tcpCtx->options[KSI_ASYNC_OPT_SND_TIMEOUT] == 0 ||
								(difftime(curTime, req->reqTime) > tcpCtx->options[KSI_ASYNC_OPT_SND_TIMEOUT])) {
						/* Set error. */
						req->state = KSI_ASYNC_STATE_ERROR;
						req->err = KSI_NETWORK_SEND_TIMEOUT;
						/* Just remove the request from the request queue. */
						reqQueue_popFront(tcpCtx, NULL);
					} else {
						KSI_LOG_logBlob(tcpCtx->ctx, KSI_LOG_DEBUG, "Sending request", req->raw, req->len);

						while (req->sentCount < req->len) {
							int c;
#ifdef _WIN32
							if (req->len - req->sentCount > INT_MAX) {
								c = send(tcpCtx->sockfd, (char *) req->raw + req->sentCount, (int) (INT_MAX), 0);
							} else {
								c = send(tcpCtx->sockfd, (char *) req->raw + req->sentCount, (int) (req->len - req->sentCount), 0);
							}
#else
							c = send(tcpCtx->sockfd, (char *) req->raw + req->sentCount, req->len - req->sentCount, 0);
#endif
							if (c == KSI_SCK_SOCKET_ERROR) {
								if (KSI_SCK_errno == KSI_SCK_EWOULDBLOCK || KSI_SCK_errno == KSI_SCK_EAGAIN) {
									KSI_LOG_info(tcpCtx->ctx,
											"Async TCP send would block. Bytes sent so far %d/%d. Error: %d (%s).",
											req->sentCount, req->len, KSI_SCK_errno, KSI_SCK_strerror(KSI_SCK_errno));
									goto cleanup;
								} else {
									closeSocket(tcpCtx, __LINE__);
									KSI_LOG_error(tcpCtx->ctx,
											"Async TCP closing connection. Unable to write to socket. Error: %d (%s).",
											KSI_SCK_errno, KSI_SCK_strerror(KSI_SCK_errno));
									res = KSI_ASYNC_CONNECTION_CLOSED;
									goto cleanup;
								}
							}
							req->sentCount += c;
						}

						if (req->sentCount == req->len) {
							tcpCtx->roundCount++;

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
							reqQueue_popFront(tcpCtx, NULL);
						}
					}
				} else {
					/* The state could have been changed in application layer. Just remove the request from the request queue. */
					reqQueue_popFront(tcpCtx, NULL);
				}

			} while (tcpCtx->reqQueueFront != NULL);
		} else {
			KSI_LOG_debug(tcpCtx->ctx, "Async TCP output buffer not ready.");
		}
	}

	res = KSI_OK;
cleanup:
	KSI_OctetString_free(resp);
	return res;
}

static int addToSendQueue(TcpAsyncCtx *tcpCtx, KSI_AsyncHandle *request) {
	int res = KSI_UNKNOWN_ERROR;

	if (tcpCtx == NULL || request == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	request->state = KSI_ASYNC_STATE_WAITING_FOR_DISPATCH;
	/* Start send timeout. */
	time(&request->reqTime);

	res = reqQueue_pushBack(tcpCtx, request);
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

static int getCredentials(TcpAsyncCtx *tcpCtx, const char **user, const char **pass) {
	if (tcpCtx == NULL) return KSI_INVALID_ARGUMENT;
	if (user != NULL) *user = tcpCtx->ksi_user;
	if (pass != NULL) *pass = tcpCtx->ksi_pass;
	return KSI_OK;
}

static void TcpAsyncCtx_free(TcpAsyncCtx *t) {
	if (t != NULL) {
		KSI_AsyncHandle *handle = t->reqQueueFront;
		while (handle) {
			KSI_AsyncHandle *next = handle->next;
			KSI_AsyncHandle_free(handle);
			handle = next;
		}
		KSI_OctetStringList_free(t->respQueue);
		if (t->sockfd != TCP_INVALID_SOCKET_FD) close(t->sockfd);
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
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	tmp->ctx = ctx;
	tmp->sockfd = TCP_INVALID_SOCKET_FD;

	tmp->reqQueueFront = NULL;
	tmp->reqQueueBack = NULL;
	tmp->respQueue = NULL;

	tmp->inLen = 0;

	tmp->ksi_user = NULL;
	tmp->ksi_pass = NULL;
	tmp->host = NULL;
	tmp->port = 0;

	tmp->socketReady = false;
	tmp->connectedAt = 0;
	tmp->roundStartAt = 0;
	tmp->roundCount = 0;

	/* Initialize io queues. */
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
	TcpAsyncCtx *netImpl = NULL;

	if (ctx == NULL || c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_AsyncClient_construct(ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	tmp->addRequest = (int (*)(void *, KSI_AsyncHandle *))addToSendQueue;
	tmp->getResponse = (int (*)(void *, KSI_OctetString **, size_t *))getResponse;
	tmp->dispatch = (int (*)(void *))dispatch;
	tmp->getCredentials = (int (*)(void *, const char **, const char **))getCredentials;


	res = TcpAsyncCtx_new(ctx, &netImpl);
	if (res != KSI_OK) goto cleanup;

	netImpl->options = tmp->options;

	tmp->clientImpl_free = (void (*)(void*))TcpAsyncCtx_free;
	tmp->clientImpl = netImpl;
	netImpl = NULL;

	*c = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	TcpAsyncCtx_free(netImpl);
	KSI_AsyncClient_free(tmp);

	return res;
}

int KSI_TcpAsyncClient_setService(KSI_AsyncClient *c, const char *host, unsigned port, const char *user, const char *pass) {
	if (c == NULL || c->clientImpl == NULL) return KSI_INVALID_ARGUMENT;
	return setService(c->clientImpl, host, port, user, pass);
}
