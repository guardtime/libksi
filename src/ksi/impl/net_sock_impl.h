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

#ifndef NET_SOCK_INTERNAL_H_
#define NET_SOCK_INTERNAL_H_

#include <sys/types.h>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  pragma comment (lib, "Ws2_32.lib") /* Link with Ws2_32.lib. */
#else
#  ifndef __USE_GNU
#    define __USE_GNU
#    include <unistd.h>
#    undef __USE_GNU
#  else
#    include <unistd.h>
#  endif
#  include <sys/socket.h>
#  include <sys/ioctl.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <errno.h>
#  ifndef __USE_MISC
#    define __USE_MISC
#    include <netdb.h>
#    undef __USE_MISC
#  else
#    include <netdb.h>
#  endif
#  include <sys/time.h>
#endif

#ifdef _WIN32
#  define close(sock) closesocket(sock)
#  define poll WSAPoll
#  define ioctl ioctlsocket
#  define KSI_INVALID_SOCKET  INVALID_SOCKET
#  define KSI_SCK_SOCKET_ERROR SOCKET_ERROR
#  define KSI_SCK_errno       WSAGetLastError()
#  define KSI_SCK_strerror(no) ""
#  define KSI_SCK_ETIMEDOUT   WSAETIMEDOUT
#  define KSI_SCK_EAGAIN      WSAEWOULDBLOCK
#  define KSI_SCK_EWOULDBLOCK WSAEWOULDBLOCK
#  define KSI_SCK_EINPROGRESS WSAEINPROGRESS
#  define KSI_SCK_EINTR       WSAEINTR
#else
#  define KSI_INVALID_SOCKET  (-1)
#  define KSI_SCK_SOCKET_ERROR (-1)
#  define KSI_SCK_errno       (errno)
#  define KSI_SCK_strerror(no) strerror(no)
#  define KSI_SCK_ETIMEDOUT   ETIMEDOUT
#  define KSI_SCK_EAGAIN      EAGAIN
#  define KSI_SCK_EWOULDBLOCK EWOULDBLOCK
#  define KSI_SCK_EINPROGRESS EINPROGRESS
#  define KSI_SCK_EINTR       EINTR
#endif

#ifndef TEMP_FAILURE_RETRY
#  define KSI_SCK_TEMP_FAILURE_RETRY(res, exp) while ((res = exp) == KSI_SCK_SOCKET_ERROR && errno == KSI_SCK_EINTR)
#else
#  define KSI_SCK_TEMP_FAILURE_RETRY(res, exp) (res = TEMP_FAILURE_RETRY(exp))
#endif



#endif /* NET_SOCK_INTERNAL_H_ */
