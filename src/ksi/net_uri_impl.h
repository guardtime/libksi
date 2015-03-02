/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#ifndef NET_URI_IMPL_H_
#define NET_URI_IMPL_H_

#include "net_http.h"
#include "net_tcp.h"
#include "net_impl.h"
#include "http_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

	enum client_e {
		URI_HTTP,
		URI_TCP,
		URI_CLIENT_COUNT
	};

	struct KSI_UriClient_st {
		KSI_NetworkClient parent;

		KSI_HttpClient *httpClient;
		KSI_TcpClient *tcpClient;

		KSI_NetworkClient *pExtendClient;
		KSI_NetworkClient *pAggregationClient;
	};

#ifdef __cplusplus
}
#endif

#endif /* NET_URI_IMPL_H_ */
