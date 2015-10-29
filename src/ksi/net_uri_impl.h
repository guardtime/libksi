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
		KSI_NetworkClient *httpClient;
		KSI_NetworkClient *tcpClient;

		KSI_NetworkClient *pExtendClient;
		KSI_NetworkClient *pAggregationClient;
	};

#ifdef __cplusplus
}
#endif

#endif /* NET_URI_IMPL_H_ */
