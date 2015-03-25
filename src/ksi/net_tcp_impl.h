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

#ifndef NET_TCP_INTERNAL_H_
#define NET_TCP_INTERNAL_H_

#include "internal.h"
#include "net_http.h"
#include "net_impl.h"
#include "net_http_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_TcpClient_st {
		KSI_NetworkClient parent;
		

		/* TODO: Is it required to be a signed int? */
		int transferTimeoutSeconds;
		
		char *aggrHost;
		unsigned aggrPort;

		char *extHost;
		unsigned extPort;

		int (*sendRequest)(KSI_NetworkClient *, KSI_RequestHandle *, char *host, unsigned port);
		KSI_HttpClient *http;
	};


#ifdef __cplusplus
}
#endif

#endif /* NET_HTTP_INTERNAL_H_ */
