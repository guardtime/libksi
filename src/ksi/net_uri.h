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

#ifndef KSI_NET_URI_H_
#define KSI_NET_URI_H_

#include "net.h"
#include "net_http.h"
#include "net_tcp.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct KSI_UriClient_st KSI_UriClient;

	/**
	 * Creates a new URI client.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	client		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_UriClient_new(KSI_CTX *ctx, KSI_UriClient **client);

	/**
	 * Initializes an existing URI client.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	client		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_UriClient_init(KSI_CTX *ctx, KSI_UriClient *client);

	/**
	 * Cleanup method for #KSI_UriClient.
	 * \param[in]	client	Pointer to the HTTP client.
	 */
	void KSI_UriClient_free(KSI_UriClient *client);


	/**
	 * Setter for the publications file URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Null-terminated URL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_UriClient_setPublicationUrl(KSI_UriClient *client, const char *val);

	int KSI_UriClient_setExtender(KSI_UriClient *client, const char *uri, const char *loginId, const char *key);
	int KSI_UriClient_setAggregator(KSI_UriClient *client, const char *uri, const char *loginId, const char *key);

	int KSI_UriClient_setTransferTimeoutSeconds(KSI_UriClient *client, int timeout);
	int KSI_UriClient_setConnectionTimeoutSeconds(KSI_UriClient *client, int timeout);

#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_CURL_H_ */
