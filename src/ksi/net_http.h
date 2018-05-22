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

#ifndef KSI_NET_HTTP_H_
#define KSI_NET_HTTP_H_

#include "net.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KSI_HttpClient_st KSI_HttpClient;


/**
 * Creates a new http client.
 * \param[in]	ctx			KSI context.
 * \param[out]	http		Pointer to the receiving pointer.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_HttpClient_new(KSI_CTX *ctx, KSI_NetworkClient **http);

/**
 * Creates a new http client.
 * \param[in]	ctx			KSI context.
 * \param[out]	http		Pointer to the receiving pointer.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_AbstractHttpClient_new(KSI_CTX *ctx, KSI_NetworkClient **http);

/**
 * Setter for the publications file URL. The value will be copied and thus
 * can be freed after successful call.
 * \param[in]	client		Pointer to the http client.
 * \param[in]	val			Null-terminated URL.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_HttpClient_setPublicationUrl(KSI_NetworkClient *client, const char *val);

/**
 * Setter for the connection timeout in seconds.
 * \param[in]	client		Pointer to the http client.
 * \param[in]	val			Timeout in seconds.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_HttpClient_setConnectTimeoutSeconds(KSI_NetworkClient *client, int val);

/**
 * Setter for the read timeout in seconds.
 * \param[in]	client		Pointer to the http client.
 * \param[in]	val			Timeout in seconds.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_HttpClient_setReadTimeoutSeconds(KSI_NetworkClient *client, int val);

/**
 * Setter for the http client extender parameters.
 * \param[in]	client		Pointer to http client.
 * \param[in]	url			Host name.
 * \param[in]	user		User name.
 * \param[in]	key			HMAC shared secret.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_HttpClient_setExtender(KSI_NetworkClient *client, const char *url, const char *user, const char *key);

/**
 * Setter for the http aggregator parameters.
 * \param[in]	client		Pointer to http client.
 * \param[in]	url			Host URL.
 * \param[in]	user		User name.
 * \param[in]	key			HMAC shared secret.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_HttpClient_setAggregator(KSI_NetworkClient *client, const char *url, const char *user, const char *key);


/**
 * Creates a new HTTP async client.
 * \param[in]	ctx			KSI context.
 * \param[out]	c			Pointer to the receiving pointer.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_AsyncClient_free
 * \see #KSI_HttpAsyncClient_setService
 */
int KSI_HttpAsyncClient_new(KSI_CTX *ctx, KSI_AsyncClient **c);

/**
 * Setter for the HTTP service endpoint parameters.
 * \param[in]	c			Pointer to tcp async client.
 * \param[in]	url			Host name.
 * \param[in]	user		User name.
 * \param[in]	pass		HMAC shared secret.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_HttpAsyncClient_new
 */
int KSI_HttpAsyncClient_setService(KSI_AsyncClient *c, const char *url, const char *user, const char *pass);

/**
 * Initialize HTTP implementation globals.
 * \param[in]	ctx			KSI context.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_Http_init(KSI_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_CURL_H_ */
