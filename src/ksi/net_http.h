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
	int KSI_HttpClient_new(KSI_CTX *ctx, KSI_HttpClient **http);

	/**
	 * Initialized an existing http client.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	http		Pointer to the HTTP client.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_init(KSI_CTX *ctx, KSI_HttpClient *http);

	/**
	 * Cleanup method for #KSI_HttpClient.
	 * \param[in]	http	Pointer to the HTTP client.
	 */
	void KSI_HttpClient_free(KSI_HttpClient *http);

	/**
	 * Implementation specific function for initializing.
	 * the HTTP client.
	 * \param[in]	http		Pointer to HTTP client.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClientImpl_init(KSI_HttpClient *http);

	/**
	 * Setter for the signer (aggregator) URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Null-terminated URL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	KSI_FN_DEPRECATED(int KSI_HttpClient_setSignerUrl(KSI_HttpClient *client, const char *val));

	/**
	 * Setter for the extender URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Null-terminated URL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	KSI_FN_DEPRECATED(int KSI_HttpClient_setExtenderUrl(KSI_HttpClient *client, const char *val));

	/**
	 * Setter for the publications file URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Null-terminated URL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_setPublicationUrl(KSI_HttpClient *client, const char *val);

	/**
	 * Setter for the connection timeout in seconds.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Timeout in seconds.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_setConnectTimeoutSeconds(KSI_HttpClient *client, int val);

	/**
	 * Setter for the read timeout in seconds.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Timeout in seconds.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_setReadTimeoutSeconds(KSI_HttpClient *client, int val);

	/**
	 * Setter for the http client extender parameters.
     * \param[in	client		Pointer to http client.
     * \param[in]	host		Host name.
     * \param[in]	port		Port number.
     * \param[in]	user		User name.
     * \param[in]	pass		Password.
     * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
     */
	int KSI_HttpClient_setExtender(KSI_HttpClient *client, const char *url, const char *user, const char *pass);
	
	/**
	 * Setter for the http aggregator parameters.
     * \param[in	client		Pointer to http client.
     * \param[in]	host		Host name.
     * \param[in]	port		Port number.
     * \param[in]	user		User name.
     * \param[in]	pass		Password.
     * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
     */
	int KSI_HttpClient_setAggregator(KSI_HttpClient *client, const char *url, const char *user, const char *pass);


#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_CURL_H_ */
