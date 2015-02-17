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


#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_CURL_H_ */
