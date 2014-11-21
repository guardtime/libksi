#ifndef KSI_NET_HTTP_H_
#define KSI_NET_HTTP_H_

#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif
	/**
	 * Creates a new http client.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	client		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_new(KSI_CTX *ctx, KSI_NetworkClient **client);

	/**
	 * Setter for the signer (aggregator) URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Null-terminated URL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_setSignerUrl(KSI_NetworkClient *client, const char *val);

	/**
	 * Setter for the extender URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Null-terminated URL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_setExtenderUrl(KSI_NetworkClient *client, const char *val);

	/**
	 * Setter for the publications file URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Null-terminated URL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_setPublicationUrl(KSI_NetworkClient *client, const char *val);

	/**
	 * Setter for the connetion timeout in seconds.
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
	 * Initializes an existing http client.
	 * \param[in]	client		Ponter to http client.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_init(KSI_NetworkClient *client);

#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_CURL_H_ */
