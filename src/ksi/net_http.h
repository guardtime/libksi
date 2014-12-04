#ifndef KSI_NET_HTTP_H_
#define KSI_NET_HTTP_H_

#include "net.h"

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
	 * Cleanup method for #KSI_HttpClient.
	 * \param[in]	http	Pointer to the HTTP client.
	 */
	void KSI_HttpClient_free(KSI_HttpClient *http);

	/**
	 * Setter for the signer (aggregator) URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Null-terminated URL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_setSignerUrl(KSI_HttpClient *client, const char *val);

	/**
	 * Setter for the extender URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Null-terminated URL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_setExtenderUrl(KSI_HttpClient *client, const char *val);

	/**
	 * Setter for the publications file URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Null-terminated URL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HttpClient_setPublicationUrl(KSI_HttpClient *client, const char *val);

	/**
	 * Setter for the connetion timeout in seconds.
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

#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_CURL_H_ */
