#ifndef KSI_NET_TCP_H_
#define KSI_NET_TCP_H_

#include "net.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct KSI_TcpClient_st KSI_TcpClient;

	/**
	 * Creates a new TCP client.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	client		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TcpClient_new(KSI_CTX *ctx, KSI_TcpClient **client);

	/**
	 * Initializes an existing TCP client.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	client		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TcpClient_init(KSI_CTX *ctx, KSI_TcpClient *client);

	/**
	 * Cleanup method for #KSI_HttpClient.
	 * \param[in]	client	Pointer to the HTTP client.
	 */
	void KSI_TcpClient_free(KSI_TcpClient *client);


	/**
	 * Setter for the publications file URL. The value will be copied and thus
	 * can be freed after successful call.
	 * \param[in]	client		Pointer to the http client.
	 * \param[in]	val			Null-terminated URL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TcpClient_setPublicationUrl(KSI_TcpClient *client, const char *val);

	
	/**
	 * Setter for the tcp client extender parameters.
     * \param[in	client		Pointer to tcp client.
     * \param[in]	host		Host name.
     * \param[in]	port		Port number.
     * \param[in]	user		User name.
     * \param[in]	pass		Password.
     * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
     */
	int KSI_TcpClient_setExtender(KSI_TcpClient *client, const char *host, unsigned port, const char *user, const char *pass);
	
	/**
	 * Setter for the tcp aggregator parameters.
     * \param[in	client		Pointer to tcp client.
     * \param[in]	host		Host name.
     * \param[in]	port		Port number.
     * \param[in]	user		User name.
     * \param[in]	pass		Password.
     * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
     */
	int KSI_TcpClient_setAggregator(KSI_TcpClient *client, const char *host, unsigned port, const char *user, const char *pass);
	
	/**
	 * Setter for the read, write, timeout in seconds.
	 * \param[in]	client		Pointer to the tcp client.
	 * \param[in]	val			Timeout in seconds.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_TcpClient_setTransferTimeoutSeconds(KSI_TcpClient *client, int transferTimeoutSeconds);

#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_CURL_H_ */
