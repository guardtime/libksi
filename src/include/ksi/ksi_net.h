#ifndef KSI_NET_H_
#define KSI_NET_H_

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \addtogroup network Network Interface
	 * This module contains two networking concepts used in this API:
	 * - Network provider (#KSI_NetProvider), this object takes care of network
	 * transtport.
	 * - Network handle (#KSI_NetHandle), this object contains a single request and
	 * is used to access the response.
	 * @{
	 */

	/**
	 * Free network handle object.
	 * \param[in]		handle			Network handle.
	 */
	void KSI_NetHandle_free(KSI_NetHandle *handle);

	/**
	 * Free network provider object.
	 * \param[in]		provider		Network provider.
	 */
	void KSI_NetProvider_free(KSI_NetProvider *provider);

	/**
	 * Sends a non-blocking signing request or initialize the handle.
	 * \param[in]		provider		Network provider.
	 * \param[in]		handle			Network handle.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetProvider_sendSignRequest(KSI_NetProvider *provider, KSI_NetHandle *handle);

	/**
	 * Sends a non-blocking extending request or initialize the handle.
	 * \param[in]		provider		Network provider.
	 * \param[in]		handle			Network handle.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetProvider_sendExtendRequest(KSI_NetProvider *provider, KSI_NetHandle *handle);

	/**
	 * Sends a non-blocking publicationsfile request or initialize the handle.
	 * \param[in]		provider		Network provider.
	 * \param[in]		handle			Network handle.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetProvider_sendPublicationsFileRequest(KSI_NetProvider *provider, KSI_NetHandle *handle);

	/**
	 * Setter for network request implementation context.
	 * \param[in]		handle			Network handle.
	 * \param[in]		netCtx			Network implementation context.
	 * \param[in]		netCtx_free		Cleanup method for the network context.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetHandle_setNetContext(KSI_NetHandle *handle, void *netCtx, void (*netCtx_free)(void *));

	/**
	 * Getter method for the network request implementation context.
	 * \param[in]		handle			Network handle.
	 * \param[out]		c				Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The caller may not free the output object.
	 */
	int KSI_NetHandle_getNetContext(KSI_NetHandle *handle, void **c);

	/**
	 * Getter for the request. The request can be set only while creating the network handle object
	 * (see #KSI_NetHandle_new).
	 *
	 * \param[in]		handle			Network handle.
	 * \param[out]		request			Pointer to the receiving pointer.
	 * \param[out]		request_len		Pointer to the reveiving length value.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output memory may not be freed by the caller.
	 */
	int KSI_NetHandle_getRequest(KSI_NetHandle *handle, const unsigned char **request, int *request_len);

	/**
	 * Response value setter. Should be called only by the actual network provider implementation.
	 * \param[in]		handle			Network handle.
	 * \param[in]		response		Pointer to the response.
	 * \param[in]		response_len	Response length.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The \c response memory may be freed after a successful call to this method, as the
	 * contents is copied internally.
	 */
	int KSI_NetHandle_setResponse(KSI_NetHandle *handle, const unsigned char *response, int response_len);

	/**
	 * A blocking function to read the response to the request. The function is blocking only
	 * for the first call on one handle. If the first call succeeds following calls output the
	 * same value.
	 * \param[in]		handle			Network handle.
	 * \param[out]		response		Pointer to the receiving response pointer.
	 * \param[out]		response_len	Pointer to the receiving response length value.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetHandle_getResponse(KSI_NetHandle *handle, const unsigned char **response, int *response_len);

	/**
	 * Constructor for network handle object.
	 * \param[in]		ctx				KSI context.
	 * \param[in]		request			Pointer to request.
	 * \param[in]		request_length	Lengt of the request.
	 * \param[out]		handle			Pointer to the receiving network handle pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The \c request value may be freed after a successful call to this function as
	 * its contents is copied internally.
	 */
	int KSI_NetHandle_new(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle);

	/**
	 * As network handles may be created by using several KSI contexts with different network providers and/or
	 * the network provider of a KSI context may be changed during runtime, it is necessary to state the function
	 * to be called to reveive the response.
	 * \param[in]		handle			Network handle.
	 * \param[in]		fn				Pointer to response reader function.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetHandle_setReadResponseFn(KSI_NetHandle *handle, int (*fn)(KSI_NetHandle *));

	/**
	 * Constructor for a new network provider.
	 * \param[in]		ctx				KSI context.
	 * \param[out]		provider		Pointer to the receiving network provider pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetProvider_new(KSI_CTX *ctx, KSI_NetProvider **provider);

	/**
	 * Setter for the implementation specific networking context.
	 * \param[in]		provider		Network provider.
	 * \param[in]		netCtx			Implementation specific context.
	 * \param[in]		netCtx_free		Pointer to the implementation specific network context cleanup method.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetProvider_setNetCtx(KSI_NetProvider *provider, void *netCtx, void (*netCtx_free)(void *));

	/**
	 * Getter for the implementation specific network context.
	 * \param[in]		provider		Network provider.
	 * \param[out]		netCtx			Pointer to the implementation specific network context.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetProvider_getNetContext(KSI_NetProvider *provider, void **netCtx);

	/**
	 * Setter for sign request function.
	 * \param[in]		provider		Network provider.
	 * \param[in]		fn				Pointer to sign request function.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetProvider_setSendSignRequestFn(KSI_NetProvider *provider, int (*fn)(KSI_NetProvider *, KSI_NetHandle *));

	/**
	 * Setter for sign request function.
	 * \param[in]		provider		Network provider.
	 * \param[in]		fn				Pointer to extend request function.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetProvider_setSendExtendRequestFn(KSI_NetProvider *provider, int (*fn)(KSI_NetProvider *, KSI_NetHandle *));

	/**
	 * Setter for sign request function.
	 * \param[in]		provider		Network provider.
	 * \param[in]		fn				Pointer to publicationsfile request function.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetProvider_setSendPublicationRequestFn(KSI_NetProvider *provider, int (*fn)(KSI_NetProvider *, KSI_NetHandle *));

	/**
	 * @}
	 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_H_ */
