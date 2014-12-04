#ifndef KSI_NET_H_
#define KSI_NET_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \addtogroup network Network Interface
	 * This module contains two networking concepts used in this API:
	 * - Network provider (#KSI_NetworkClient), this object takes care of network
	 * transtport.
	 * - Network handle (#KSI_RequestHandle), this object contains a single request and
	 * is used to access the response.
	 * @{
	 */

	/**
	 * Free network handle object.
	 * \param[in]		handle			Network handle.
	 */
	void KSI_RequestHandle_free(KSI_RequestHandle *handle);

	/**
	 * Free network provider object.
	 * \param[in]		provider		Network provider.
	 */
	void KSI_NetworkClient_free(KSI_NetworkClient *provider);

	/**
	 * Sends a non-blocking signing request or initialize the handle.
	 * \param[in]		provider		Network provider.
	 * \param[in]		request			Request object.
	 * \param[out]		handle			Network handle.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetworkClient_sendSignRequest(KSI_NetworkClient *provider, KSI_AggregationReq *request, KSI_RequestHandle **handle);

	/**
	 * Sends a non-blocking extending request or initialize the handle.
	 * \param[in]		provider		Network provider.
	 * \param[in]		request			Extend request.
	 * \param[in]		handle			Network handle.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetworkClient_sendExtendRequest(KSI_NetworkClient *provider, KSI_ExtendReq *request, KSI_RequestHandle **handle);

	/**
	 * Sends a non-blocking publicationsfile request or initialize the handle.
	 * \param[in]		provider		Network provider.
	 * \param[in]		handle			Network handle.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetworkClient_sendPublicationsFileRequest(KSI_NetworkClient *provider, KSI_RequestHandle *handle);

	/**
	 * Setter for network request implementation context.
	 * \param[in]		handle			Network handle.
	 * \param[in]		netCtx			Network implementation context.
	 * \param[in]		netCtx_free		Cleanup method for the network context.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_RequestHandle_setImplContext(KSI_RequestHandle *handle, void *netCtx, void (*netCtx_free)(void *));

	/**
	 * Getter method for the network request implementation context.
	 * \param[in]		handle			Network handle.
	 * \param[out]		c				Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The caller may not free the output object.
	 */
	int KSI_RequestHandle_getNetContext(KSI_RequestHandle *handle, void **c);

	/**
	 * Getter for the request. The request can be set only while creating the network handle object
	 * (\see #KSI_RequestHandle_new).
	 *
	 * \param[in]		handle			Network handle.
	 * \param[out]		request			Pointer to the receiving pointer.
	 * \param[out]		request_len		Pointer to the reveiving length value.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The output memory may not be freed by the caller.
	 */
	int KSI_RequestHandle_getRequest(KSI_RequestHandle *handle, const unsigned char **request, unsigned *request_len);

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
	int KSI_RequestHandle_setResponse(KSI_RequestHandle *handle, const unsigned char *response, unsigned response_len);

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
	int KSI_RequestHandle_getResponse(KSI_RequestHandle *handle, unsigned char **response, unsigned *response_len);

	/**
	 * TODO!
	 */
	int KSI_RequestHandle_getExtendResponse(KSI_RequestHandle *handle, KSI_ExtendResp **resp);

	/**
	 * TODO!
	 */
	int KSI_RequestHandle_getAggregationResponse(KSI_RequestHandle *handle, KSI_AggregationResp **resp);
	
	/**
	 * TODO!
	 */
	KSI_CTX *KSI_RequestHandle_getCtx (const KSI_RequestHandle *handle);
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
	int KSI_RequestHandle_new(KSI_CTX *ctx, const unsigned char *request, unsigned request_length, KSI_RequestHandle **handle);

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
	int KSI_RequestHandle_setReadResponseFn(KSI_RequestHandle *handle, int (*fn)(KSI_RequestHandle *));

	/**
	 * Constructor for a new plain network provider.
	 * \param[in]		ctx				KSI context.
	 * \param[out]		provider		Pointer to the receiving network provider pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note Do not use, unless implementing a new network client.
	 */
	int KSI_NetworkClient_new(KSI_CTX *ctx, KSI_NetworkClient **provider);

	/**
	 * Setter for the implementation specific networking context.
	 * \param[in]		provider		Network provider.
	 * \param[in]		netCtx			Implementation specific context.
	 * \param[in]		netCtx_free		Pointer to the implementation specific network context cleanup method.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetworkClient_setNetCtx(KSI_NetworkClient *provider, void *netCtx, void (*netCtx_free)(void *));

	/**
	 * Setter for sign request function.
	 * \param[in]		provider		Network provider.
	 * \param[in]		fn				Pointer to sign request function.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetworkClient_setSendSignRequestFn(KSI_NetworkClient *provider, int (*fn)(KSI_NetworkClient *, KSI_AggregationReq *, KSI_RequestHandle **));

	/**
	 * Setter for sign request function.
	 * \param[in]		provider		Network provider.
	 * \param[in]		fn				Pointer to extend request function.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_NetworkClient_setSendExtendRequestFn(KSI_NetworkClient *provider, int (*fn)(KSI_NetworkClient *, KSI_ExtendReq *, KSI_RequestHandle **));

	/**
	 * Setter for sign request function.
	 * \param[in]		provider		Network provider.
	 * \param[in]		fn				Pointer to publicationsfile request function.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_NetworkClient_setSendPublicationRequestFn(KSI_NetworkClient *provider, int (*fn)(KSI_NetworkClient *, KSI_RequestHandle *));

	int KSI_NetworkClient_setExtenderUser(KSI_NetworkClient *netProvider, const char *val);
	int KSI_NetworkClient_setExtenderPass(KSI_NetworkClient *netProvider, const char *val);
	int KSI_NetworkClient_setAggregatorUser(KSI_NetworkClient *netProvider, const char *val);
	int KSI_NetworkClient_setAggregatorPass(KSI_NetworkClient *netProvider, const char *val);
	
	int KSI_NetworkClient_getExtenderUser(const KSI_NetworkClient *netProvider, const char **val);
	int KSI_NetworkClient_getExtenderPass(const KSI_NetworkClient *netProvider, const char **val);
	int KSI_NetworkClient_getAggregatorUser(const KSI_NetworkClient *netProvider, const char **val);
	int KSI_NetworkClient_getAggregatorPass(const KSI_NetworkClient *netProvider, const char **val);
	/**
	 * @}
	 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_H_ */
