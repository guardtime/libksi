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

#ifndef KSI_NET_ASYNC_H_
#define KSI_NET_ASYNC_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \addtogroup asyncNetwork Network Interface (Asynchronous)
	 * The asynchronous API provides the ability to send KSI service requests in a non-blocking manner.
	 * As a drawback, it is not guaranteed that received responses are returned in the same order as the
	 * requests have been queued. However, you can associate each request with a private pointer.
	 * The interface incorporates two major parts:
	 * - #KSI_AsyncService takes care of network transport. Added request does not launch the transfer
	 * automatically. To initiate processing of added requests you have to call #KSI_AsyncService_run.
	 * - #KSI_AsyncHandle is a request wrapper. It is possible to add multiple handles to the #KSI_AsyncService
	 * at any time. A completed request (whether with a response, or an error status) can be accessed via
	 * #KSI_AsyncService_run input parameter \c handle.
	 * @{
	 */



	/**
	 * Async handle object resource cleanup method.
	 * \param[in]		o				Instance to be freed.
	 */
	void KSI_AsyncHandle_free(KSI_AsyncHandle *o);

	/**
	 * Constructor for the async handle object.
	 * \param[in]		ctx				KSI context.
	 * \param[in]		req				Aggregation request.
	 * \param[out]		o				Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The handle takes ownership of the \c req resource, thus it may not be freed after a successful
	 * call to this function.
	 */
	int KSI_AsyncAggregationHandle_new(KSI_CTX *ctx, KSI_AggregationReq *req, KSI_AsyncHandle **o);

	/**
	 * Constructor for the async handle object.
	 * \param[in]		ctx				KSI context.
	 * \param[in]		req				Extend request.
	 * \param[out]		o				Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The handle takes ownership of the provided request resource, thus they may not be freed after a successful
	 * call to this function.
	 * \see #KSI_AsyncService_addRequest for adding asynchronous request to the output queue.
	 * \see #KSI_AsyncHandle_getExtendResp for retrieving extend response.
	 */
	int KSI_AsyncExtendHandle_new(KSI_CTX *ctx, KSI_ExtendReq *req, KSI_AsyncHandle **o);

	/**
	 * Constructor for the async handle object for extending provided KSI signature.
	 * \param[in]		ctx				KSI context.
	 * \param[in]		sig				KSI signature to be extended.
	 * \param[in]		pubRec			Publication record (optional).
	 * \param[out]		o				Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The handle \c o will make copies of the resources, thus it is users responsibility to clean up input
	 * resources after a successful call to this function.
	 * \see #KSI_AsyncService_addRequest for adding asynchronous request to the output queue.
	 * \see #KSI_AsyncHandle_getExtendResp for retrieving extend response.
	 * \see #KSI_AsyncHandle_getSignature for retrieving an extended KSI signature.
	 */
	int KSI_AsyncExtendingHandle_new(KSI_CTX *ctx, const KSI_Signature *sig, const KSI_PublicationRecord *pubRec, KSI_AsyncHandle **o);

	KSI_DEFINE_REF(KSI_AsyncHandle);

	/**
	 * Setter for the request user private context.
	 * \param[in]		o				Async handle object.
	 * \param[in]		reqCtx			Request context.
	 * \param[in]		reqCtx_free		Pointer to the context cleanup method.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AsyncHandle_setRequestCtx(KSI_AsyncHandle *o, void *reqCtx, void (*reqCtx_free)(void*));

	/**
	 * Getter for the request specific context.
	 * \param[in]		o				Async handle object.
	 * \param[out]		reqCtx			Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AsyncHandle_getRequestCtx(const KSI_AsyncHandle *o, const void **reqCtx);

	/**
	 * Get the state of the request handle.
	 * \param[in]		h				Async handle.
	 * \param[out]		state			Payload state #KSI_AsyncHandleState
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncHandle_getError for reading error code.
	 * \see #KSI_AsyncHandle_getSignature for getting KSI signature.
	 */
	int KSI_AsyncHandle_getState(const KSI_AsyncHandle *h, int *state);

	/**
	 * Get the  error code for the request which state is #KSI_ASYNC_STATE_ERROR.
	 * \param[in]		h				Async handle.
	 * \param[out]		error			Handle error #KSI_StatusCode
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncHandle_getState for getting the state of the request.
	 */
	int KSI_AsyncHandle_getError(const KSI_AsyncHandle *h, int *error);

	/**
	 * Get the external error code for the request which state is #KSI_ASYNC_STATE_ERROR.
	 * \param[in]		h				Async handle.
	 * \param[out]		ext				Handle error message.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncHandle_getState for getting the state of the request.
	 */
	int KSI_AsyncHandle_getExtError(const KSI_AsyncHandle *h, long *ext);

	/**
	 * Get the error message for the request which state is #KSI_ASYNC_STATE_ERROR.
	 * \param[in]		h				Async handle.
	 * \param[out]		msg				Handle external error code.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncHandle_getState for getting the state of the request.
	 * \see #KSI_Utf8String_cstr for message stringification.
	 */
	int KSI_AsyncHandle_getErrorMessage(const KSI_AsyncHandle *h, KSI_Utf8String **msg);

	/**
	 * Get the request ID.
	 * \param[in]		h				Async handle.
	 * \param[out]		id				Request ID.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The value is only valid after a successful call to #KSI_AsyncService_addRequest.
	 * \see #KSI_AsyncService_addRequest for adding asynchronous request to the output queue.
	 */
	int KSI_AsyncHandle_getRequestId(const KSI_AsyncHandle *h, KSI_uint64_t *id);

	/**
	 * Getter for the aggregation request.
	 * \param[in]		h				Async handle.
	 * \param[out]		req				Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AsyncHandle_getAggregationReq(const KSI_AsyncHandle *h, KSI_AggregationReq **req);

	/**
	 * Getter for the extend request.
	 * \param[in]		h				Async handle.
	 * \param[out]		req				Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AsyncHandle_getExtendReq(const KSI_AsyncHandle *h, KSI_ExtendReq **req);

	/**
	 * Getter for the aggregation response.
	 * \param[in]		h				Async handle.
	 * \param[out]		resp			Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_SignatureBuilder_openFromAggregationResp for building a signature from aggregation response.
	 * \see #KSI_AsyncHandle_getSignature for getting a verified signature.
	 */
	int KSI_AsyncHandle_getAggregationResp(const KSI_AsyncHandle *h, KSI_AggregationResp **resp);

	/**
	 * Getter for the extend response.
	 * \param[in]		h				Async handle.
	 * \param[out]		resp			Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncHandle_getSignature for getting a verified signature.
	 */
	int KSI_AsyncHandle_getExtendResp(const KSI_AsyncHandle *h, KSI_ExtendResp **resp);

	/**
	 * KSI signature getter. The returned signature is verified internally.
	 * \param[in]		h				Async handle.
	 * \param[out]		signature		Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The returned resources must be freed by the caller.
	 * \note The signature will only be returned if the handle state is #KSI_ASYNC_STATE_RESPONSE_RECEIVED.
	 * \see #KSI_AsyncHandle_getState for getting the state of the request.
	 * \see #KSI_Signature_free for cleaning up returned resources.
	 */
	int KSI_AsyncHandle_getSignature(const KSI_AsyncHandle *h, KSI_Signature **signature);

	/**
	 * Server push configuration getter.
	 * \param[in]		h				Async handle.
	 * \param[out]		config			Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note A valid configuration will only be returned if the handle state is #KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED.
	 * \see #KSI_AsyncHandle_getState for getting the state of the request.
	 * \see #KSI_Config_free for cleaning up returned resources.
	 */
	int KSI_AsyncHandle_getConfig(const KSI_AsyncHandle *h, KSI_Config **config);

	/**
	 * Free async client object.
	 * \param[in]		c				Async client object.
	 * \note This will also handle termination of opened network connection.
	 * \see #KSI_TcpAsyncClient_new
	 * \see #KSI_HttpAsyncClient_new
	 */
	void KSI_AsyncClient_free(KSI_AsyncClient *c);

	/**
	 * Construct an abstract async client object.
	 * \param[in]		ctx				KSI context.
	 * \param[out]		c				Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AbstractAsyncClient_new(KSI_CTX *ctx, KSI_AsyncClient **c);


	/**
	 * Free async service object.
	 * \param[in]		service			Async serivce object.
	 */
	void KSI_AsyncService_free(KSI_AsyncService *service);

	/**
	 * Creates and initalizes a concrete async service object to be used to interract with aggregator endpoint.
	 * \param[in]		ctx				KSI context.
	 * \param[out]		service			Pointer to the receiving pointer.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncService_free
	 */
	int KSI_SigningAsyncService_new(KSI_CTX *ctx, KSI_AsyncService **service);

	int KSI_ExtendingAsyncService_new(KSI_CTX *ctx, KSI_AsyncService **service);

	/**
	 * Non-blocking aggregation request setter. All request are put into output queue untill, they are sent
	 * during #KSI_AsyncService_run call.
	 * \param[in]		s				Async service instance.
	 * \param[out]		handle			Async handle associated with the request.
	 * \return #KSI_OK, when operation succeeded;
	 * \return #KSI_ASYNC_REQUEST_CACHE_FULL, if the internal cache is full. In this case the
	 *         caller should wait for responses, or process received responses;
	 * \return otherwise an error code.
	 * \note The async service \c s takes ownership of \c req request on a successful call to this function, thus
	 *       the caller may not clear the memory.
	 * \see #KSI_SigningAsyncService_new for creating a new signing async service instance.
	 * \see #KSI_AsyncAggregationHandle_new for creating a new async request instance.
	 * \see #KSI_AsyncHandle_free for cleaning up resources in case of a failure.
	 * \see #KSI_AsyncService_run for handling communication towards service endpoint.
	 * \see #KSI_ASYNC_OPT_REQUEST_CACHE_SIZE for increasing the cache size.
	 */
	int KSI_AsyncService_addRequest(KSI_AsyncService *s, KSI_AsyncHandle *handle);

	/**
	 * Non-blocking send/receive worker. The method will open a connection to remote service, dispatch cached
	 * requests and map the received responses. The method has to be called multiple times in order for all
	 * request to be processed.
	 * \param[in]		service			Async service instance.
	 * \param[out]		handle			Async handle associated with a request.
	 * \param[out]		waiting			Total number of requests in process.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The \c waiting count can be ignored by setting it to NULL.
	 * \note The returned \c handle will be set to NULL if there is no response in queue.
	 * \see #KSI_AsyncService_addRequest for adding asynchronous request to the output queue.
	 * \see #KSI_AsyncHandle_getState for getting the state of the request.
	 * \see #KSI_AsyncService_getPendingCount for requests in process.
	 * \see #KSI_AsyncService_getReceivedCount for received responses.
	 */
	int KSI_AsyncService_run(KSI_AsyncService *service, KSI_AsyncHandle **handle, size_t *waiting);

	/**
	 * Enum defining async handle state.
	 */
	typedef enum KSI_AsyncHandleState_en {
		/** The state of the request is undefined. */
		KSI_ASYNC_STATE_UNDEFINED = 0,
		/** The request is cached in the output queue. */
		KSI_ASYNC_STATE_WAITING_FOR_DISPATCH,
		/** The request has been dispathed. */
		KSI_ASYNC_STATE_WAITING_FOR_RESPONSE,
		/**
		 * The response has been received and is ready to be read. This is the final state of a request.
		 * \see #KSI_AsyncHandle_getAggregationResp for extracting aggregation response.
		 * \see #KSI_AsyncHandle_getSignature for extracting KSI signature.
		 * \see #KSI_AsyncHandle_free for cleaning up resources.
		 */
		KSI_ASYNC_STATE_RESPONSE_RECEIVED,
		/**
		 * Push configuration has been received from the server. This is the final state of a request.
		 * \see #KSI_AsyncHandle_getConfig for extracting server configuration response.
		 * \see #KSI_AsyncHandle_free for cleaning up resources.
		 */
		KSI_ASYNC_STATE_PUSH_CONFIG_RECEIVED,
		/**
		 * An error has occured while the request was in process. This is the final state of a request.
		 * \see #KSI_AsyncHandle_getError for reading the error code.
		 * \see #KSI_AsyncHandle_free for cleaning up resources.
		 * \see #KSI_AsyncService_addRequest for re-adding the request back into the request queue.
		 */
		KSI_ASYNC_STATE_ERROR
	} KSI_AsyncHandleState;

	/**
	 * Get the number of requests that have been sent or are still in send queue.
	 * \param[in]		s				Async service instance.
	 * \param[out]		count			Pointer to the value.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AsyncService_getPendingCount(KSI_AsyncService *s, size_t *count);

	/**
	 * Get the number of request that have received a response and are ready to be extracted from async service \c s.
	 * \param[in]		s				Async service instance.
	 * \param[out]		count			Pointer to the value.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncService_run for extracting received responses.
	 */
	int KSI_AsyncService_getReceivedCount(KSI_AsyncService *s, size_t *count);

	/**
	 * Enum defining async service options. Pay attention to the used parameter type.
	 * \see #KSI_AsyncService_setOption for applying option values.
	 * \see #KSI_AsyncService_getOption for extracting option values.
	 */
	typedef enum KSI_AsyncOption_en {

		/**
		 * Async connection timeout. Time interval between when network connection has been initiated and
		 * the point it has been established.
		 * Default setting is 10 sec.
		 * \param		timeout			Timeout in seconds. Paramer of type size_t.
		 * \see #KSI_AsyncHandle_getState for the request state.
		 * \see #KSI_AsyncHandle_getError for the request error.
		 * \note In case of timeout, if there are any request that have not been responded yet, the request state
		 * will be set to #KSI_ASYNC_STATE_ERROR and error #KSI_NETWORK_CONNECTION_TIMEOUT.
		 */
		KSI_ASYNC_OPT_CON_TIMEOUT = 0,

		/**
		 * Async request response receive timeout. Represents the time interval between when the request
		 * was sent out and a response has been received.
		 * Default setting is 10 sec.
		 * \param		timeout			Timeout in seconds. Paramer of type size_t.
		 * \see #KSI_AsyncHandle_getState for the request state.
		 * \see #KSI_AsyncHandle_getError for the request error.
		 * \note In case of timeout the request state will be set to #KSI_ASYNC_STATE_ERROR
		 * and error to #KSI_NETWORK_RECIEVE_TIMEOUT.
		 */
		KSI_ASYNC_OPT_RCV_TIMEOUT,

		/**
		 * Async request send timeout. Represent the time interval between when the request has been added
		 * to the request queue and it has been sent out.
		 * Default setting is 10 sec.
		 * \param		timeout			Timeout in seconds. Paramer of type size_t.
		 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
		 * \see #KSI_AsyncHandle_getState for the request state.
		 * \see #KSI_AsyncHandle_getError for the request error.
		 * \note In case of timeout the request state will be set to #KSI_ASYNC_STATE_ERROR
		 * and error to #KSI_NETWORK_SEND_TIMEOUT.
		 */
		KSI_ASYNC_OPT_SND_TIMEOUT,

		/**
		 * Maximum parallel running request count. New value may not be less than the allready set value.
		 * Default setting is 1.
		 * \param		count			Paramer of type size_t.
		 * \see #KSI_AsyncService_addRequest for adding asynchronous request to the output queue.
		 */
		KSI_ASYNC_OPT_REQUEST_CACHE_SIZE,

		/**
		 * Maximum number of request permitted per round.
		 * Default setting is 1.
		 * \param		count			Paramer of type size_t.
		 * \note In case the maximum number of request is allready sent out during a round interval,
		 * additional request will be buffered in intenal cache.
		 */
		KSI_ASYNC_OPT_MAX_REQUEST_COUNT,

		__KSI_ASYNC_OPT_COUNT
	} KSI_AsyncOption;


	/**
	 * Async service option setter.
	 * \param[in]		s				Async service instance.
	 * \param[in]		option			Option to be updated from #KSI_AsyncOption.
	 * \param[in]		value			Option value as specified in #KSI_AsyncOption.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncOption defines supported options and parameter types.
	 * \see #KSI_AsyncService_getOption for extracting option values.
	 */
	int KSI_AsyncService_setOption(KSI_AsyncService *s, const KSI_AsyncOption option, void *value);

	/**
	 * Async service option getter.
	 * \param[in]		s				Async service instance.
	 * \param[in]		option			Option to be updated from #KSI_AsyncOption.
	 * \param[out]		value			Option value as specified in #KSI_AsyncOption.
	 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncOption defines supported options and parameter types.
	 * \see #KSI_AsyncService_setOption for applying option values.
	 */
	int KSI_AsyncService_getOption(const KSI_AsyncService *s, const KSI_AsyncOption option, void *value);

	/**
	 * @}
	 */

#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_ASYNC_H_ */
