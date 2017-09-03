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
	 * \addtogroup asyncNetwork Network interface (asynchronous).
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
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The handle takes ownership of the \c req resource, thus it may not be freed after a successful
	 * call to this function.
	 */
	int KSI_AsyncAggregationHandle_new(KSI_CTX *ctx, KSI_AggregationReq *req, KSI_AsyncHandle **o);

	KSI_DEFINE_REF(KSI_AsyncHandle);

	/**
	 * Setter for the request user private context.
	 * \param[in]		o				Async handle object.
	 * \param[in]		reqCtx			Request context.
	 * \param[in]		reqCtx_free		Pointer to the context cleanup method.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AsyncHandle_setRequestCtx(KSI_AsyncHandle *o, void *reqCtx, void (*reqCtx_free)(void*));

	/**
	 * Getter for the request specific context.
	 * \param[in]		o				Async handle object.
	 * \param[out]		reqCtx			Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AsyncHandle_getRequestCtx(const KSI_AsyncHandle *o, const void **reqCtx);

	/**
	 * Get the state of the request handle.
	 * \param[in]		h				Async handle.
	 * \param[out]		state			Payload state #KSI_AsyncHandleState_en
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncHandle_getError for reading error code.
	 */
	int KSI_AsyncHandle_getState(const KSI_AsyncHandle *h, int *state);

	/**
	 * Get the error code for the request which state is #KSI_ASYNC_STATE_ERROR.
	 * \param[in]		h				Async handle.
	 * \param[out]		error			Payload error #KSI_StatusCode
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncHandle_getState for getting the state of the request.
	 */
	int KSI_AsyncHandle_getError(const KSI_AsyncHandle *h, int *error);

	/**
	 * Getter for the aggregation response
	 * \param[in]		h				Async handle.
	 * \param[out]		resp			Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AsyncHandle_getAggregationResp(const KSI_AsyncHandle *h, KSI_AggregationResp **resp);

	/**
	 * Free async client object.
	 * \param[in]		c				Async client object.
	 * \see #KSI_TcpAsyncClient_new
	 * \note This will also handle termination of open network connection.
	 */
	void KSI_AsyncClient_free(KSI_AsyncClient *c);

	/**
	 * Free async service object.
	 * \param[in]		service			Async serivce object.
	 */
	void KSI_AsyncService_free(KSI_AsyncService *service);

	/**
	 * Creates and initalizes a concrete async service object to be used to interract with aggregator endpoint.
	 * \param[in]		ctx				KSI context.
	 * \param[out]		service			Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncService_free
	 */
	int KSI_SigningAsyncService_new(KSI_CTX *ctx, KSI_AsyncService **service);

	/**
	 * Non-blocking aggregation request setter. All request are put into output queue untill.
	 * The request are sent during #KSI_AsyncService_run call.
	 * \param[in]		s				Async service instance.
	 * \param[in]		req				Aggregation request.
	 * \param[out]		handle			Async handle associated with the request.
	 * \return #KSI_OK, when operation succeeded;
	 * \return #KSI_ASYNC_MAX_PARALLEL_COUNT_REACHED, if the internal cache is full. In this case the
	 *         caller should wait for responses, or process received responses;
	 * \return otherwise an error code.
	 * \note The async service \c s takes ownership of \c req request on a successful call to this function, thus
	 *       the caller may not clear the memory.
	 * \see #KSI_SigningAsyncService_new for creating a new signing async service instance.
	 * \see #KSI_AsyncAggregationHandle_new for creating a new async request instance.
	 * \see #KSI_AsyncRequest_free for cleaning up resources in case of a failure.
	 * \see #KSI_AsyncService_run for handling communication towards service endpoint.
	 * \see #KSI_AsyncService_setMaxParallelRequests for increasing the internal cache.
	 */
	int KSI_AsyncService_addRequest(KSI_AsyncService *s, KSI_AsyncHandle *handle);

	/**
	 * Non-blocking send/receive worker. The method will open a connection to remote service, dispatch cached
	 * requests and map the received responses. The method has to be called multiple times in order for all
	 * request to be processed.
	 * \param[in]		service			Async service instance.
	 * \param[out]		handle			Async handle associated with a request.
	 * \param[out]		waiting			Total number of requests in process.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The \c waiting count can be ignored by setting it to NULL.
	 * \note The returned \c handle will be set to #KSI_ASYNC_HANDLE_NULL if there is no response in queue.
	 * \see #KSI_AsyncService_addRequest for adding asynchronous request to the output queue.
	 * \see #KSI_AsyncHandle_getState for getting the state of the request.
	 * \see #KSI_AsyncService_getPendingCount for requests in process.
	 * \see #KSI_AsyncService_getReceivedCount for received responses.
	 */
	int KSI_AsyncService_run(KSI_AsyncService *service, KSI_AsyncHandle **handle, size_t *waiting);

	/**
	 * Enum defining async handle state.
	 */
	enum KSI_AsyncHandleState_en {
		/** The state of the request is undefined. */
		KSI_ASYNC_STATE_UNDEFINED = 0,
		/** The request is cached in the output queue. */
		KSI_ASYNC_STATE_WAITING_FOR_DISPATCH,
		/** The request has been dispathed */
		KSI_ASYNC_STATE_WAITING_FOR_RESPONSE,
		/**
		 * A response has been received and ready to be read. This is final state of a request.
		 * \see #KSI_AsyncHandle_getAggregationResp for extracting aggregation response.
		 * \see #KSI_AsyncHandle_free for cleaning up resources.
		 */
		KSI_ASYNC_STATE_RESPONSE_RECEIVED,
		/**
		 * An error has occured while the request was in process. This is final state of a request.
		 * \see #KSI_AsyncHandle_getError for reading the error code.
		 * \see #KSI_AsyncHandle_free for cleaning up resources.
		 * \see #KSI_AsyncService_addRequest for readding the request back into the request queue.
		 */
		KSI_ASYNC_STATE_ERROR
	};

	/**
	 * Get the number of request that have been sent, or still in send queue.
	 * \param[in]		s				Async serice instance.
	 * \param[out]		count			Pointer to the value.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AsyncService_getPendingCount(KSI_AsyncService *s, size_t *count);

	/**
	 * Get the number of request that have received a response.
	 * \param[in]		s				Async serice instance.
	 * \param[out]		count			Pointer to the value.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AsyncService_getReceivedCount(KSI_AsyncService *s, size_t *count);

#define KSI_ASYNC_DEFAULT_ROUND_MAX_COUNT   (1 << 3)
#define KSI_ASYNC_DEFAULT_PARALLEL_REQUESTS (1 << 10)
#define KSI_ASYNC_ROUND_DURATION_SEC 1

	/**
	 * Set maximum parallel running request count. The \c count may not be less than the previously set value.
	 * Default value is #KSI_ASYNC_DEFAULT_PARALLEL_REQUESTS
	 * \param[in]		service			Async serice instance.
	 * \param[in]		count			Value to be applied.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AsyncService_setMaxParallelRequests(KSI_AsyncService *service, size_t count);

	/**
	 * Setter for the async connection timeout.
	 * \param[in]		service			Async serice instance.
	 * \param[in]		value			Timeout in seconds.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncHandle_getState for the request state.
	 * \see #KSI_AsyncHandle_getError for the request error.
	 * \note In case of timeout and there are any request that have not been responded yet, the request state
	 * will be set to #KSI_ASYNC_STATE_ERROR and error #KSI_NETWORK_CONNECTION_TIMEOUT.
	 */
	int KSI_AsyncService_setConnectTimeout(KSI_AsyncService *service, const size_t value);

	/**
	 * Setter for the async request response receive timeout.
	 * \param[in]		service			Async serice instance.
	 * \param[in]		value			Timeout in seconds.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncHandle_getState for the request state.
	 * \see #KSI_AsyncHandle_getError for the request error.
	 * \note In case of timeout the request state will be set to #KSI_ASYNC_STATE_ERROR
	 * and error to #KSI_NETWORK_RECIEVE_TIMEOUT
	 */
	int KSI_AsyncService_setReceiveTimeout(KSI_AsyncService *service, const size_t value);

	/**
	 * Setter for the async request send timeout.
	 * \param[in]		service			Async serice instance.
	 * \param[in]		value			Timeout in seconds.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_AsyncHandle_getState for the request state.
	 * \see #KSI_AsyncHandle_getError for the request error.
	 * \note In case of timeout the request state will be set to #KSI_ASYNC_STATE_ERROR
	 * and error to #KSI_NETWORK_SEND_TIMEOUT
	 */
	int KSI_AsyncService_setSendTimeout(KSI_AsyncService *service, const size_t value);

	/**
	 * Setter for the maximum number of request permitted per round.
	 * \param[in]		service			Async serice instance.
	 * \param[in]		value			Maximum request count.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_ASYNC_ROUND_DURATION_SEC defines the round time interval.
	 * \see #KSI_AsyncService_addRequest for adding asynchronous request to the output queue.
	 * \note In case the maximum number of request is allready sent out during a round interval,
	 * additional request will be buffered in intenal cache.
	 */
	int KSI_AsyncService_setMaxRequestCount(KSI_AsyncService *service, const size_t value);


	/**
	 * @}
	 */

#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_ASYNC_H_ */
