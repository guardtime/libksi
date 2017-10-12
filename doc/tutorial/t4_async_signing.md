T4 - Asynchronous Signing Tutorial
==================================

Disclaimer
----------

For simplicity reasons, the error handling in this tutorial is mostly omitted.
In practice almost all the functions in the SDK return a status code. If status code is #KSI_OK, all went well.

1. Preparation
--------------

For common preparation, see [Basics Tutorial](tutorial/t0_basics.md).
After that, initialize the asynchronous signing service provider.

~~~~~~~~~~{.c}

	KSI_AsyncService *service = NULL; /* Must be freed. */

	KSI_SigningAsyncService_new(ksi, &service);

~~~~~~~~~~

Next, set up the \c service. Similarly to basic signing (see [Signing Tutorial](tutorial/t1_signing.md)), you need to configure service location to send the signing request to. Currently only TCP connection is supported for asynchronous signing, thus let's assume the signing service address is \c ksi+tcp://signservice.somehost:1234 and it is authenticated by \c user:key.

~~~~~~~~~~{.c}

	KSI_AsyncService_setEndpoint(service, "ksi+tcp://signingservice.somehost:1234", "user", "key");

~~~~~~~~~~

Unlike the basic signing, the asynchronous signing is non-blocking (except DNS resolution). This enables the user to do several simultaneous transfers in parallel, each single transfer is wrapped into #KSI_AsyncHandle.

~~~~~~~~~~{.c}

	KSI_AsyncHandle *handle = NULL;

	KSI_AsyncAggregationHandle_new(ksi, req, &handle);

~~~~~~~~~~

Additionally, user's private data can be added to the handle, which is associated with the request.

~~~~~~~~~~{.c}

	KSI_AsyncHandle_setRequestCtx(handle, (void *)p_data, (void (*)(void *))data_free);

~~~~~~~~~~

When the #KSI_AsyncHandle is set up, add it to the asynchronous service provider #KSI_AsyncService by invoking #KSI_AsyncService_addRequest. You may add multiple #KSI_AsyncHandle's at any time.

~~~~~~~~~~{.c}

	KSI_AsyncService_addRequest(service, handle);

~~~~~~~~~~

2. Additional Options
----------------------

In order to adjust the #KSI_AsyncService to meat your needs, #KSI_AsyncService_setOption should be used. The available options are described under #KSI_AsyncOption. Pay attention to the parameter type description. The updated parameters affect all transfers.

The throughput of added requests is controlled via two options:
- #KSI_ASYNC_OPT_REQUEST_CACHE_SIZE option controls how many request are open in parallel. In case the maximum number of requests is already added to the #KSI_AsyncService, the next invocation of #KSI_AsyncService_addRequest will return an error code #KSI_ASYNC_REQUEST_CACHE_FULL. In this case the implementation code should call #KSI_AsyncService_run in order to read out received responses and free up cache in #KSI_AsyncService.

~~~~~~~~~~{.c}

	size_t count = (1 << 10);

	KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)count);

~~~~~~~~~~

- #KSI_ASYNC_OPT_MAX_REQUEST_COUNT option defines the maximum number of request to be sent during a predefined time interval (also round). The value should not exceed KSI aggregation service provider configuration (see #KSI_receiveAggregatorConfig). The round interval can not be changed by the user and is set internally to 1 sec.

~~~~~~~~~~{.c}

	size_t count = (1 << 8);

	KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, (void *)count);

~~~~~~~~~~

3. Signing
----------

Adding the handles to the service provider does not start the transfer automatically. The idea of the asynchronous API is that the user implementation controls every aspect of the query. In order to initiate the transfer, you must invoke #KSI_AsyncService_run. It is not guaranteed that all added handles will be processed during a call to #KSI_AsyncService_run.

Any info regarding the request is returned from the asynchronous service provider via #KSI_AsyncService_run input parameters. Any completed request is returned via the input parameter \c handle, and the number of pending request via the input parameter \c waiting. In order to process all requests, the run method should be invoked as long as there are pending
requests left.

The type of data contained in the returned handle can be determined via #KSI_AsyncHandle_getState. The returned \c state can be:
- #KSI_ASYNC_STATE_RESPONSE_RECEIVED for an aggregation response, or
- #KSI_ASYNC_STATE_ERROR for an error status.

~~~~~~~~~~{.c}

	do {
		KSI_AsyncHandle *handle = NULL; /* Must be freed. */

		KSI_AsyncService_run(service, &handle, &pending);

		if (handle != NULL) {
			int state = KSI_ASYNC_STATE_UNDEFINED;

			KSI_AsyncHandle_getState(handle, &state);

			switch (state) {
				case KSI_ASYNC_STATE_RESPONSE_RECEIVED: {
						...
					}
					break;
				case KSI_ASYNC_STATE_ERROR: {
						...
					}
					break;
			}
		}
	} (pending);

~~~~~~~~~~

4. Saving
---------

In case of a succesful response, the KSI signature can be extracted from the handle by invoking #KSI_AsyncHandle_getSignature.

~~~~~~~~~~{.c}

	KSI_Signature *signature = NULL; /* Must be freed. */

	KSI_AsyncHandle_getSignature(handle, &signature);

~~~~~~~~~~

To save the signature to a file or database it's content needs to be serialized. For this, call the #KSI_Signature_serialize method.

~~~~~~~~~~{.c}

	unsigned char *serialized = NULL; /* Must be freed. */
	size_t serialized_len;

	KSI_Signature_serialize(sig, &serialized, &serialized_len);

~~~~~~~~~~

Now you may store the contents of \c serialized with length \c serialized_len how ever needed.

5. Cleanup
----------

As the final step, you need to free all the allocated resources.

The returned handle from #KSI_AsyncService_run must be freed after it has been processed.

~~~~~~~~~~{.c}

	KSI_AsyncHandle_free(handle);

~~~~~~~~~~

Also the extracted signature from the #KSI_AsyncHandle must be freed.

~~~~~~~~~~{.c}

	KSI_Signature_free(signature);

~~~~~~~~~~

Note that the KSI context may be reused as much as needed (within a single thread) and must not be created every time. Also, the context must be freed last.

~~~~~~~~~~{.c}

	KSI_AsyncService_free(service);
	KSI_CTX_free(ksi); /* Must be freed last. */

~~~~~~~~~~
