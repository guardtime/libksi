T4 - Asynchronous Interface Tutorial
==================================

## Disclaimer
----------

For simplicity reasons, the error handling in this tutorial is mostly omitted. In practice almost all the functions in the SDK return a status code. If status code is #KSI_OK, all went well.

Following tutorial will describe the signing interface in details. However, as the same practices apply also to the asynchronous extending interface, you will find applicable references.

## 1. Preparation
----------

For common preparation, see [Basics Tutorial](tutorial/t0_basics.md). After completion, initialize the asynchronous service provider. 

~~~~~~~~~~{.c}

	KSI_AsyncService *service = NULL; /* Must be freed. */

	KSI_SigningAsyncService_new(ksi, &service);

~~~~~~~~~~
(see #KSI_ExtendingAsyncService_new for extending)

Next, set up the \c service. Similarly to basic interface (see [Signing Tutorial](tutorial/t1_signing.md) or [Extending Tutorial](tutorial/t3_extending.md)), you need to configure service location to send the request to. Let's assume the service address is \c ksi+tcp://service.somehost:1234 and it is authenticated by \c user:key.

~~~~~~~~~~{.c}

	KSI_AsyncService_setEndpoint(service, "ksi+tcp://service.somehost:1234", "user", "key");

~~~~~~~~~~

### 1.1. High Availability Considerations
----------

The aim of this feature in SDK is to enable the user to send requests to all configured gateways where first successful response will be returned.

There are interfaces for each asynchronous service provider respectivelly. 

~~~~~~~~~~{.c}

	KSI_AsyncService *service = NULL; /* Must be freed. */

	KSI_SigningHighAvailabilityService_new(ksi, &service);

~~~~~~~~~~
(see #KSI_ExtendingHighAvailabilityService_new for extending)

You can configure several service locations to send the request to (at least one must be configured). Let's assume you would like to configure three sub services with following addresses:
- \c ksi+tcp://service.somehost1:1234 and it is authenticated by \c user1:key1.
- \c ksi+tcp://service.somehost1:2345 and it is authenticated by \c user2:key2.
- \c ksi+tcp://service.somehost1:3456 and it is authenticated by \c user3:key3.

~~~~~~~~~~{.c}

	KSI_AsyncService_addEndpoint(service, "ksi+tcp://service.somehost1:1234", "user1", "key1");
	KSI_AsyncService_addEndpoint(service, "ksi+tcp://service.somehost2:2345", "user2", "key2");
	KSI_AsyncService_addEndpoint(service, "ksi+tcp://service.somehost3:3456", "user3", "key3");

~~~~~~~~~~


## 2. Additional Options
----------

In order to adjust the #KSI_AsyncService to meet your needs, #KSI_AsyncService_setOption should be used. The available options are described under #KSI_AsyncOption. Pay attention to the parameter type description. The updated parameters affect all transfers.

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

## 3. Creating a Request
----------

Unlike the basic interface, the asynchronous interface is non-blocking (except DNS resolution). This enables the user to do several simultaneous transfers in parallel, each single transfer is wrapped into #KSI_AsyncHandle.

### 3.1. Signing
----------

Provide a signing \c request #KSI_AggregationReq.

~~~~~~~~~~{.c}

	KSI_AsyncHandle *handle = NULL;

	KSI_AsyncAggregationHandle_new(ksi, request, &handle);

~~~~~~~~~~

### 3.2. Extending
----------

There are two interfaces for constructing an extending \c handle:

- providing an #KSI_ExtendReq. From user point of view, the drawback of using this interface is that you will not be able to get a #KSI_Signature from the response handle.

~~~~~~~~~~{.c}

	KSI_AsyncHandle *handle = NULL;

	KSI_AsyncExtendHandle_new(ksi, request, &handle);

~~~~~~~~~~

- providing a #KSI_Signature and optionally a #KSI_PublicationRecord. In case the publication record is not provided, the \c signature will be extended to the nearest publication. Note that the input data may not be freed until the request has received a response.

~~~~~~~~~~{.c}

	KSI_AsyncHandle *handle = NULL;

	KSI_AsyncExtendingHandle_new(ksi, signature, publicationRecond, &handle);

~~~~~~~~~~

### 3.3. Setting Up The Request
----------

Additionally, user's private data can be added to the handle, which is associated with the request.

~~~~~~~~~~{.c}

	KSI_AsyncHandle_setRequestCtx(handle, (void *)p_data, (void (*)(void *))data_free);

~~~~~~~~~~

When the #KSI_AsyncHandle is set up, add it to the asynchronous service provider #KSI_AsyncService by invoking #KSI_AsyncService_addRequest. You may add multiple #KSI_AsyncHandle's at any time.

~~~~~~~~~~{.c}

	KSI_AsyncService_addRequest(service, handle);

~~~~~~~~~~

Adding the handles to the service provider does not start the transfer automatically. The idea of the asynchronous API is that the user implementation controls every aspect of the query. In order to initiate the transfer, you must invoke #KSI_AsyncService_run. It is not guaranteed that all added handles will be processed during a call to #KSI_AsyncService_run.

Any info regarding the request is returned from the asynchronous service provider via #KSI_AsyncService_run input parameters. Any completed request is returned via the input parameter \c handle, and the number of pending request via the input parameter \c waiting. In order to process all requests, the run method should be invoked as long as there are pending requests left.

The type of data contained in the returned handle can be determined via #KSI_AsyncHandle_getState. The returned \c state can be any of the final states described in #KSI_AsyncHandleState, eg:
- #KSI_ASYNC_STATE_RESPONSE_RECEIVED for an aggregation response
- #KSI_ASYNC_STATE_ERROR for an error status

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

			KSI_AsyncHandle_free(handle);
		}
	} (pending);

~~~~~~~~~~

## 4. Saving
----------

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

## 5. Cleanup
----------

As the final step, you need to free all the allocated resources.

The returned handle from #KSI_AsyncService_run must be freed after it has been processed.

~~~~~~~~~~{.c}

	KSI_AsyncHandle_free(handle);

~~~~~~~~~~

Also the extracted signature from #KSI_AsyncHandle must be freed.

~~~~~~~~~~{.c}

	KSI_Signature_free(signature);

~~~~~~~~~~

Note that the KSI context may be reused as much as needed (within a single thread) and must not be created every time. Also, the context must be freed last.

~~~~~~~~~~{.c}

	KSI_AsyncService_free(service);
	KSI_CTX_free(ksi); /* Must be freed last. */

~~~~~~~~~~
