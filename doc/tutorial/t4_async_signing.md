T4 - Asynchronous Signing Tutorial
==================================

Disclaimer
----------

For simplicity reasons, the error handling in this tutorial is mostly omitted.
In practice almost all the functions in the SDK return a status code which
value should be checked to be #KSI_OK, which means all went well.

1. Preparation
--------------

For commmon preparation see [Basics Tutorial](tutorial/t0_basics.md).
Additionally, asynchronous signing service provider needs to be initialized. 

~~~~~~~~~~{.c}

	KSI_AsyncService *service = NULL; /* Must be freed. */

	KSI_SigningAsyncService_new(ksi, &service);

~~~~~~~~~~

Next step would be to set up the \c service. As with basic signing one needs to
configure service location to send the signing request to. Let's assume the 
signing service address is \c tcp://signservice.somehost:1234 and it is 
authenticated by \c user:key (currently only TCP connection is supported). 

~~~~~~~~~~{.c}

	KSI_AsyncService_setEndpoint(service, "tcp://signingservice.somehost:1234", "user", "key");

~~~~~~~~~~

Unlike the basic signing (see [Signing Tutorial](tutorial/t1_signing.md)), 
the asynchronous signing is non blocking (except DNS resolution). This enable 
the user to do several simultaneous transfers in parallel where each single 
transfer is wrapped into #KSI_AsyncHandle.

~~~~~~~~~~{.c}

	KSI_AsyncHandle *handle = NULL;

	KSI_AsyncAggregationHandle_new(ksi, req, &handle);

~~~~~~~~~~

Additionally, user private data can be added to the handle, which is 
associated with the request.

~~~~~~~~~~{.c}

	KSI_AsyncHandle_setRequestCtx(handle, (void *)p_data, (void (*)(void *))data_free);

~~~~~~~~~~

When the #KSI_AsyncHandle is set up, it should be added to the asynchronous
service provider #KSI_AsyncService by invoking #KSI_AsyncService_addRequest. 
There can be added multiple #KSI_AsyncHandle's at any time. 

~~~~~~~~~~{.c}

	KSI_AsyncService_addRequest(service, handle);

~~~~~~~~~~

1.1 Additional Options
----------------------

In order to adjust the #KSI_AsyncService to meat your needs #KSI_AsyncService_setOption 
should be used. The available options are described under #KSI_AsyncOption. Pay 
attention to the parameter type description. The updated parameters affect all 
transfers. 

The throughput of added requests is controlled via two options:
- #KSI_ASYNC_OPT_REQUEST_CACHE_SIZE option controls how many request are 
open in parallel. In case the maximum amount of request is already added to 
the #KSI_AsyncService, the next invocation of #KSI_AsyncService_addRequest will
return an error code #KSI_ASYNC_REQUEST_CACHE_FULL. In this case the 
implementation code should call #KSI_AsyncService_run in order to read out 
received responses and free up cache space in #KSI_AsyncService.

~~~~~~~~~~{.c}

	size_t count = (1 << 10);

	KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_REQUEST_CACHE_SIZE, (void *)count);

~~~~~~~~~~

- #KSI_ASYNC_OPT_MAX_REQUEST_COUNT option defines the maximum number of request 
to be sent during a predefined time interval (also round). The value should not 
exceed KSI aggregation service provider configuration (see #KSI_receiveAggregatorConfig). 
The round interval can not be changed by the user and is set internally to 1 sec.

~~~~~~~~~~{.c}

	size_t count = (1 << 8);

	res = KSI_AsyncService_setOption(as, KSI_ASYNC_OPT_MAX_REQUEST_COUNT, (void *)count);

~~~~~~~~~~

2. Signing
----------

Adding the handles to the service provider does not start the transfer 
automatically. The idea of this asynchronous API is that the user 
implementation controls every aspect of the query. In order to initiate 
the transfer user has to invoke #KSI_AsyncService_run. It is not guaranteed 
that all added handles will be processed during a call to #KSI_AsyncService_run.

Any info regarding the request are returned from the asynchronous service 
provider via #KSI_AsyncService_run input parameters. Any completed request 
are returned via the input paranemeter \c handle, and the number of pending 
request via the input paranemeter \c waiting. In order to process all 
requests, the run method should be invoked as long as there are pending 
request left.

The type of the information contained in the returned handle can be 
determined via #KSI_AsyncHandle_getState. The returned \c state can be:
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

In case of a succesfull response the KSI signature can be extracted from 
the handle by invoking #KSI_AsyncHandle_getSignature.

~~~~~~~~~~{.c}

	KSI_Signature *signature = NULL; /* Must be freed. */

	KSI_AsyncHandle_getSignature(handle, &signature);

~~~~~~~~~~

To save the signature to a file or database it's content needs to be serialize.
To do so, one simply need to call the #KSI_Signature_serialize method.

~~~~~~~~~~{.c}

	unsigned char *serialized = NULL; /* Must be freed. */
	size_t serialized_len;

	KSI_Signature_serialize(sig, &serialized, &serialized_len);

~~~~~~~~~~

Now the user may store the contents of \c serialized with length 
\c serialized_len how ever needed.

5. Cleanup
----------

As the final step we need to free all the allocated resources. 

The returned handle from #KSI_AsyncService_run must be freed after it has been
processed.

~~~~~~~~~~{.c}

	KSI_AsyncHandle_free(handle);

~~~~~~~~~~

Also the extracted signature from the #KSI_AsyncHandle must be freed.

~~~~~~~~~~{.c}

	KSI_Signature_free(signature);

~~~~~~~~~~

Note that the KSI context may be reused as much as needed (within a single 
thread) and must not be created every time. It is also important to point out 
that the context must be freed last.

~~~~~~~~~~{.c}

	KSI_AsyncService_free(service);
	KSI_CTX_free(ksi); /* Must be freed last. */

~~~~~~~~~~
