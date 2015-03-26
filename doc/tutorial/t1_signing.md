T1 - Signing Tutorial
=====================

Disclaimer
----------

For simplicity reasons, the error handling in thsi tutorial mostly omitted.
In practice almost all the functions in the SDK return a status code which
value should be checked to be #KSI_OK, which means all went well.

1. Preparattion
---------------

The first thing by using the SDK, we need to create a KSI context variable
and initialize it. The context contains all the configurations and can be used
for debuging. The following example shows the initialization of a new #KSI_CTX
object.

    #include <ksi/ksi.h>
    KSI_CTX *ksi = NULL; /* Must be feed at the end. */
    KSI_CTX_new(&ksi); /* Must be initialized only once per thread. */

The next step would be to configure the contetx, as there are no default service
locations to send the signing request to. Let's assume the signing service address is
\c signservice.somehost:1234 and it is authenticated by \c user:key. We can configure
the signing service provider by calling #KSI_CTX_setAggregator.

    KSI_CTX_setAggregator(ksi, "signingservice.somehost:1234", "user", "key");

The context is ready to be used for signing (for extending, the extending service
must be configured see [Extending Turorial](t3_extending.md)).

2. Hashing
----------

Lets assume our data to be signed is stored in a variable called \c data and it's
length is stored in \c data_len.

As only the hash of the original document is signed, we need to create a #KSI_DataHash
object. This is usually done using the #KSI_DataHasher object where the data can be added to the
hash calculation in chunks. In our example, the data is already stored in a single
memory buffer and we can use the #KSI_DataHash_create function. We will use the 
#KSI_HASHALG_SHA2_256 algorithm.

    KSI_DataHash *hsh = NULL; /* Must be freed. */
    KSI_DataHash_create(ksi, data, data_len, &hsh);

3. Signing
----------

At this point we should have all we need to sign document (actually only the hash value of it). To
do so, we need to call #KSI_createSignaure.

    KSI_Signature *sig = NULL;
    KSI_createSignature(ksi, hsh, &sig);

4. Saving
---------

To save the signature to a file or database we need to serialize it's content. To do so, we simply need
to call the #KSI_Signature_serialize method.

    unsigned char *serialized = NULL; /* Must be freed. */
    size_t serialized_len;
    
    KSI_Signature_serialize(sig, &serialized, &serialized_len);

Now the user may strore the contents of \c serialized with lengt \c serialised_len how ever needed.

5. Cleanup
----------

As the final step we need to free all the allocated resources. Note that the KSI context may
be reused as much as needed (within a single thread) and must not be creates every time. It is
also important to point out that the context must be freed last.

    KSI_DataHash_free(hsh);
    KSI_Signature_free(sig);
    KSI_free(serialized);
    KSI_CTX_free(ksi); /* Must be freed last. */
