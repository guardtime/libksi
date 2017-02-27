T1 - Signing Tutorial
=====================

Disclaimer
----------

For simplicity reasons, the error handling in this tutorial is mostly omitted.
In practice almost all the functions in the SDK return a status code which
value should be checked to be #KSI_OK, which means all went well.

1. Preparation
---------------

For preparation see [Basics Tutorial](tutorial/t0_basics.md).

2. Hashing
----------

Lets assume our data to be signed is stored in a variable called \c data and it's
length is stored in \c data_len.

As only the hash of the original document is signed, we need to create a #KSI_DataHash
object. This is usually done using the #KSI_DataHasher object where the data can be added to the
hash calculation in chunks. In our example, the data is already stored in a single
memory buffer and we can use the #KSI_DataHash_create function. We will use the 
#KSI_HASHALG_SHA2_256 algorithm.

~~~~~~~~~~{.c}

    KSI_DataHash *hsh = NULL; /* Must be freed. */
    KSI_DataHash_create(ksi, data, data_len, KSI_HASHALG_SHA2_256, &hsh);

~~~~~~~~~~

3. Signing
----------

At this point we should have all we need to sign the document (actually only the hash value of it). To
do so, we need to call #KSI_createSignature.

~~~~~~~~~~{.c}

	KSI_Signature *sig = NULL;
	KSI_createSignature(ksi, hsh, &sig);

~~~~~~~~~~

4. Saving
---------

To save the signature to a file or database we need to serialize it's content. To do so, we simply need
to call the #KSI_Signature_serialize method.

~~~~~~~~~~{.c}

	unsigned char *serialized = NULL; /* Must be freed. */
	size_t serialized_len;
	
	KSI_Signature_serialize(sig, &serialized, &serialized_len);

~~~~~~~~~~

Now the user may store the contents of \c serialized with length \c serialized_len how ever needed.

5. Cleanup
----------

As the final step we need to free all the allocated resources. Note that the KSI context may
be reused as much as needed (within a single thread) and must not be created every time. It is
also important to point out that the context must be freed last.

~~~~~~~~~~{.c}

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	KSI_free(serialized);
	KSI_CTX_free(ksi); /* Must be freed last. */

~~~~~~~~~~
