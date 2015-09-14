T3 - Extending Tutorial
=====================

Disclaimer
----------

For simplicity reasons, the error handling in this tutorial is mostly omitted.
In practice almost all the functions in the SDK return a status code which
value should be checked to be #KSI_OK, which means all went well.

1. Preparation
---------------

For preparation see [Basics Tutorial](tutorial/t0_basics.md).

2. Parsing
----------

Usually if a signature needs to be verified, it has been serialized into a binary format
which is stored in a file or database. We won't cover reading the binary data, as it may vary
on different integrations. Let's assume the signature is copied into a buffer
called \c raw and it's length is stored in \c raw_len. To parse the signature we need to
call #KSI_Signature_parse:

~~~~~~~~~~{.c}

	KSI_Signature *sig = NULL;
	KSI_Signature_parse(ksi, raw, raw_len, &sig);

~~~~~~~~~~

After a successful call to #KSI_Signature_parse the buffer \c raw can be freed by the caller
as it is not referenced by the signature.

3. Extending
------------

After parsing and before extending the signature, we can verify it ( see [Verifying tutorial](tutorial/t2_verifying.md)),
but if the signature has not been extended for many years, the verification may fail (which is one of the 
reasons why signatures should be extended as soon as possible). Furthermore, if the extending process succeeds,
the signature is automatically verified (i.e a bad signature will fail eventually anyway).

The extending of a signature can be done using the #KSI_extendSignature function:

~~~~~~~~~~{.c}

	KSI_Signature *extended = NULL;
	res = KSI_extendSignature(ksi, sig, &extended);
	if (res != KSI_OK) {
	  ...
	}

~~~~~~~~~~

If the signature is successfully extended, the old signature may be replaced with the new
signature. To serialize the new signature see the [Signing tutorial](tutorial/t1_signing.md).

5. Cleanup
----------

As the final step we need to free all the allocated resources. Note that the KSI context may
be reused as much as needed (within a single thread) and must not be creates every time. It is
also important to point out that the context must be freed last.

~~~~~~~~~~{.c}

	KSI_Signature_free(extended);
	KSI_Signature_free(sig);
	KSI_CTX_free(ksi); /* Must be freed last. */

~~~~~~~~~~
	