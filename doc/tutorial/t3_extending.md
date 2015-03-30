T1 - Extending Tutorial
=====================

Disclaimer
----------

For simplicity reasons, the error handling in this tutorial mostly omitted.
In practice almost all the functions in the SDK return a status code which
value should be checked to be #KSI_OK, which means all went well.

The first thing by using the SDK, we need to create a KSI context variable
and initialize it. The context contains all the configurations and can be used
for debugging. The following example shows the initialization of a new #KSI_CTX
object.

    #include <ksi/ksi.h>
    KSI_CTX *ksi = NULL; /* Must be feed at the end. */
    KSI_CTX_new(&ksi); /* Must be initialized only once per thread. */

The next step would be to configure the context, as there are no default service
locations configured. The verification process may on some cases access to the
extender service. Let's assume the extending service address is
\c extendservice.somehost:4321 and it is authenticated by \c user:key. We can configure
the service provider by calling #KSI_CTX_setExtender.

    KSI_CTX_setExtender(ksi, "signingservice.somehost:1234", "user", "key");

The context is ready to be used for verification.

2. Parsing
----------

Usually if a signature needs to be verified, it has been serialized into a binary format
which is stored in a file or database. We won't cover reading the binary data, as it may vary
on different integrations. Let's assume the signature is copied into a buffer
called \c raw and it's length is stored in \c raw_len. To parse the signature we need to
call #KSI_Signature_parse:

    KSI_Signature *sig = NULL;
    KSI_Signature_parse(ksi, raw, raw_len, &sig);

After a successful call to #KSI_Signature_parse the buffer \c raw can be freed by the caller
as it is not referenced by the signature.

3. Extending
------------

After parsing and before extending the signature, we can verify it ( see [Verifying tutorial](t2_verifying.md)),
but if the signature has not been extended for many years, the verification may fail (which is one of the 
reasons why signatures should be extended as soon as possible). Furthermore, if the extending process succeeds,
the signature is automatically verified (i.e a bad signature will fail eventually anyway).

The extending of a signature can be done using the #KSI_extendSignature function:

    KSI_Signature *extended = NULL;
    res = KSI_extendSignature(ksi, sig, &extended);
    if (res != KSI_OK) {
      ...
    }

If the signature is successfully extended, the old signature may be replaced with the new
signature. To serialize the new signature see the [Signing tutorial](t1_signing.md).

5. Cleanup
----------

As the final step we need to free all the allocated resources. Note that the KSI context may
be reused as much as needed (within a single thread) and must not be creates every time. It is
also important to point out that the context must be freed last.

    KSI_Signature_free(extended);
    KSI_Signature_free(sig);
    KSI_CTX_free(ksi); /* Must be freed last. */
