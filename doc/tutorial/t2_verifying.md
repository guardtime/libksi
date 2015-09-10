T2 - Verifying Tutorial
=====================

Disclaimer
----------

For simplicity reasons, the error handling in this tutorial is mostly omitted.
In practice almost all the functions in the SDK return a status code which
value should be checked to be #KSI_OK, which means all went well.

1. Preparation
---------------

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
\c http://extendservice.somehost:4321 and it is authenticated by \c user:key. We can configure
the service provider by calling #KSI_CTX_setExtender.

    KSI_CTX_setExtender(ksi, "http://signingservice.somehost:1234", "user", "key");

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

3. Signature-only Verification
------------------------------

Sometimes it is enough to verify only the signature itself without having the original
document that was signed. To verify the signature we must call #KSI_Signature_verify. At this point
it is vital to check the return value. Unless the return value was #KSI_OK there was something
wrong in the verification process (NB! This does not mean the signature is bad - it might be a
connectivity issue with the extender or sth.):

    int res; /* The return value. */
    res = KSI_Signature_verify(sig, ksi);
    if (res == KSI_OK) {
        printf("The signature looks fine!\n");
    } else {
        /* Error handling. */
    }

4. Document verification
----------

Lets assume our document to be verified is stored in a variable called \c data and it's
length is stored in \c data_len.

As only the hash of the original document was signed, we need to create a #KSI_DataHash
object. This is usually done using the #KSI_DataHasher object where the data can be added to the
hash calculation in chunks. In our example, the data is already stored in a single
memory buffer and we can use the #KSI_DataHash_create function. We will use the 
#KSI_HASHALG_SHA2_256 algorithm.

    KSI_DataHash *hsh = NULL; /* Must be freed. */
    KSI_DataHash_create(ksi, data, data_len, &hsh);
    
To verify the document hash with the signature we need to call #KSI_Signature_verifyDataHash.

    int res; /* The return value. */
    res = KSI_Signature_verifyDataHash(sig, ksi, hsh);
    if (res == KSI_OK) {
       printf("Document verified with the signature.");
    } else {
       /* Error handling. */
    }

5. When something went wrong.
-----------------------------

We did not describe the branches when the verification functions did not return #KSI_OK. It is important to
note, that if the verification process does not return #KSI_OK, it does not mean the document or the signature
are invalid - in some cases bad configuration (e.g. missing or bad can be the root cause). Only #KSI_VERIFICATION_FAILURE
as the return value indicates, the signature or the document is invalid. The simplest error handling could be
written as:

    res = KSI_Signature_verify(sig, ksi);
    switch(res) {
        case KSI_OK:
            printf("The signature looks fine!\n");
            break;
        case KSI_VERIFICATION_ERROR:
            printf("The is not valid!\n");
            break;
        default:
            printf("I am unable to verify due to an error.\n");
            break;
    }
    
The first two cases of the last switch statement should be clear, but what to do with the default branch? One way to diagnose the
problem is to add more status codes to the statement, but in general it is enough to inform the user (or log) the error message.
For this, there are two methods #KSI_getErrorString, which converts the status code into a null-terminated string. To get a more
detailed error message we can use #KSI_ERR_getBaseErrorMessage.

6. Cleanup
----------

As the final step we need to free all the allocated resources. Note that the KSI context may
be reused as much as needed (within a single thread) and must not be creates every time. It is
also important to point out that the context must be freed last.

    KSI_DataHash_free(hsh);
    KSI_Signature_free(sig);
    KSI_CTX_free(ksi); /* Must be freed last. */
