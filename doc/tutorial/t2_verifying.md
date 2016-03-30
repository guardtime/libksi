T2 - Verifying Tutorial
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

3. Policies
-----------

Signatures are verified according to one or more policies. A verification policy is a set of ordered
rules that verify relevant signature properties. Verifying a signature according to a policy results
in one of three possible outcomes:
- Verification is successful, which means that there is enough data to prove that the signature is correct.
- Verification is not possible, which means that there is not enough data to prove or disprove the correctness
of the signature. Note: with some other policy it might still be possible to prove the correctness of the signature.
- Verification failed, which means that the signature is definitely invalid or the document does not match
the signature.

The SDK provides the following predefined policies for verification:
- Internal policy. This policy verifies the consistency of various internal components of the signature without
requiring any additional data from the user. The verified components are the aggregation chain, calendar chain (optional),
calendar authentication record (optional) and publication record (optional). Additionally, if a document hash is provided,
the signature is verified against it.
- Key-based policy. This policy verifies the PKI signature and calendar chain data in the calendar authentication record of the signature.
For conclusive results, a calendar hash chain and calendar authentication record must be present in the signature.
A publication file must be provided for performing lookup of a matching certificate.
- Publications file based policy. This policy verifies the signature publication record against a publication
in the publication file. If necessary (and permitted), the signature is extended to the publication. For conclusive results
the signature must either contain a publication record with a suitable publication or signature extending must be allowed.
A publications file must be provided for lookup and an extender must be configured. 
- User provided publication string based policy. This policy verifies the signature publication record against the
publication string. if necessary (and permitted), the signature is extended to the user publication. For conclusive results
the signature must either contain a publication record with a suitable publication or signature extending must be allowed.
A publication string must be provided and an extender must be configured.
- Calendar-based policy. This policy first extends the signature to either the head of the calendar or to the 
same time as the calendar chain of the signature. The extended signature calendar chain is then verified against
aggregation chain of the signature. For conclusive results the extender must be configured.

Note: all of the policies perform internal verification as a prerequisite to the specific verification.

4. Verifying a signature according to a policy
----------------------------------------------

To perform verification according to a policy, we first need to get a pointer to it. To use any of the predefined
policies, we can simply call one the corresponding functions, e.g. #KSI_Policy_getInternal. Second, we need to create
a context for verification by calling #KSI_VerificationContext_create. As a bare minimum, we must set the signature
in the verification context by calling #KSI_VerificationContext_setSignature. When we have set up the verification
context (see more examples below), we can verify the signature by calling #KSI_SignatureVerifier_verify which creates
a verification result object. The function also returns a status code which should be #KSI_OK if the verification process
was completed without any internal errors (e.g. invalid parameters, out of memory errors, no extender configured, etc).
#KSI_OK does not indicate a successful verification, so we must inspect the verification result for details:

~~~~~~~~~~{.c}
	
	int res; /* The return value. */
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *context = NULL;
	KSI_PolicyVerificationResult *result = NULL;

	res = KSI_Policy_getInternal(ksi, &policy);
	res = KSI_VerificationContext_create(ksi, &context);
	res = KSI_VerificationContext_setSignature(context, sig);
	res = KSI_SignatureVerifier_verify(policy, context, &result);
	if (res == KSI_OK) {
		if (result->finalResult.resultCode == VER_RES_OK)
			printf("Signature verified successfully!\n");
		} else {
			/* Error handling. Verification failed or was inconclusive. */
			/* Check result->finalResult.errorCode for error code. */
		}
	} else {
		/* Error handling. Verification not completed due to some error. */
	}


~~~~~~~~~~
 

5. Signature-only Verification
------------------------------

Sometimes it is enough to verify only the signature itself without having the original
document that was signed. To verify the signature we must call #KSI_verifySignature. At this point
it is vital to check the return value. Unless the return value was #KSI_OK there was something
wrong in the verification process (NB! This does not mean the signature is bad - it might be a
connectivity issue with the extender or sth.):

~~~~~~~~~~{.c}

	int res; /* The return value. */
	res = KSI_verifySignature(ksi, sig);
	if (res == KSI_OK) {
	    printf("The signature looks fine!\n");
	} else {
	    /* Error handling. */
	}

~~~~~~~~~~

6. Document verification
----------

Lets assume our document to be verified is stored in a variable called \c data and it's
length is stored in \c data_len.

As only the hash of the original document was signed, we need to create a #KSI_DataHash
object. This is usually done using the #KSI_DataHasher object where the data can be added to the
hash calculation in chunks. In our example, the data is already stored in a single
memory buffer and we can use the #KSI_DataHash_create function. We will use the 
#KSI_HASHALG_SHA2_256 algorithm.

~~~~~~~~~~{.c}

	KSI_DataHash *hsh = NULL; /* Must be freed. */
	KSI_DataHash_create(ksi, data, data_len, &hsh);
    
~~~~~~~~~~

To verify the document hash with the signature we need to call #KSI_Signature_verifyDataHash.

~~~~~~~~~~{.c}

	int res; /* The return value. */
	res = KSI_Signature_verifyDataHash(sig, ksi, hsh);
	if (res == KSI_OK) {
	   printf("Document verified with the signature.");
	} else {
	   /* Error handling. */
	}

~~~~~~~~~~

7. When something went wrong.
-----------------------------

We did not describe the branches when the verification functions did not return #KSI_OK. It is important to
note, that if the verification process does not return #KSI_OK, it does not mean the document or the signature
are invalid - in some cases bad configuration (e.g. missing or bad can be the root cause). Only #KSI_VERIFICATION_FAILURE
as the return value indicates, the signature or the document is invalid. The simplest error handling could be
written as:

~~~~~~~~~~{.c}

	res = KSI_Signature_verify(sig, ksi);
	switch(res) {
	    case KSI_OK:
	        printf("The signature looks fine!\n");
	        break;
	    case KSI_VERIFICATION_FAILURE:
	        printf("The signature is not valid!\n");
	        break;
	    default:
	        printf("I am unable to verify due to an error.\n");
	        break;
	}
    
~~~~~~~~~~

The first two cases of the last switch statement should be clear, but what to do with the default branch? One way to diagnose the
problem is to add more status codes to the statement, but in general it is enough to inform the user (or log) the error message.
For this, there are two methods #KSI_getErrorString, which converts the status code into a null-terminated string. To get a more
detailed error message we can use #KSI_ERR_getBaseErrorMessage.

8. Cleanup
----------

As the final step we need to free all the allocated resources. Note that the KSI context may
be reused as much as needed (within a single thread) and must not be creates every time. It is
also important to point out that the context must be freed last.

~~~~~~~~~~{.c}

	KSI_DataHash_free(hsh);
	KSI_Signature_free(sig);
	KSI_CTX_free(ksi); /* Must be freed last. */

~~~~~~~~~~