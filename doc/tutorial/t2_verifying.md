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
A trusted publication file must be provided for performing lookup of a matching certificate.
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
policies, we can simply call one of the corresponding functions,, e.g. #KSI_Policy_getPublicationsFileBased.
Second, we need to create a context for verification by calling #KSI_VerificationContext_create. As a bare minimum,
we must set the signature in the verification context by calling #KSI_VerificationContext_setSignature. Since we are
performing publication-based verification, we should also set up the publications file to be used in verification by calling
#KSI_VerificationContext_setPublicationsFile. When we have set up the verification context (see more examples below),
we can verify the signature by calling #KSI_SignatureVerifier_verify which creates a verification result object.
The function also returns a status code which should be #KSI_OK if the verification process was completed without
any internal errors (e.g. invalid parameters, out of memory errors, no extender configured, etc). Note: #KSI_OK alone
does not indicate a successful verification, so we must inspect the verification result for details:

~~~~~~~~~~{.c}
	
	int res; /* The return value. */
	const KSI_Policy *policy;
	KSI_VerificationContext *context = NULL; /* Must be freed. */
	KSI_PolicyVerificationResult *result = NULL; /* Must be freed. */
	KSI_PublicationsFile *pubFile = NULL; /* Must be freed. */

	res = KSI_Policy_getPublicationsFileBased(ksi, &policy);
	res = KSI_VerificationContext_create(ksi, &context);
	res = KSI_VerificationContext_setSignature(context, sig);
	res = KSI_PublicationsFile_fromFile(ksi, "~/publications.bin", &pubFile);
	res = KSI_VerificationContext_setPublicationsFile(context, pubFile);
	res = KSI_SignatureVerifier_verify(policy, context, &result);
	if (res == KSI_OK) {
		if (result->finalResult.resultCode == VER_RES_OK)
			printf("Signature verified successfully!\n");
		} else {
			/* Error handling. Verification failed or was inconclusive. */
			/* Check result->finalResult.errorCode for error code. */
		}
	} else {
		/* Error handling. Verification not completed due to internal error. */
	}

~~~~~~~~~~
 
5. Verification context
-----------------------

We use the verification context to specify input parameters for the verification. We can set the publications file,
publication string, input document hash and aggregation level. For publication based verification policy we can
specify if extending of the signature is allowed.

Let's continue with another example. For user provided publication based policy we need to set up the publication string by calling
#KSI_VerificationContext_setUserPublication:

~~~~~~~~~~{.c}

	const char pubString[] = "AAAAAA-CUCYWA-AAOBM6-PNYLRK-EPI3VG-2PJGCF-Y5QHV3-XURLI2-GRFBK4-VHBED2-Q37QIB-UE3ENA";
	KSI_PublicationData *userPub = NULL;

	res = KSI_Policy_getUserProvidedPublicationBased(ksi, &policy);
	res = KSI_VerificationContext_create(ksi, &context);
	res = KSI_VerificationContext_setSignature(context, sig);
	res = KSI_PublicationData_fromBase32(ksi, pubString, &userPub);
	res = KSI_VerificationContext_setUserPublication(context, userPub);
	res = KSI_SignatureVerifier_verify(policy, context, &result);
	if (res == KSI_OK) {
		if (result->finalResult.resultCode == VER_RES_OK)
			printf("Signature verified successfully!\n");
		} else {
			/* Error handling. Verification failed or was inconclusive. */
			/* Check result->finalResult.errorCode for error code. */
		}
	} else {
		/* Error handling. Verification not completed due to internal error. */
	}

~~~~~~~~~~

For using the key based policy, we must set up the publications file, similarly to publications file based policy (see example above).
No special set up is needed for calendar based policy. The interfaces for getting the policies are:

~~~~~~~~~~{.c}

	res = KSI_Policy_getKeyBased(ksi, &policy);
	res = KSI_Policy_getCalendarBased(ksi, &policy);

~~~~~~~~~~

For allowing extension of signature for publication based policies, we have to enable it in the verification context by
calling #KSI_VerificationContext_setExtendingAllowed. By default the extending is not allowed and this can lead to
inconclusive verification results if a suitable publication is not found. Note: if extending is allowed, a valid extender
should also be configured (see Basics tutorial).

~~~~~~~~~~{.c}

	/* Any non-zero value allows extending, zero disables extending. */
	res = KSI_VerificationContext_setExtendingAllowed(context, 1);

~~~~~~~~~~

If we need to verify a signature with an aggregation level other than the default 0, we can specify this in the
verification context by calling #KSI_VerificationContext_setAggregationLevel. Initial aggregation level cannot
be greater than 0xFF.

~~~~~~~~~~{.c}

	res = KSI_VerificationContext_setAggregationLevel(context, 4);

~~~~~~~~~~

For verifying the document, we need to set up the document hash by calling #KSI_VerificationContext_setDocumentHash.
The document hash, if set up, will be verified as part of all predefined policies, but for the sake of a simple example
we will choose internal policy:

~~~~~~~~~~{.c}

	KSI_DataHash *hsh = NULL; /* Must be freed. */
	
	res = KSI_Policy_getInternal(ksi, &policy);
	res = KSI_VerificationContext_create(ksi, &context);
	res = KSI_VerificationContext_setSignature(context, sig);
	/* \c data contains the document to be verified. Length of the document is stored in \c data_len. */
	res = KSI_DataHash_create(ksi, data, data_len, &hsh);
	res = KSI_VerificationContext_setDocumentHash(context, hsh);
	res = KSI_SignatureVerifier_verify(policy, context, &result);
	if (res == KSI_OK) {
		if (result->finalResult.resultCode == VER_RES_OK)
			printf("Signature verified successfully!\n");
		} else {
			/* Error handling. Verification failed or was inconclusive. */
			/* Check result->finalResult.errorCode for error code. */
		}
	} else {
		/* Error handling. Verification not completed due to internal error. */
	}
 
~~~~~~~~~~

6. Chaining fallback policies
-----------------------------

If we want automatic fallback to a different verification policy if the original policy verification
fails, we need to clone a predefined policy by calling #KSI_Policy_clone and set a desired fallback policy
by calling #KSI_Policy_setFallback. Predefined policies cannot be modified, so fallback policies cannot
be attached to them directly. When we have cloned a policy, we also need to free it after use by calling
#KSI_Policy_free.

~~~~~~~~~~{.c}

	res = KSI_Policy_getKeyBased(ksi, &orgPolicy);
	res = KSI_Policy_getPublicationsFileBased(ksi, &fallbackPolicy);
	res = KSI_Policy_clone(ksi, orgPolicy, &clonedPolicy);
	res = KSI_Policy_setFallback(ksi, clonedPolicy, fallbackPolicy);
	/* Set up the verification context. */
	res = KSI_SignatureVerifier_verify(clonedPolicy, context, &result);
	/* Error handling. */
	KSI_Policy_free(clonedPolicy);

~~~~~~~~~~

7. Inspecting the result of verification
----------------------------------------

As mentioned before, the prerequisite of a conclusive verification result is that #KSI_SignatureVerifier_verify
returns #KSI_OK. If the return code is other than #KSI_OK, e.g. #KSI_INVALID_ARGUMENT or #KSI_OUT_OF_MEMORY, the
verification process was not completed and it is not possible to say if the signature is valid or incorrect.
If however #KSI_OK is returned, we must evaluate the \c result object, which is created by #KSI_SignatureVerifier_verify.
Only then can we say if the verification was a success or failure.

~~~~~~~~~~{.c}

	res = KSI_SignatureVerifier_verify(policy, context, &result);
	if (res == KSI_OK) {
		/* Verification process was completed without errors, inspect the result. */
		switch (result->finalResult.resultCode) {
			case VER_RES_OK:
				printf("Verification successful, signature is valid.\n");
				break;
			case VER_RES_FAIL:
				printf("Verification failed, signature is not valid.\n");
				printf("Verification error code: %d\n", result->finalResult.errorCode);
				break;
			case VER_RES_NA:
				printf("Verification inconclusive, not enough data to prove or disprove signature correctness.\n");
				break;
		}
	} else {
		printf("Unable to complete verification due to an internal error: %x.\n", res);
		printf("Error description: %s\n", KSI_getErrorString(res));
	}

~~~~~~~~~~

8. Cleanup
----------

As the final step we need to free all the allocated resources. When using predefined policies, there is no need to
free the policy. However, cloned policies must be freed by calling #KSI_Policy_free. The verification context must
be freed by calling #KSI_VerificationContext_free. This function frees all resources that have been configured for
verification, so if we are not the owners of a particular resource, e.g. we need to keep using the signature after
verification, it is important to set this parameter to #NULL in the verification context to prevent if from being
freed. After we are done inspecting the verification result, we must free it with #KSI_PolicyVerificationResult_free.
Note that the KSI context may be reused as much as needed (within a single thread) and must not be created every time.
It is also important to point out that the context, if freed, must be freed last.

~~~~~~~~~~{.c}

	KSI_DataHash_free(hsh);
	KSI_Policy_free(clonedPolicy);
	/* We need to use the signature after verification, so let's prevent if from being freed. */
	KSI_VerificationContext_setSignature(context, NULL);
	KSI_VerificationContext_free(context); /* Will keep the signature object. */
	KSI_PolicyVerificationResult_free(result);
	KSI_CTX_free(ksi); /* Must be freed last. */

~~~~~~~~~~

9. Building your own policies
-----------------------------

If the predefined policies do not meet our needs of verification, we can still build our own policies. For this we need
to put rules (implemented as verification functions) in some order that meets our verification needs. We can reuse
predefined rules  or define our own rules for this purpose. We start off by initializing a policy structure first:

~~~~~~~~~~{.c}

	static const KSI_Policy customPolicy = {
		customRules,	/* Pointer to rules. */
		NULL,			/* Pointer to fallback policy. */
		"CustomPolicy"	/* Name of the policy. */
	};

~~~~~~~~~~

We are referencing a \c customRules object, which is the array of rules that perform the verification functionality
of this policy. So let's create this array:

~~~~~~~~~~{.c}

	static const Rule customRules[] = {
		{RULE_TYPE_BASIC, VerifyingFunction1},
		{RULE_TYPE_BASIC, VerifyingFunction2},
		{RULE_TYPE_BASIC, VerifyingFunction3},
		{RULE_TYPE_BASIC, NULL}					/* Every rule array has to end with this empty rule. */
	};

~~~~~~~~~~

Each element in this array consists of two parts: rule type and a pointer. For this first example, we will use the
basic rule type #RULE_TYPE_BASIC, which means that the second part - pointer - is a pointer to a verifying function.
When a policy is verified by #KSI_SignatureVerifier_verify, it goes through this array and checks the rule type.
If the rule type is #RULE_TYPE_BASIC, it calls the verifying function and examines the verification result of this
function. If the function returns #KSI_OK and verification result is #VER_RES_OK, it continues with the next rule
in the array and does so until it encounters the final empty rule. In this case the verification is successful.
If at some point any of the functions does not return #KSI_OK or the verification result is not #VER_RES_OK, the
verification fails and no more rules are processed. There is however one exception when the next rule is processed
and we will see this in one of the following examples. For now, let's examine the typical verifying function:

~~~~~~~~~~{.c}

	int VerifyingFunction1(KSI_VerificationContext *context, KSI_RuleVerificationResult *result) {
		int res = KSI_UNKNOWN_ERROR;

		if (context == NULL || result == NULL) {
			/* Unable to complete verification, set VER_RES_NA as result. */
			result->resultCode = VER_RES_NA;
			result->errorCode = VER_ERR_GEN_2;
			/* Return relevant error code. */
			res = KSI_INVALID_ARGUMENT;
			goto cleanup;
		}

		/* Perform some sort of verification of the signature. */
		if (!success) {
			/* Set VER_RES_FAIL as result and set appropriate error code. */
			result->resultCode = VER_RES_FAIL;
			result->errorCode = VER_ERR_CUST_1;
			/* Return KSI_OK because verification was completed. */
			res = KSI_OK;
		} else {
			/* Set VER_RES_OK as result. */
			result->resultCode = VER_RES_OK;
			result->errorCode = VER_ERR_NONE;
			/* Return KSI_OK because verification was completed. */
			res = KSI_OK;
		}

	cleanup:
		/* Perform cleanup of resources, if needed. */
		return res;
	}

~~~~~~~~~~

Important points to remember about a verifying function:
1. Regardless of verification success or failure, the return code in \c should be #KSI_OK, indicating that the function
had enough input data and was able to reach a conclusion about the correctness of the data.
2. The only case where the return code should be anything other than #KSI_OK is when the function encounters an internal
error (e.g. is not able to allocate a resource, cannot find a publications file, is not able to connect to the extender, etc.)
or cannot use the provided input data (e.g. a mandatory parameter is NULL, data is in the wrong format, etc.). A relevant error code
should then be returned to indicate the reason why verification was not completed.

Time to move on to some more complex rules. Let's say we want to provide alternative, equally conclusive paths to a verification result.
Path A means that we would have to go through a set of three rules, path B requires verification of a different set of four rules and path C
consists of yet another set of two rules. Finally, after succeeding at either path A, B, or C, we still want to run some final rule before 
deciding on the result of the policy. We can write it down like this:

~~~~~~~~~~{.c}

	static const Rule pathARules[] = {
		{RULE_TYPE_BASIC, VerifyingFunction1},
		{RULE_TYPE_BASIC, VerifyingFunction2},
		{RULE_TYPE_BASIC, VerifyingFunction3},
		{RULE_TYPE_BASIC, NULL}					/* Every rule array has to end with this empty rule. */
	};

	static const Rule pathBRules[] = {
		{RULE_TYPE_BASIC, VerifyingFunction4},
		{RULE_TYPE_BASIC, VerifyingFunction5},
		{RULE_TYPE_BASIC, VerifyingFunction6},
		{RULE_TYPE_BASIC, VerifyingFunction7},
		{RULE_TYPE_BASIC, NULL}					/* Every rule array has to end with this empty rule. */
	};

	static const Rule pathCRules[] = {
		{RULE_TYPE_BASIC, VerifyingFunction8},
		{RULE_TYPE_BASIC, VerifyingFunction9},
		{RULE_TYPE_BASIC, NULL}					/* Every rule array has to end with this empty rule. */
	};

	static const Rule chooseABCRule[] = {
		{RULE_TYPE_COMPOSITE_OR, pathARules},
		{RULE_TYPE_COMPOSITE_OR, pathBRules},
		{RULE_TYPE_COMPOSITE_OR, pathCRules},
		{RULE_TYPE_BASIC, NULL}					/* Every rule array has to end with this empty rule. */
	};

	static const Rule complexRules[] = {
		{RULE_TYPE_COMPOSITE_AND, chooseABCRule},
		{RULE_TYPE_BASIC, VerifyingFunction10},
		{RULE_TYPE_BASIC, NULL}					/* Every rule array has to end with this empty rule. */
	};

	static const KSI_Policy complexPolicy = {
		complexRules,	/* Pointer to rules. */
		NULL,			/* Pointer to fallback policy. */
		"ComplexPolicy"	/* Name of the policy. */
	};

~~~~~~~~~~

We introduced two new rule types here: #RULE_TYPE_COMPOSITE_OR and #RULE_TYPE_COMPOSITE_AND. Both are composite rule types,
which means that the second part of the rule - the pointer - is not a function pointer (as was the case with the basic rule type),
but instead a pointer to another array of rules. The array of rules can contain both basic and composite rules, meaning that
composite rules can be nested. As you would expect from any array of rules, the composite rule is also also verified in a linear
fashion until a rule fails or until all rules including the last one are successful.

The result of the composite rule, whether success or failure, is interpreted according to the rule type. If an OR-type rule
is successfully verified, further rules in the rule array are skipped and the whole rule of which the OR-type rule is part of,
is considered successfully verified. In our example, if \c pathARules verifies successfully, the subsequent rules \c pathBRules
and \c pathCRules are skipped and the rule \c chooseABCRule is considered successful. The analogy to an OR-statement continues,
but with a slightly different definition of failure - if an OR-type rule result is inconclusive (#VER_RES_NA), we are allowed to 
verify the the next rule in the array. However, if an OR-type rule result fails with #VER_RES_FAIL, subsequent rules are not verified
and the result of array of rules is a failure. So in our example, if \c pathARules results in #VER_RES_NA, the rule \c pathBRules
is verified. If this rule result is also inconclusive, the rule \c pathCRules is verified. If however any of those rules fail
with #VER_RES_FAIL, the rule \c chooseABCRule has also failed. 

In our example the rule \c chooseABCRule itself is a composite AND-type rule, which means that its result must be successful for
the verification to continue. So for a successful result of the \c complexPolicy, both \c chooseABCRule and \c VerifyingFunction10
must verify successfully. If an AND-type rule fails, the whole rule array of which it is part of, fails as well (no further rules
are verified). 

Let's summarize how rule results are interpreted:
1. If the return code is not #KSI_OK, the rule has failed due to some internal error. No further rules are checked and the return code
is propagated upwards to the top level rule, concluding with a failure of the policy.
2. If the return code is #KSI_OK, the rule was verified and its result must be examined.
3. A basic rule or a composite AND-type rule is considered successful if the result is #VER_RES_OK. In this case the verification
continues with the next rule on the same level.
4. A composite OR-type rule is considered successful if the result is #VER_RES_OK. Further rules on the same level are skipped and
verification continues one level higher.
5. Any rule is considered a failure if the result is #VER_RES_FAIL. No further rules are checked and the result is propagated upwards
to the top level rule, concluding with a failure of the policy.
6. A basic rule or a composite AND-type rule is considered inconclusive if the result is #VER_RES_NA. The result is propagated one
level upwards, but further rules on the same level are skipped. Verification may stop or continue depending on rule types of the
upper level rules.
7. A composite OR-type rule is considered inconclusive if the result code is #VER_RES_NA. The result is ignored and the next rule
on the same level is checked. This is the only exception where verification is guaranteed to continue even if the result is not
#KSI_RES_OK.
8. The result of the last checked rule on any level is always propagated one level higher.