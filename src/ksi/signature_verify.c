/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

#include <string.h>

#include "internal.h"
#include "signature_verify.h"

static int verify_signature(KSI_Signature *sig, KSI_CTX *ctx,
							KSI_DataHash *hsh, KSI_uint64_t rootLevel, int extAllowed, KSI_PublicationsFile *pubFile, KSI_PublicationData *pubData,
							int (*getPolicy)(KSI_CTX *, const KSI_Policy **), KSI_Policy *customPolicy,
							KSI_PolicyVerificationResult **result) {

	int res = KSI_UNKNOWN_ERROR;
	const KSI_Policy *policy = NULL;
	KSI_VerificationContext *info = NULL;
	KSI_PolicyVerificationResult *tmp = NULL;

	if (sig == NULL || ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	/* Create verification context */
	res = KSI_VerificationContext_create(ctx, &info);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Init signature in verification context */
	res = KSI_VerificationContext_setSignature(info, sig);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Init document hash in verification context */
	if (hsh != NULL) {
		res = KSI_VerificationContext_setDocumentHash(info, hsh);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Init publications file in verification context*/
	if (pubFile != NULL) {
		res = KSI_VerificationContext_setPublicationsFile(info, pubFile);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Init user publication data in verification context */
	if (pubData != NULL) {
		res = KSI_VerificationContext_setUserPublication(info, pubData);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Init aggregation level in verification context */
	if (rootLevel > 0xff) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Aggregation level can't be larger than 0xff.");
		goto cleanup;
	}
	res = KSI_VerificationContext_setAggregationLevel(info, rootLevel);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Init extention permission in verification context */
	res = KSI_VerificationContext_setExtendingAllowed(info, !!extAllowed);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (customPolicy != NULL) {
		policy = customPolicy;
	} else {
		/* Get the desired verification policy */
		res = getPolicy(ctx, &policy);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Verify signature */
	res = KSI_SignatureVerifier_verify(policy, info, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*result = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_PolicyVerificationResult_free(tmp);

	/* Clear data references in verification context as we do not own the memory */
	KSI_VerificationContext_setSignature(info, NULL);
	KSI_VerificationContext_setDocumentHash(info, NULL);
	KSI_VerificationContext_setPublicationsFile(info, NULL);
	KSI_VerificationContext_setUserPublication(info, NULL);
	KSI_VerificationContext_free(info);

	return res;
}

int KSI_SignatureVerify_general(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh,
								KSI_PublicationsFile *pubFile, KSI_PublicationData *pubData, int extPerm,
								KSI_PolicyVerificationResult **result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmpPolicy = NULL;
	KSI_Policy *pubPolicyClone = NULL;
	KSI_Policy *calPolicyClone = NULL;


	if (sig == NULL || ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	/* In case user publications are provided, the signature should be verified agains those */
	if (pubFile != NULL || pubData != NULL) {
		int (*getter)(KSI_CTX *, const KSI_Policy **);

		(pubData != NULL) ? (getter = KSI_Policy_getUserProvidedPublicationBased) :
							(getter = KSI_Policy_getPublicationsFileBased);

		/* Verify singature */
		res = verify_signature(sig, ctx, hsh, 0, extPerm, pubFile, pubData, getter, NULL, result);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

	} else {
		/* Otherwise build a chain of verification policies */
		/* Construct a policy chain: PubBasedPolicy->CalendarBasedPolicy->KeyBasedPolicy */

		/* Get first verification policy. */
		res = KSI_Policy_getPublicationsFileBased(ctx, &tmpPolicy);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
		/* Clone the policy in order to set fallback policy */
		res = KSI_Policy_clone(ctx, tmpPolicy, &pubPolicyClone);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		/* Fallback to PKI key verification */
		res = KSI_Policy_getCalendarBased(ctx, &tmpPolicy);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
		/* Clone the policy in order to set fallback policy */
		res = KSI_Policy_clone(ctx, tmpPolicy, &calPolicyClone);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
		/* Make chain pubBasedPolicy->KeyBasedPolicy */
		res = KSI_Policy_setFallback(ctx, pubPolicyClone, calPolicyClone);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		/* Fallback to online verifycation */
		res = KSI_Policy_getKeyBased(ctx, &tmpPolicy);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
		res = KSI_Policy_setFallback(ctx, calPolicyClone, tmpPolicy);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		/* Verify singature */
		res = verify_signature(sig, ctx, hsh, 0, extPerm, pubFile, pubData, NULL, pubPolicyClone, result);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	res = KSI_OK;
cleanup:
	KSI_Policy_free(pubPolicyClone);
	KSI_Policy_free(calPolicyClone);

	return res;
}

int KSI_SignatureVerify_internal(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, KSI_uint64_t lvl, KSI_PolicyVerificationResult **result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	res = verify_signature(sig, ctx, hsh, lvl, 0, NULL, NULL, KSI_Policy_getInternal, NULL, result);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_SignatureVerify_internalConsistency(KSI_Signature *sig, KSI_CTX *ctx, KSI_PolicyVerificationResult **result){
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	res = KSI_SignatureVerify_internal(sig, ctx, NULL, 0, result);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_SignatureVerify_documentHash(KSI_Signature *sig, KSI_CTX *ctx, KSI_DataHash *hsh, KSI_PolicyVerificationResult **result){
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	if (hsh == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_SignatureVerify_internal(sig, ctx, hsh, 0, result);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_SignatureVerify_userProvidedPublicationBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PublicationData *pubData, int extPerm, KSI_PolicyVerificationResult **result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	if (pubData == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = verify_signature(sig, ctx, NULL, 0, extPerm, NULL, pubData, KSI_Policy_getUserProvidedPublicationBased, NULL, result);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_SignatureVerify_publicationsFileBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PublicationsFile *pubFile, int extPerm, KSI_PolicyVerificationResult **result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	return verify_signature(sig, ctx, NULL, 0, extPerm, pubFile, NULL, KSI_Policy_getPublicationsFileBased, NULL, result);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_SignatureVerify_keyBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PublicationsFile *pubFile, KSI_PolicyVerificationResult **result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	return verify_signature(sig, ctx, NULL, 0, 0, pubFile, NULL, KSI_Policy_getKeyBased, NULL, result);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_SignatureVerify_calendarBased(KSI_Signature *sig, KSI_CTX *ctx, KSI_PolicyVerificationResult **result) {
	int res = KSI_UNKNOWN_ERROR;

	if (sig == NULL || ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	return verify_signature(sig, ctx, NULL, 0, 1, NULL, NULL, KSI_Policy_getCalendarBased, NULL, result);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}
