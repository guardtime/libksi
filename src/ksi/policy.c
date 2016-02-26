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

#include "policy.h"
#include "policy_impl.h"
#include "verification_rule.h"

static void PolicyResult_free(KSI_PolicyResult *result);

KSI_IMPLEMENT_LIST(KSI_PolicyResult, PolicyResult_free);

static int Rule_verify(const Rule *rule, VerificationContext *context, KSI_RuleResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RuleResult ruleResult;
	const Rule *currentRule = NULL;

	if (rule == NULL || context == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	currentRule = rule;
	while (currentRule->rule) {
		if (currentRule->type == RULE_TYPE_BASIC) {
			res = ((Verifier)(currentRule->rule))(context, &ruleResult);
		} else if (currentRule->type == RULE_TYPE_COMPOSITE) {
			res = Rule_verify((Rule *)currentRule->rule, context, &ruleResult);
		} else {
			res = KSI_INVALID_ARGUMENT;
			goto cleanup;
		}

		if (res != KSI_OK) {
			ruleResult.resultCode = NA;
			ruleResult.errorCode = GEN_2;
		}

		if (ruleResult.resultCode == OK) {
			if (currentRule->type == RULE_TYPE_COMPOSITE && currentRule->skipOnFirstOk == true) {
				/* Do not handle the next rule(s) because the first OK is enough. */
				break;
			}
		} else {
			if (currentRule->type == RULE_TYPE_BASIC || (currentRule->type == RULE_TYPE_COMPOSITE && currentRule->skipOnFirstOk == false)) {
				/* Do not handle the next rule(s) because the first FAIL or NA is enough. */
				break;
			}
		}
		currentRule++;
	}
	*result = ruleResult;

	/* TODO: add rule result? */

cleanup:

	return res;
}

const Rule internalRules[] = {
	{RULE_TYPE_BASIC, false, KSI_VerificationRule_AggregationChainInputHashVerification},
	{RULE_TYPE_BASIC, false, KSI_VerificationRule_AggregationHashChainConsistency},
	{RULE_TYPE_BASIC, false, KSI_VerificationRule_AggregationHashChainTimeConsistency},
	{RULE_TYPE_BASIC, false, KSI_VerificationRule_CalendarHashChainInputHashVerification},
	{RULE_TYPE_BASIC, false, KSI_VerificationRule_CalendarHashChainAggregationTime},
	{RULE_TYPE_BASIC, false, KSI_VerificationRule_CalendarHashChainRegistrationTime},
	{RULE_TYPE_BASIC, false, KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash},
	{RULE_TYPE_BASIC, false, KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime},
	{RULE_TYPE_BASIC, false, KSI_VerificationRule_SignaturePublicationRecordPublicationHash},
	{RULE_TYPE_BASIC, false, KSI_VerificationRule_SignaturePublicationRecordPublicationTime},
	{RULE_TYPE_BASIC, false, KSI_VerificationRule_DocumentHashVerification},
	{RULE_TYPE_BASIC, false, NULL}
};

int KSI_Policy_createCalendarBased(KSI_CTX *ctx, KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;

	static const Rule rules1[] = {
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_SignatureDoesNotContainPublication},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches},
		{RULE_TYPE_BASIC, false, NULL}
	};

	static const Rule rules2[] = {
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_SignaturePublicationRecordExistence},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash},
		{RULE_TYPE_BASIC, false, NULL}
	};

	static const Rule rules3[] = {
		{RULE_TYPE_COMPOSITE, true, rules1},
		{RULE_TYPE_COMPOSITE, true, rules2},
		{RULE_TYPE_COMPOSITE, true, NULL}
	};

	static const Rule rules4[] = {
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_CalendarHashChainDoesNotExist},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime}
	};

	static const Rule rules5[] = {
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_CalendarHashChainExistence},
		{RULE_TYPE_COMPOSITE, false, rules3},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime},
	};

	static const Rule rules6[] = {
		{RULE_TYPE_COMPOSITE, true, rules4},
		{RULE_TYPE_COMPOSITE, true, rules5},
		{RULE_TYPE_COMPOSITE, true, NULL}
	};

	static const Rule calendarBasedRules[] = {
		{RULE_TYPE_COMPOSITE, false, internalRules},
		{RULE_TYPE_COMPOSITE, false, rules6},
		{RULE_TYPE_COMPOSITE, false, NULL}
	};

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_Policy);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->fallbackPolicy = NULL;
	tmp->rules = calendarBasedRules;
	*policy = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);
	return res;
}

int KSI_Policy_createKeyBased(KSI_CTX *ctx, KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;

	static const Rule keyBasedRules[] = {
		{RULE_TYPE_COMPOSITE, false, internalRules},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_CalendarHashChainExistence},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_CalendarAuthenticationRecordExistence},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_CertificateExistence},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification},
		{RULE_TYPE_BASIC, false, NULL}
	};

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_Policy);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->fallbackPolicy = NULL;
	tmp->rules = keyBasedRules;
	*policy = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);
	return res;
}

int KSI_Policy_createPublicationsFileBased(KSI_CTX *ctx, KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;

	static const Rule publicationPresentRules[] = {
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_SignaturePublicationRecordExistence},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_PublicationsFileContainsSignaturePublication},
		{RULE_TYPE_BASIC, false, NULL}
	};
	static const Rule useExtendingRules[] = {
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_SignatureDoesNotContainPublication},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_PublicationsFileContainsPublication},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_ExtendingPermittedVerification},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_PublicationsFilePublicationTimeMatchesExtenderResponse},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash},
		{RULE_TYPE_BASIC, false, NULL}
	};

	static const Rule rules1[] = {
		{RULE_TYPE_COMPOSITE, true, publicationPresentRules},
		{RULE_TYPE_COMPOSITE, true, useExtendingRules},
		{RULE_TYPE_COMPOSITE, true, NULL}
	};

	static const Rule publicationsFileBasedRules[] = {
		{RULE_TYPE_COMPOSITE, false, internalRules},
		{RULE_TYPE_COMPOSITE, false, rules1},
		{RULE_TYPE_COMPOSITE, false, NULL}
	};

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_Policy);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->fallbackPolicy = NULL;
	tmp->rules = publicationsFileBasedRules;
	*policy = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);
	return res;
}

int KSI_Policy_createUserProvidedPublicationBased(KSI_CTX *ctx, KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;

	static const Rule userPublicationRules[] = {
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_SignaturePublicationRecordExistence},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_UserProvidedPublicationVerification},
		{RULE_TYPE_BASIC, false, NULL}
	};

	static const Rule useExtendingRules[] = {
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_ExtendingPermittedVerification},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash},
		{RULE_TYPE_BASIC, false, NULL}
	};

	static const Rule rules1[] = {
		{RULE_TYPE_COMPOSITE, true, userPublicationRules},
		{RULE_TYPE_COMPOSITE, true, useExtendingRules},
		{RULE_TYPE_COMPOSITE, true, NULL}
	};

	static const Rule userProvidedPublicationBasedRules[] = {
		{RULE_TYPE_COMPOSITE, false, internalRules},
		{RULE_TYPE_BASIC, false, KSI_VerificationRule_UserProvidedPublicationExistence},
		{RULE_TYPE_COMPOSITE, false, rules1},
		{RULE_TYPE_COMPOSITE, false, NULL}
	};

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_Policy);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->fallbackPolicy = NULL;
	tmp->rules = userProvidedPublicationBasedRules;
	*policy = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);
	return res;
}

static void PolicyResult_free(KSI_PolicyResult *result) {
	KSI_free(result);
}

static int PolicyVerificationResult_create(KSI_PolicyVerificationResult **result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PolicyVerificationResult *tmp = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(KSI_PolicyVerificationResult);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = KSI_PolicyResultList_new(&tmp->results);
	if (res != KSI_OK) {
		goto cleanup;
	}

	tmp->finalResult.resultCode = NA;
	tmp->finalResult.errorCode = GEN_2;
	*result = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_PolicyVerificationResult_free(tmp);
	return res;
}

static int PolicyVerificationResult_addResult(KSI_PolicyVerificationResult *result, KSI_PolicyResult *next) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL || next == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* TODO: Do we overwrite the final result? */
	result->finalResult = *next;
	res = KSI_PolicyResultList_append(result->results, next);

cleanup:

	return res;
}

static int Policy_verifySignature(KSI_Policy *policy, VerificationContext *context, KSI_PolicyResult **result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PolicyResult *tmp = NULL;

	if (policy == NULL || policy->rules == NULL || context == NULL || context->ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(KSI_PolicyResult);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = Rule_verify(policy->rules, context, tmp);
	if (res != KSI_OK) goto cleanup;

	*result = tmp;
	tmp = NULL;

cleanup:

	PolicyResult_free(tmp);
	return res;
}

int KSI_Policy_setFallback(KSI_CTX *ctx, KSI_Policy *policy, KSI_Policy *fallback) {
	int res = KSI_UNKNOWN_ERROR;

	if (ctx == NULL || policy == NULL || fallback == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	policy->fallbackPolicy = policy;
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Policy_verify(KSI_Policy *policy, VerificationContext *context, KSI_PolicyVerificationResult **result) {
	KSI_Policy *currentPolicy;
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_PolicyVerificationResult *tmp = NULL;
	KSI_PolicyResult *tmp_result = NULL;

	if (policy == NULL || context == NULL || context->ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = context->ctx;
	res = PolicyVerificationResult_create(&tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->finalResult.resultCode = NA;
	tmp->finalResult.errorCode = GEN_2;
	*result = tmp;
	tmp = NULL;

	currentPolicy = policy;
	while (currentPolicy != NULL) {
		res = Policy_verifySignature(currentPolicy, context, &tmp_result);
		/* Stop verifying the policy whenever there is an internal error (invalid arguments, out of memory, etc). */
		if (res != KSI_OK) goto cleanup;

		res = PolicyVerificationResult_addResult(*result, tmp_result);
		if (res != KSI_OK) goto cleanup;

		if (tmp_result->resultCode != OK) {
			currentPolicy = currentPolicy->fallbackPolicy;
		}
		else {
			currentPolicy = NULL;
		}
	}

	tmp_result = NULL;

cleanup:

	PolicyResult_free(tmp_result);
	KSI_PolicyVerificationResult_free(tmp);
	return res;
}

void KSI_Policy_free(KSI_Policy *policy) {
	KSI_free(policy);
}

void KSI_PolicyVerificationResult_free(KSI_PolicyVerificationResult *result) {
	if (result != NULL) {
		KSI_PolicyResultList_free(result->results);
		KSI_free(result);
	}
}

int KSI_VerificationContext_create(KSI_CTX *ctx, VerificationContext **context) {
	int res = KSI_UNKNOWN_ERROR;
	VerificationContext *tmp = NULL;

	if (ctx == NULL || context == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(VerificationContext);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->userData.sig = NULL;
	tmp->tempData.extendedSig = NULL;
	tmp->userData.documentHash = NULL;
	tmp->tempData.aggregationOutputHash = NULL;
	tmp->tempData.publicationsFile = NULL;
	tmp->userData.userPublication = NULL;
	*context = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_VerificationContext_free(tmp);
	return res;
}

void KSI_VerificationContext_free(VerificationContext *context) {
	if (context != NULL) {
		KSI_Signature_free(context->userData.sig);
		KSI_Signature_free(context->tempData.extendedSig);
		KSI_DataHash_free(context->userData.documentHash);
		KSI_DataHash_free(context->tempData.aggregationOutputHash);
		KSI_PublicationsFile_free(context->tempData.publicationsFile);
		KSI_PublicationData_free(context->userData.userPublication);
		KSI_free(context);
	}
}

void KSI_VerificationContext_clean(VerificationContext *context) {
	if (context != NULL) {
		KSI_Signature_free(context->tempData.extendedSig);
		context->tempData.extendedSig = NULL;
		KSI_DataHash_free(context->tempData.aggregationOutputHash);
		context->tempData.aggregationOutputHash = NULL;
		KSI_PublicationsFile_free(context->tempData.publicationsFile);
		context->tempData.publicationsFile = NULL;
	}
}
