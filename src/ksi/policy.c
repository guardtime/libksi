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

static void RuleVerificationResult_free(KSI_RuleVerificationResult *result);

KSI_IMPLEMENT_LIST(KSI_RuleVerificationResult, RuleVerificationResult_free);

static int PolicyVerificationResult_addLatestRuleResult(KSI_PolicyVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RuleVerificationResult *tmp = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(KSI_RuleVerificationResult);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	*tmp = result->finalResult;

	res = KSI_RuleVerificationResultList_append(result->ruleResults, tmp);
	if (res != KSI_OK) goto cleanup;

	tmp = NULL;

cleanup:

	RuleVerificationResult_free(tmp);
	return res;
}

static int Rule_verify(const Rule *rule, KSI_VerificationContext *context, KSI_PolicyVerificationResult *policyResult) {
	int res = KSI_UNKNOWN_ERROR;
	const Rule *currentRule = NULL;

	if (rule == NULL || context == NULL || policyResult == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	currentRule = rule;
	while (currentRule->rule) {
		policyResult->finalResult.resultCode = VER_RES_NA;
		policyResult->finalResult.errorCode = VER_ERR_GEN_2;
		switch (currentRule->type) {
			case RULE_TYPE_BASIC:
				res = ((Verifier)(currentRule->rule))(context, &policyResult->finalResult);
				KSI_LOG_debug(context->ctx, "Rule result: %i %i %i %s %s",
							  res,
							  policyResult->finalResult.resultCode,
							  policyResult->finalResult.errorCode,
							  policyResult->finalResult.ruleName,
							  policyResult->finalResult.policyName);
				break;

			case RULE_TYPE_COMPOSITE_AND:
			case RULE_TYPE_COMPOSITE_OR:
				res = Rule_verify((Rule *)currentRule->rule, context, policyResult);
				break;

			default:
				res = KSI_INVALID_ARGUMENT;
				break;
		}

		if (currentRule->type == RULE_TYPE_BASIC && !(res == KSI_OK && policyResult->finalResult.resultCode == VER_RES_NA)) {
			/* For better readability, only add results of basic rules which do not confirm lack or existence of a component. */
			PolicyVerificationResult_addLatestRuleResult(policyResult);
		}

		if (res != KSI_OK) {
			/* If verification cannot be completed due to an internal error, no more rules should be processed. */
			break;
		} else if (policyResult->finalResult.resultCode == VER_RES_FAIL) {
			/* If a rule fails, no more rules in the policy should be processed. */
			break;
		} else if (policyResult->finalResult.resultCode == VER_RES_OK) {
			/* If a rule succeeds, the following OR-type rules should be skipped. */
			if (currentRule->type == RULE_TYPE_COMPOSITE_OR) {
				break;
			}
		} else /* if (ruleResult.resultCode == VER_RES_NA) */ {
			/* If an OR-type rule result is not conclusive, the next rule should be processed. */
			if (currentRule->type == RULE_TYPE_BASIC || currentRule->type == RULE_TYPE_COMPOSITE_AND) {
				break;
			}
		}
		currentRule++;
	}

cleanup:

	return res;
}

static const Rule noCalendarAuthenticationRecordRule[] = {
	{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordDoesNotExist},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule calendarAuthenticationRecordVerificationRule[] = {
	{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordExistence},
	{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash},
	{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule publicationRecordVerificationRule[] = {
	{RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordExistence},
	{RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordPublicationHash},
	{RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordPublicationTime},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule calendarAuthenticationRecordRule[] = {
	{RULE_TYPE_COMPOSITE_OR, noCalendarAuthenticationRecordRule},
	{RULE_TYPE_COMPOSITE_OR, calendarAuthenticationRecordVerificationRule},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule noPublicationRecordRule[] = {
	{RULE_TYPE_BASIC, KSI_VerificationRule_SignatureDoesNotContainPublication},
	{RULE_TYPE_COMPOSITE_AND, calendarAuthenticationRecordRule},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule publicationOrCalendarAuthenticationRecordRule[] = {
	{RULE_TYPE_COMPOSITE_OR, noPublicationRecordRule},
	{RULE_TYPE_COMPOSITE_OR, publicationRecordVerificationRule},
	{RULE_TYPE_COMPOSITE_OR, NULL}
};

static const Rule noCalendarHashChainRule[] = {
	{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainDoesNotExist},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule calendarHashChainVerificationRule[] = {
	{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainExistence},
	{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainInputHashVerification},
	{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainAggregationTime},
	{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainRegistrationTime},
	{RULE_TYPE_COMPOSITE_AND, publicationOrCalendarAuthenticationRecordRule},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule calendarHashChainRule[] = {
	{RULE_TYPE_COMPOSITE_OR, noCalendarHashChainRule},
	{RULE_TYPE_COMPOSITE_OR, calendarHashChainVerificationRule},
	{RULE_TYPE_COMPOSITE_OR, NULL}
};

static const Rule noDocumentHashRule[] = {
	{RULE_TYPE_BASIC, KSI_VerificationRule_DocumentHashDoesNotExist},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule documentHashVerificationRule[] = {
	{RULE_TYPE_BASIC, KSI_VerificationRule_DocumentHashExistence},
	{RULE_TYPE_BASIC, KSI_VerificationRule_DocumentHashVerification},
	{RULE_TYPE_BASIC, NULL}
};

static const Rule documentHashRule[] = {
	{RULE_TYPE_COMPOSITE_OR, noDocumentHashRule},
	{RULE_TYPE_COMPOSITE_OR, documentHashVerificationRule},
	{RULE_TYPE_COMPOSITE_OR, NULL}
};

static const Rule internalRules[] = {
	{RULE_TYPE_BASIC, KSI_VerificationRule_AggregationChainInputHashVerification},
	{RULE_TYPE_BASIC, KSI_VerificationRule_AggregationHashChainConsistency},
	{RULE_TYPE_BASIC, KSI_VerificationRule_AggregationHashChainTimeConsistency},
	{RULE_TYPE_COMPOSITE_AND, calendarHashChainRule},
	{RULE_TYPE_COMPOSITE_AND, documentHashRule},
	{RULE_TYPE_BASIC, NULL}
};

int KSI_Policy_getInternal(KSI_CTX *ctx, const KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;

	static const KSI_Policy internalPolicy = {
		internalRules,
		NULL,
		"InternalPolicy"
	};

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	*policy = &internalPolicy;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Policy_getCalendarBased(KSI_CTX *ctx, const KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;

	static const Rule rules1[] = {
		{RULE_TYPE_BASIC, KSI_VerificationRule_SignatureDoesNotContainPublication},
		{RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches},
		{RULE_TYPE_BASIC, NULL}
	};

	static const Rule rules2[] = {
		{RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordExistence},
		{RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash},
		{RULE_TYPE_BASIC, NULL}
	};

	static const Rule rules3[] = {
		{RULE_TYPE_COMPOSITE_OR, rules1},
		{RULE_TYPE_COMPOSITE_OR, rules2},
		{RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const Rule rules4[] = {
		{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainDoesNotExist},
		{RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash},
		{RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime},
		{RULE_TYPE_BASIC, NULL}
	};

	static const Rule rules5[] = {
		{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainExistence},
		{RULE_TYPE_COMPOSITE_AND, rules3},
		{RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash},
		{RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime},
		{RULE_TYPE_BASIC, NULL}
	};

	static const Rule rules6[] = {
		{RULE_TYPE_COMPOSITE_OR, rules4},
		{RULE_TYPE_COMPOSITE_OR, rules5},
		{RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const Rule calendarBasedRules[] = {
		{RULE_TYPE_COMPOSITE_AND, internalRules},
		{RULE_TYPE_COMPOSITE_AND, rules6},
		{RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const KSI_Policy calendarBasedPolicy = {
		calendarBasedRules,
		NULL,
		"CalendarBasedPolicy"
	};

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	*policy = &calendarBasedPolicy;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Policy_getKeyBased(KSI_CTX *ctx, const KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;

	static const Rule keyBasedRules[] = {
		{RULE_TYPE_COMPOSITE_AND, internalRules},
		{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainExistence},
		{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordExistence},
		{RULE_TYPE_BASIC, KSI_VerificationRule_CertificateExistence},
		{RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification},
		{RULE_TYPE_BASIC, NULL}
	};

	static const KSI_Policy keyBasedPolicy = {
		keyBasedRules,
		NULL,
		"KeyBasedPolicy"
	};

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	*policy = &keyBasedPolicy;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Policy_getPublicationsFileBased(KSI_CTX *ctx, const KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;

	static const Rule publicationPresentRules[] = {
		{RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordExistence},
		{RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileContainsSignaturePublication},
		{RULE_TYPE_BASIC, NULL}
	};
	static const Rule useExtendingRules[] = {
		{RULE_TYPE_BASIC, KSI_VerificationRule_SignatureDoesNotContainPublication},
		{RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileContainsPublication},
		{RULE_TYPE_BASIC, KSI_VerificationRule_ExtendingPermittedVerification},
		{RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse},
		{RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFilePublicationTimeMatchesExtenderResponse},
		{RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash},
		{RULE_TYPE_BASIC, NULL}
	};

	static const Rule rules1[] = {
		{RULE_TYPE_COMPOSITE_OR, publicationPresentRules},
		{RULE_TYPE_COMPOSITE_OR, useExtendingRules},
		{RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const Rule publicationsFileBasedRules[] = {
		{RULE_TYPE_COMPOSITE_AND, internalRules},
		{RULE_TYPE_COMPOSITE_AND, rules1},
		{RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const KSI_Policy publicationsFileBasedPolicy = {
		publicationsFileBasedRules,
		NULL,
		"PublicationsFileBasedPolicy"
	};

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	*policy = &publicationsFileBasedPolicy;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Policy_getUserProvidedPublicationBased(KSI_CTX *ctx, const KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;

	static const Rule userPublicationRules[] = {
		{RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordExistence},
		{RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationVerification},
		{RULE_TYPE_BASIC, NULL}
	};

	static const Rule useExtendingRules[] = {
		{RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification},
		{RULE_TYPE_BASIC, KSI_VerificationRule_ExtendingPermittedVerification},
		{RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse},
		{RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse},
		{RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash},
		{RULE_TYPE_BASIC, NULL}
	};

	static const Rule rules1[] = {
		{RULE_TYPE_COMPOSITE_OR, userPublicationRules},
		{RULE_TYPE_COMPOSITE_OR, useExtendingRules},
		{RULE_TYPE_COMPOSITE_OR, NULL}
	};

	static const Rule userProvidedPublicationBasedRules[] = {
		{RULE_TYPE_COMPOSITE_AND, internalRules},
		{RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationExistence},
		{RULE_TYPE_COMPOSITE_AND, rules1},
		{RULE_TYPE_COMPOSITE_AND, NULL}
	};

	static const KSI_Policy userProvidedPublicationBasedPolicy = {
		userProvidedPublicationBasedRules,
		NULL,
		"UserProvidedPublicationBasedPolicy"
	};

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	*policy = &userProvidedPublicationBasedPolicy;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Policy_clone(KSI_CTX *ctx, const KSI_Policy *policy, KSI_Policy **clone) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL || clone == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_Policy);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->rules = policy->rules;
	tmp->fallbackPolicy = policy->fallbackPolicy;
	tmp->policyName = policy->policyName;
	*clone = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Policy_free(tmp);
	return res;
}

static void RuleVerificationResult_free(KSI_RuleVerificationResult *result) {
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

	res = KSI_RuleVerificationResultList_new(&tmp->ruleResults);
	if (res != KSI_OK) {
		goto cleanup;
	}

	res = KSI_RuleVerificationResultList_new(&tmp->policyResults);
	if (res != KSI_OK) {
		goto cleanup;
	}

	tmp->finalResult.resultCode = VER_RES_NA;
	tmp->finalResult.errorCode = VER_ERR_GEN_2;
	*result = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_PolicyVerificationResult_free(tmp);
	return res;
}

static int PolicyVerificationResult_addLatestPolicyResult(KSI_PolicyVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RuleVerificationResult *tmp = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(KSI_RuleVerificationResult);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	*tmp = result->finalResult;
	res = KSI_RuleVerificationResultList_append(result->policyResults, tmp);
	if (res != KSI_OK) goto cleanup;

	tmp = NULL;

cleanup:

	RuleVerificationResult_free(tmp);
	return res;
}

static int Policy_verifySignature(const KSI_Policy *policy, KSI_VerificationContext *context, KSI_PolicyVerificationResult *policyResult) {
	int res = KSI_UNKNOWN_ERROR;

	if (policy == NULL || policy->rules == NULL || context == NULL || context->ctx == NULL || policyResult == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = Rule_verify(policy->rules, context, policyResult);
	if (res != KSI_OK) goto cleanup;

cleanup:

	return res;
}

int KSI_Policy_setFallback(KSI_CTX *ctx, KSI_Policy *policy, const KSI_Policy *fallback) {
	int res = KSI_UNKNOWN_ERROR;

	if (ctx == NULL || policy == NULL || fallback == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	policy->fallbackPolicy = fallback;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_SignatureVerifier_verify(const KSI_Policy *policy, KSI_VerificationContext *context, KSI_PolicyVerificationResult **result) {
	const KSI_Policy *currentPolicy;
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_PolicyVerificationResult *tmp = NULL;

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

	tmp->finalResult.resultCode = VER_RES_NA;
	tmp->finalResult.errorCode = VER_ERR_GEN_2;
	tmp->finalResult.stepsPerformed = 0;
	tmp->finalResult.stepsFailed = 0;
	tmp->finalResult.stepsSuccessful = 0;
	*result = tmp;
	tmp = NULL;

	currentPolicy = policy;
	while (currentPolicy != NULL) {
		(*result)->finalResult.policyName = currentPolicy->policyName;
		res = Policy_verifySignature(currentPolicy, context, *result);
		/* Stop verifying the policy whenever there is an internal error (invalid arguments, out of memory, etc). */
		if (res != KSI_OK) goto cleanup;

		res = PolicyVerificationResult_addLatestPolicyResult(*result);
		if (res != KSI_OK) goto cleanup;

		if ((*result)->finalResult.resultCode != VER_RES_OK) {
			currentPolicy = currentPolicy->fallbackPolicy;
			if (currentPolicy != NULL) {
				KSI_VerificationContext_clean(context);
				KSI_LOG_debug(ctx, "Verifying fallback policy");
			}
		} else {
			currentPolicy = NULL;
		}
	}

cleanup:

	KSI_PolicyVerificationResult_free(tmp);
	return res;
}

void KSI_Policy_free(KSI_Policy *policy) {
	KSI_free(policy);
}

void KSI_PolicyVerificationResult_free(KSI_PolicyVerificationResult *result) {
	if (result != NULL) {
		KSI_RuleVerificationResultList_free(result->ruleResults);
		KSI_RuleVerificationResultList_free(result->policyResults);
		KSI_free(result);
	}
}

int KSI_VerificationContext_create(KSI_CTX *ctx, KSI_VerificationContext **context) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_VerificationContext *tmp = NULL;

	if (ctx == NULL || context == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(KSI_VerificationContext);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->userData.sig = NULL;
	tmp->userData.extendingAllowed = 0;
	tmp->userData.docAggrLevel = 0;
	tmp->tempData.extendedSig = NULL;
	tmp->userData.documentHash = NULL;
	tmp->tempData.aggregationOutputHash = NULL;
	tmp->tempData.publicationsFile = NULL;
	tmp->userData.userPublication = NULL;
	tmp->userData.userPublicationsFile = NULL;
	*context = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_VerificationContext_free(tmp);
	return res;
}

#define CONTEXT_DEFINE_SETTER(baseType, valueType, valueName, alias) int baseType##_set##alias(baseType *o, valueType valueName)

#define CONTEXT_IMPLEMENT_SETTER(baseType, valueType, valueName, alias)			\
CONTEXT_DEFINE_SETTER(baseType, valueType, valueName, alias) {					\
	int res = KSI_UNKNOWN_ERROR;											\
	if (o == NULL) {														\
		res = KSI_INVALID_ARGUMENT;											\
		goto cleanup;														\
	}																		\
	o->userData.valueName = valueName;												\
	res = KSI_OK;															\
cleanup:																	\
	return res;																\
}																			\

CONTEXT_IMPLEMENT_SETTER(KSI_VerificationContext, KSI_Signature *, sig, Signature);
CONTEXT_IMPLEMENT_SETTER(KSI_VerificationContext, KSI_DataHash *, documentHash, DocumentHash);
CONTEXT_IMPLEMENT_SETTER(KSI_VerificationContext, KSI_PublicationData *, userPublication, UserPublication);
CONTEXT_IMPLEMENT_SETTER(KSI_VerificationContext, KSI_PublicationsFile *, userPublicationsFile, PublicationsFile);
CONTEXT_IMPLEMENT_SETTER(KSI_VerificationContext, int, extendingAllowed, ExtendingAllowed);
CONTEXT_IMPLEMENT_SETTER(KSI_VerificationContext, KSI_uint64_t, docAggrLevel, AggregationLevel);

void KSI_VerificationContext_free(KSI_VerificationContext *context) {
	if (context != NULL) {
		KSI_Signature_free(context->userData.sig);
		KSI_Signature_free(context->tempData.extendedSig);
		KSI_DataHash_free(context->userData.documentHash);
		KSI_DataHash_free(context->tempData.aggregationOutputHash);
		KSI_nofree(context->tempData.publicationsFile);
		KSI_PublicationsFile_free(context->userData.userPublicationsFile);
		KSI_PublicationData_free(context->userData.userPublication);
		KSI_free(context);
	}
}

void KSI_VerificationContext_clean(KSI_VerificationContext *context) {
	if (context != NULL) {
		KSI_Signature_free(context->tempData.extendedSig);
		context->tempData.extendedSig = NULL;
		KSI_DataHash_free(context->tempData.aggregationOutputHash);
		context->tempData.aggregationOutputHash = NULL;
		KSI_nofree(context->tempData.publicationsFile);
	}
}
