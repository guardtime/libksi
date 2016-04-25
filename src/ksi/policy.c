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

static int Rule_verify(const KSI_Rule *rule, KSI_VerificationContext *context, KSI_PolicyVerificationResult *policyResult) {
	int res = KSI_UNKNOWN_ERROR;
	const KSI_Rule *currentRule = NULL;

	if (rule == NULL || context == NULL || policyResult == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	currentRule = rule;
	while (currentRule->rule) {
		policyResult->finalResult.resultCode = KSI_VER_RES_NA;
		policyResult->finalResult.errorCode = KSI_VER_ERR_GEN_2;
		switch (currentRule->type) {
			case KSI_RULE_TYPE_BASIC:
				res = ((Verifier)(currentRule->rule))(context, &policyResult->finalResult);
				KSI_LOG_debug(context->ctx, "Rule result: %i %i %i %s %s",
							  res,
							  policyResult->finalResult.resultCode,
							  policyResult->finalResult.errorCode,
							  policyResult->finalResult.ruleName,
							  policyResult->finalResult.policyName);
				break;

			case KSI_RULE_TYPE_COMPOSITE_AND:
			case KSI_RULE_TYPE_COMPOSITE_OR:
				res = Rule_verify((KSI_Rule *)currentRule->rule, context, policyResult);
				break;

			default:
				res = KSI_INVALID_ARGUMENT;
				break;
		}

		if (currentRule->type == KSI_RULE_TYPE_BASIC && !(res == KSI_OK && policyResult->finalResult.resultCode == KSI_VER_RES_NA)) {
			/* For better readability, only add results of basic rules which do not confirm lack or existence of a component. */
			PolicyVerificationResult_addLatestRuleResult(policyResult);
		}

		if (res != KSI_OK) {
			/* If verification cannot be completed due to an internal error, no more rules should be processed. */
			break;
		} else if (policyResult->finalResult.resultCode == KSI_VER_RES_FAIL) {
			/* If a rule fails, no more rules in the policy should be processed. */
			break;
		} else if (policyResult->finalResult.resultCode == KSI_VER_RES_OK) {
			/* If a rule succeeds, the following OR-type rules should be skipped. */
			if (currentRule->type == KSI_RULE_TYPE_COMPOSITE_OR) {
				break;
			}
		} else /* if (ruleResult.resultCode == VER_RES_NA) */ {
			/* If an OR-type rule result is not conclusive, the next rule should be processed. */
			if (currentRule->type == KSI_RULE_TYPE_BASIC || currentRule->type == KSI_RULE_TYPE_COMPOSITE_AND) {
				break;
			}
		}
		currentRule++;
	}

cleanup:

	return res;
}

/******************
 * INTERNAL POLICY
 ******************/

static const KSI_Rule noCalendarAuthenticationRecordRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordDoesNotExist},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule calendarAuthenticationRecordVerificationRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule publicationRecordVerificationRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordPublicationHash},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordPublicationTime},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule calendarAuthenticationRecordRule[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, noCalendarAuthenticationRecordRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, calendarAuthenticationRecordVerificationRule},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule noPublicationRecordRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignatureDoesNotContainPublication},
	{KSI_RULE_TYPE_COMPOSITE_AND, calendarAuthenticationRecordRule},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule publicationOrCalendarAuthenticationRecordRule[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, noPublicationRecordRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, publicationRecordVerificationRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

static const KSI_Rule noCalendarHashChainRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainDoesNotExist},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule calendarHashChainVerificationRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainInputHashVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainAggregationTime},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainRegistrationTime},
	{KSI_RULE_TYPE_COMPOSITE_AND, publicationOrCalendarAuthenticationRecordRule},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule calendarHashChainRule_int[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, noCalendarHashChainRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, calendarHashChainVerificationRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

static const KSI_Rule noDocumentHashRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_DocumentHashDoesNotExist},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule documentHashVerificationRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_DocumentHashExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_DocumentHashVerification},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule documentHashRule[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, noDocumentHashRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, documentHashVerificationRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

static const KSI_Rule internalRules[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationChainInputHashVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationHashChainConsistency},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationHashChainTimeConsistency},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationHashChainIndexConsistency},
	{KSI_RULE_TYPE_COMPOSITE_AND, calendarHashChainRule_int},
	{KSI_RULE_TYPE_COMPOSITE_AND, documentHashRule},
	{KSI_RULE_TYPE_BASIC, NULL}
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

/************************
 * CALENDAR-BASED POLICY
 ************************/

static const KSI_Rule CalendarChainRightLinksVerificationRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignatureDoesNotContainPublication},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainRightLinksMatch},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule CalendarChainRootHashVerificationRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule publicationRecordRule_cal[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, CalendarChainRightLinksVerificationRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, CalendarChainRootHashVerificationRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

static const KSI_Rule extendToHeadRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainDoesNotExist},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule extendToCalendarChainRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainExistence},
	{KSI_RULE_TYPE_COMPOSITE_AND, publicationRecordRule_cal},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule calendarHashChainRule_cal[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, extendToHeadRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, extendToCalendarChainRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

static const KSI_Rule calendarBasedRules[] = {
	{KSI_RULE_TYPE_COMPOSITE_AND, internalRules},
	{KSI_RULE_TYPE_COMPOSITE_AND, calendarHashChainRule_cal},
	{KSI_RULE_TYPE_COMPOSITE_AND, NULL}
};

int KSI_Policy_getCalendarBased(KSI_CTX *ctx, const KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;

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

/*******************
 * KEY-BASED POLICY
 *******************/

static const KSI_Rule keyBasedRules[] = {
	{KSI_RULE_TYPE_COMPOSITE_AND, internalRules},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CertificateExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification},
	{KSI_RULE_TYPE_BASIC, NULL}
};

int KSI_Policy_getKeyBased(KSI_CTX *ctx, const KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;

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

/*********************************************
 * PUBLICATION-BASED POLICY: PUBLICATION FILE
 *********************************************/

static const KSI_Rule publicationPresentRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileContainsSignaturePublication},
	{KSI_RULE_TYPE_BASIC, NULL}
};
static const KSI_Rule extendToPublicationRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignatureDoesNotContainPublication},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileContainsPublication},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendingPermittedVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFilePublicationTimeMatchesExtenderResponse},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule publicationRecordRule_pubFile[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, publicationPresentRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, extendToPublicationRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

static const KSI_Rule publicationsFileBasedRules[] = {
	{KSI_RULE_TYPE_COMPOSITE_AND, internalRules},
	{KSI_RULE_TYPE_COMPOSITE_AND, publicationRecordRule_pubFile},
	{KSI_RULE_TYPE_COMPOSITE_AND, NULL}
};

int KSI_Policy_getPublicationsFileBased(KSI_CTX *ctx, const KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;

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

/*********************************************
 * PUBLICATION-BASED POLICY: USER PUBLICATION
 *********************************************/

static const KSI_Rule userPublicationMatchRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationVerification},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule extendToUserPublicationRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendingPermittedVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule publicationRecordRule_pubString[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, userPublicationMatchRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, extendToUserPublicationRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

static const KSI_Rule userProvidedPublicationBasedRules[] = {
	{KSI_RULE_TYPE_COMPOSITE_AND, internalRules},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationExistence},
	{KSI_RULE_TYPE_COMPOSITE_AND, publicationRecordRule_pubString},
	{KSI_RULE_TYPE_COMPOSITE_AND, NULL}
};

int KSI_Policy_getUserProvidedPublicationBased(KSI_CTX *ctx, const KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;

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

/*****************
 * GENERAL POLICY
 *****************/

static const KSI_Rule generalRules[] = {
	{KSI_RULE_TYPE_COMPOSITE_AND, internalRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, keyBasedRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, publicationsFileBasedRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, userProvidedPublicationBasedRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, calendarBasedRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

int KSI_Policy_getGeneral(KSI_CTX *ctx, const KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;

	static const KSI_Policy generalPolicy = {
		generalRules,
		NULL,
		"GeneralPolicy"
	};

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	*policy = &generalPolicy;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_Policy_create(KSI_CTX *ctx, const KSI_Rule *rules, const char *name, KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || rules == NULL || name == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_Policy);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->rules = rules;
	tmp->policyName = name;
	tmp->fallbackPolicy = NULL;
	*policy = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Policy_free(tmp);
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
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
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

	tmp->finalResult.resultCode = KSI_VER_RES_NA;
	tmp->finalResult.errorCode = KSI_VER_ERR_GEN_2;
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
	KSI_LOG_debug(context->ctx, "Policy result: %i %i %i %s %s",
				  res,
				  policyResult->finalResult.resultCode,
				  policyResult->finalResult.errorCode,
				  policyResult->finalResult.ruleName,
				  policyResult->finalResult.policyName);
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
	KSI_ERR_clearErrors(ctx);

	res = PolicyVerificationResult_create(&tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->finalResult.resultCode = KSI_VER_RES_NA;
	tmp->finalResult.errorCode = KSI_VER_ERR_GEN_2;
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
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		res = PolicyVerificationResult_addLatestPolicyResult(*result);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if ((*result)->finalResult.resultCode != KSI_VER_RES_OK) {
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
	KSI_ERR_clearErrors(ctx);

	tmp = KSI_new(KSI_VerificationContext);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
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
