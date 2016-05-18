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
#include "hashchain.h"

#include <string.h>

static void RuleVerificationResult_free(KSI_RuleVerificationResult *result);
static void VerificationTempData_clear(VerificationTempData *tmp);

KSI_IMPLEMENT_LIST(KSI_RuleVerificationResult, RuleVerificationResult_free);

static int isDuplicateRuleResult(KSI_RuleVerificationResultList *resultList, KSI_RuleVerificationResult *result) {
	int return_value = 0;
	size_t i;

	for (i = 0; i < KSI_RuleVerificationResultList_length(resultList); i++) {
		int res;
		KSI_RuleVerificationResult *tmp = NULL;
		res = KSI_RuleVerificationResultList_elementAt(resultList, i, &tmp);
		if (res != KSI_OK) goto cleanup;
		/* Compare only unique rule name pointers instead of full rule names. */
		if (tmp->ruleName == result->ruleName) {
			return_value = 1;
			break;
		}
	}

cleanup:
	return return_value;
}

static int PolicyVerificationResult_addLatestRuleResult(KSI_PolicyVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RuleVerificationResult *tmp = NULL;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (isDuplicateRuleResult(result->ruleResults, &result->finalResult) == 0) {
		tmp = KSI_new(KSI_RuleVerificationResult);
		if (tmp == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}

		*tmp = result->finalResult;
		res = KSI_RuleVerificationResultList_append(result->ruleResults, tmp);
		if (res != KSI_OK) goto cleanup;
		tmp = NULL;
	}

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

		/* Duplicate the value for ease of use. */
		policyResult->resultCode = policyResult->finalResult.resultCode;

		if (currentRule->type == KSI_RULE_TYPE_BASIC && !(res == KSI_OK && policyResult->resultCode == KSI_VER_RES_NA)) {
			/* For better readability, only add results of basic rules which do not confirm lack or existence of a component. */
			PolicyVerificationResult_addLatestRuleResult(policyResult);
		}

		if (res != KSI_OK) {
			/* If verification cannot be completed due to an internal error, no more rules should be processed. */
			break;
		} else if (policyResult->resultCode == KSI_VER_RES_FAIL) {
			/* If a rule fails, no more rules in the policy should be processed. */
			break;
		} else if (policyResult->resultCode == KSI_VER_RES_OK) {
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

static const KSI_Policy PolicyInternal = {
	internalRules,
	NULL,
	"InternalPolicy"
};

const KSI_Policy* KSI_VERIFICATION_POLICY_INTERNAL = &PolicyInternal;


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

static const KSI_Policy PolicyCalendarBased = {
	calendarBasedRules,
	NULL,
	"CalendarBasedPolicy"
};

const KSI_Policy* KSI_VERIFICATION_POLICY_CALENDAR_BASED = &PolicyCalendarBased;

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

static const KSI_Policy PolicyKeyBased = {
	keyBasedRules,
	NULL,
	"KeyBasedPolicy"
};

const KSI_Policy* KSI_VERIFICATION_POLICY_KEY_BASED = &PolicyKeyBased;

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

static const KSI_Policy PolicyPublicationsFileBased = {
	publicationsFileBasedRules,
	NULL,
	"PublicationsFileBasedPolicy"
};

const KSI_Policy* KSI_VERIFICATION_POLICY_PUBLICATIONS_FILE_BASED = &PolicyPublicationsFileBased;

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

static const KSI_Policy PolicyUserPublicationBased = {
	userProvidedPublicationBasedRules,
	NULL,
	"UserProvidedPublicationBasedPolicy"
};

const KSI_Policy* KSI_VERIFICATION_POLICY_USER_PUBLICATION_BASED = &PolicyUserPublicationBased;

/*****************
 * GENERAL POLICY
 *****************/

static const KSI_Rule generalRules[] = {
	{KSI_RULE_TYPE_COMPOSITE_AND, internalRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, publicationsFileBasedRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, userProvidedPublicationBasedRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, keyBasedRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, calendarBasedRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

static const KSI_Policy PolicyGeneral = {
	generalRules,
	NULL,
	"GeneralPolicy"
};

const KSI_Policy* KSI_VERIFICATION_POLICY_GENERAL = &PolicyGeneral;

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
	VerificationTempData tempData;

	memset(&tempData, 0, sizeof(tempData));
	tempData.aggregationOutputHash = NULL;
	tempData.calendarChain = NULL;
	tempData.publicationsFile = NULL;

	if (policy == NULL || context == NULL || context->ctx == NULL || result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}


	context->tempData = &tempData;

	ctx = context->ctx;
	KSI_ERR_clearErrors(ctx);

	res = PolicyVerificationResult_create(&tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->resultCode = KSI_VER_RES_NA;
	tmp->finalResult.resultCode = KSI_VER_RES_NA;
	tmp->finalResult.errorCode = KSI_VER_ERR_GEN_2;
	tmp->finalResult.stepsPerformed = 0;
	tmp->finalResult.stepsFailed = 0;
	tmp->finalResult.stepsSuccessful = 0;

	currentPolicy = policy;
	while (currentPolicy != NULL) {
		tmp->finalResult.policyName = currentPolicy->policyName;
		res = Policy_verifySignature(currentPolicy, context, tmp);
		if (res != KSI_OK) {
			/* Stop verifying the policy whenever there is an internal error (invalid arguments, out of memory, etc). */
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		res = PolicyVerificationResult_addLatestPolicyResult(tmp);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (tmp->finalResult.resultCode != KSI_VER_RES_OK) {
			currentPolicy = currentPolicy->fallbackPolicy;
			if (currentPolicy != NULL) {
				VerificationTempData_clear(context->tempData);
				KSI_LOG_debug(ctx, "Verifying fallback policy.");
			}
		} else {
			currentPolicy = NULL;
		}
	}

	*result = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	VerificationTempData_clear(&tempData);
	if (context != NULL) {
		context->tempData = NULL;
	}

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

static void VerificationTempData_clear(VerificationTempData *tmp) {
	if (tmp != NULL) {
		KSI_DataHash_free(tmp->aggregationOutputHash);
		tmp->aggregationOutputHash = NULL;

		KSI_CalendarHashChain_free(tmp->calendarChain);
		tmp->calendarChain = NULL;

		KSI_PublicationsFile_free(tmp->publicationsFile);
		tmp->publicationsFile = NULL;
	}
}

void KSI_VerificationContext_clean(KSI_VerificationContext *context) {
	if (context != NULL) {
		if (context->tempData != NULL) {
			VerificationTempData_clear(context->tempData);
		}
		context->tempData = NULL;
		KSI_nofree(context);
	}
}

int KSI_VerificationContext_init(KSI_VerificationContext *context, KSI_CTX *ctx) {
	int res = KSI_UNKNOWN_ERROR;
	if (context == NULL || ctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	context->ctx = NULL;
	context->signature = NULL;
	context->extendingAllowed = 0;
	context->docAggrLevel = 0;
	context->documentHash = NULL;
	context->userPublication = NULL;
	context->userPublicationsFile = NULL;

	context->tempData = NULL;

	context->ctx = ctx;
	context->signature = NULL;

	res = KSI_OK;

cleanup:

	return res;

}
