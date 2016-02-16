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

static void Rule_free(Rule *rule);
static void CompositeRule_free(CompositeRule *rule);
static int BasicRule_verify(BasicRule *rule, VerificationContext *context);
static int CompositeRule_verify(CompositeRule *rule, VerificationContext *context);

KSI_IMPLEMENT_LIST(Rule, Rule_free);

static int Rule_create(Rule **rule) {
	int res = KSI_UNKNOWN_ERROR;
	Rule *tmp = NULL;

	if (rule == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(Rule);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	*rule = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	Rule_free(tmp);
	return res;
}

static int Rule_verify(Rule *rule, VerificationContext *context) {
	int res = KSI_UNKNOWN_ERROR;

	if (rule->type == RULE_TYPE_BASIC) {
		res = BasicRule_verify(rule->rule.basicRule, context);
		rule->result = rule->rule.basicRule->result;
	}
	else if (rule->type == RULE_TYPE_COMPOSITE) {
		res = CompositeRule_verify(rule->rule.compositeRule, context);
		rule->result = rule->rule.compositeRule->result;
	}
	return res;
}

static void Rule_free(Rule *rule) {
	if (rule != NULL) {
		if (rule->type == RULE_TYPE_BASIC) {
			KSI_free(rule->rule.basicRule);
		}
		if (rule->type == RULE_TYPE_COMPOSITE) {
			CompositeRule_free(rule->rule.compositeRule);
		}
		KSI_free(rule);
	}
}

static int BasicRule_create(Verifier verifier, Rule **rule) {
	int res = KSI_UNKNOWN_ERROR;
	Rule *tmp = NULL;

	if (verifier == NULL || rule == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = Rule_create(&tmp);
	if (res != KSI_OK) {
		goto cleanup;
	}

	tmp->rule.basicRule = KSI_new(BasicRule);
	if (tmp->rule.basicRule == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->rule.basicRule->verifySignature = verifier;
	tmp->type = RULE_TYPE_BASIC;
	*rule = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	Rule_free(tmp);
	return res;
}

static int BasicRule_verify(BasicRule *rule, VerificationContext *context) {
	return rule->verifySignature(context, &rule->result);
}

static int CompositeRule_create(bool skip, CompositeRule **rule) {
	int res = KSI_UNKNOWN_ERROR;
	CompositeRule *tmp = NULL;

	if (rule == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(CompositeRule);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->skipOnFirstOk = skip;
	res = RuleList_new(&tmp->rules);
	if (res != KSI_OK) {
		goto cleanup;
	}

	*rule = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	CompositeRule_free(tmp);
	return res;
}

static int CompositeRule_addBasicRule(CompositeRule *rule, Verifier verifier) {
	int res = KSI_UNKNOWN_ERROR;
	Rule *tmp = NULL;

	if (rule == NULL || verifier == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = BasicRule_create(verifier, &tmp);
	if (res != KSI_OK) {
		goto cleanup;
	}

	res = RuleList_append(rule->rules, tmp);
	if (res != KSI_OK) {
		goto cleanup;
	}

	tmp = NULL;
	res = KSI_OK;

cleanup:

	Rule_free(tmp);
	return res;
}

static int CompositeRule_addCompositeRule(CompositeRule *rule, CompositeRule *next) {
	int res = KSI_UNKNOWN_ERROR;
	Rule *tmp = NULL;

	if (rule == NULL || next == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(Rule);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->type = RULE_TYPE_COMPOSITE;
	tmp->rule.compositeRule = next;
	res = RuleList_append(rule->rules, tmp);
	if (res != KSI_OK) {
		goto cleanup;
	}

	tmp = NULL;
	res = KSI_OK;

cleanup:

	Rule_free(tmp);
	return res;
}

static int CompositeRule_verify(CompositeRule *rule, VerificationContext *context) {
	int i;
	int res = KSI_UNKNOWN_ERROR;

	rule->result.resultCode = OK;
	for (i = 0; i < RuleList_length(rule->rules); i++) {
		Rule *sub_rule;

		RuleList_elementAt(rule->rules, i, &sub_rule);
		res = Rule_verify(sub_rule, context);
		/* TODO: add rule result? */
		rule->result = sub_rule->result;
		if (rule->result.resultCode == OK && rule->skipOnFirstOk) {
			break;
		}
		if ((rule->result.resultCode == FAIL || rule->result.resultCode == NA) && !rule->skipOnFirstOk) {
			break;
		}
	}
	return res;
}

static void CompositeRule_free(CompositeRule *rule) {
	if (rule != NULL) {
		RuleList_free(rule->rules);
	}
	KSI_free(rule);
}

static int Policy_create(KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;

	if (policy == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(KSI_Policy);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = RuleList_new(&tmp->rules);
	if (res != KSI_OK) {
		goto cleanup;
	}

	tmp->fallbackPolicy = NULL;
	*policy = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_Policy_free(tmp);
	return res;
}

static int Policy_addBasicRule(KSI_Policy *policy, Verifier verifier) {
	int res = KSI_UNKNOWN_ERROR;
	Rule *tmp = NULL;

	if (policy == NULL || verifier == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = BasicRule_create(verifier, &tmp);
	if (res != KSI_OK) {
		goto cleanup;
	}

	res = RuleList_append(policy->rules, tmp);
	if (res != KSI_OK) {
		goto cleanup;
	}

	tmp = NULL;
	res = KSI_OK;

cleanup:

	Rule_free(tmp);
	return res;
}

static int Policy_addCompositeRule(KSI_Policy *policy, CompositeRule *next) {
	int res = KSI_UNKNOWN_ERROR;
	Rule *tmp = NULL;

	if (policy == NULL || next == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(Rule);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->type = RULE_TYPE_COMPOSITE;
	tmp->rule.compositeRule = next;
	res = RuleList_append(policy->rules, tmp);
	if (res != KSI_OK) {
		goto cleanup;
	}

	tmp = NULL;
	res = KSI_OK;

cleanup:

	Rule_free(tmp);
	return res;
}

#define TRY_CATCH(statement) \
	res = statement;\
	if (res != KSI_OK) {\
		KSI_pushError(ctx, res, NULL);\
		goto cleanup;\
	}\

static int KSI_Policy_createInternal(KSI_CTX *ctx, KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	TRY_CATCH(Policy_create(&tmp));

	TRY_CATCH(Policy_addBasicRule(tmp, KSI_VerificationRule_AggregationChainInputHashVerification));
	// verify aggregation hash chains
	TRY_CATCH(Policy_addBasicRule(tmp, KSI_VerificationRule_AggregationHashChainConsistency));
	TRY_CATCH(Policy_addBasicRule(tmp, KSI_VerificationRule_AggregationHashChainTimeConsistency));

	// verify calendar hash chain (if present)
	TRY_CATCH(Policy_addBasicRule(tmp, KSI_VerificationRule_CalendarHashChainInputHashVerification));
	TRY_CATCH(Policy_addBasicRule(tmp, KSI_VerificationRule_CalendarHashChainAggregationTime));
	TRY_CATCH(Policy_addBasicRule(tmp, KSI_VerificationRule_CalendarHashChainRegistrationTime));

	// verify calendar authentication record (if present)
	TRY_CATCH(Policy_addBasicRule(tmp, KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash));
	TRY_CATCH(Policy_addBasicRule(tmp, KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime));

	// verify publication record (if present)
	TRY_CATCH(Policy_addBasicRule(tmp, KSI_VerificationRule_SignaturePublicationRecordPublicationHash));
	TRY_CATCH(Policy_addBasicRule(tmp, KSI_VerificationRule_SignaturePublicationRecordPublicationTime));

	// verify document hash
	TRY_CATCH(Policy_addBasicRule(tmp, KSI_VerificationRule_DocumentHashVerification));

	*policy = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_Policy_free(tmp);
	return res;
}

int KSI_Policy_createCalendarBased(KSI_CTX *ctx, KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;
	CompositeRule *composite_rule1 = NULL;
	CompositeRule *composite_rule2 = NULL;
	CompositeRule *composite_rule3 = NULL;
	CompositeRule *composite_rule4 = NULL;
	CompositeRule *signatureDoesNotContainCalendarChainRule = NULL;
	CompositeRule *alreadyExtendedSignatureRule = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	TRY_CATCH(CompositeRule_create(false, &composite_rule2));
	TRY_CATCH(CompositeRule_addBasicRule(composite_rule2, KSI_VerificationRule_SignatureDoesNotContainPublication));
	TRY_CATCH(CompositeRule_addBasicRule(composite_rule2, KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches));

	TRY_CATCH(CompositeRule_create(false, &composite_rule3));
	TRY_CATCH(CompositeRule_addBasicRule(composite_rule3, KSI_VerificationRule_SignaturePublicationRecordExistence));
	TRY_CATCH(CompositeRule_addBasicRule(composite_rule3, KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash));

	TRY_CATCH(CompositeRule_create(true, &composite_rule1));
	TRY_CATCH(CompositeRule_addCompositeRule(composite_rule1, composite_rule2));
	TRY_CATCH(CompositeRule_addCompositeRule(composite_rule1, composite_rule3));

	TRY_CATCH(CompositeRule_create(false, &signatureDoesNotContainCalendarChainRule));
	TRY_CATCH(CompositeRule_addBasicRule(signatureDoesNotContainCalendarChainRule, KSI_VerificationRule_CalendarHashChainDoesNotExist));
	TRY_CATCH(CompositeRule_addBasicRule(signatureDoesNotContainCalendarChainRule, KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash));
	TRY_CATCH(CompositeRule_addBasicRule(signatureDoesNotContainCalendarChainRule, KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime));

	TRY_CATCH(CompositeRule_create(false, &alreadyExtendedSignatureRule));
	TRY_CATCH(CompositeRule_addBasicRule(alreadyExtendedSignatureRule, KSI_VerificationRule_CalendarHashChainExistence));
	TRY_CATCH(CompositeRule_addCompositeRule(alreadyExtendedSignatureRule, composite_rule1));
	TRY_CATCH(CompositeRule_addBasicRule(alreadyExtendedSignatureRule, KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash));
	TRY_CATCH(CompositeRule_addBasicRule(alreadyExtendedSignatureRule, KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime));

	TRY_CATCH(CompositeRule_create(true, &composite_rule4));
	TRY_CATCH(CompositeRule_addCompositeRule(composite_rule4, signatureDoesNotContainCalendarChainRule));
	TRY_CATCH(CompositeRule_addCompositeRule(composite_rule4, alreadyExtendedSignatureRule));

	/* First create internal verification policy. */
	TRY_CATCH(KSI_Policy_createInternal(ctx, &tmp));
	/* Then add all rules (extend) to internal verification policy. */
	TRY_CATCH(Policy_addCompositeRule(tmp, composite_rule4));

	*policy = tmp;
	tmp = NULL;
	composite_rule1 = NULL;
	composite_rule2 = NULL;
	composite_rule3 = NULL;
	composite_rule4 = NULL;
	signatureDoesNotContainCalendarChainRule = NULL;
	alreadyExtendedSignatureRule = NULL;
	res = KSI_OK;

cleanup:

	/* In what order should the rules be cleaned up? */
	CompositeRule_free(composite_rule1);
	CompositeRule_free(composite_rule2);
	CompositeRule_free(composite_rule3);
	CompositeRule_free(composite_rule4);
	CompositeRule_free(signatureDoesNotContainCalendarChainRule);
	CompositeRule_free(alreadyExtendedSignatureRule);
	KSI_Policy_free(tmp);

	return res;
}

int KSI_Policy_createKeyBased(KSI_CTX *ctx, KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

cleanup:

	KSI_Policy_free(tmp);

	return res;
}

int KSI_Policy_createPublicationsFileBased(KSI_CTX *ctx, KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

cleanup:

	KSI_Policy_free(tmp);

	return res;
}

int KSI_Policy_createUserProvidedPublicationBased(KSI_CTX *ctx, KSI_Policy **policy) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Policy *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || policy == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

cleanup:

	KSI_Policy_free(tmp);

	return res;
}

static int Policy_verifySignature(KSI_Policy *policy, VerificationContext *context) {
	int i;
	int res = KSI_UNKNOWN_ERROR;

	for (i = 0; i < RuleList_length(policy->rules); i++) {
		Rule *rule;

		RuleList_elementAt(policy->rules, i, &rule);
		res = Rule_verify(rule, context);
		policy->result = rule->result;
		/* Alternatively for more fine-tuned status: */
		/* Policy_resultSet(policy, rule->result); */
		if (policy->result.resultCode != OK) {
			break;
		}
	}
	return res;
}

int KSI_Policy_verify(KSI_Policy *policy, VerificationContext *context, KSI_PolicyVerificationResult **result) {
	KSI_Policy *currentPolicy;
	int res = KSI_UNKNOWN_ERROR;

	currentPolicy = policy;
	while (currentPolicy != NULL) {
		res = Policy_verifySignature(currentPolicy, context);
		/* TODO! Add each policy result to list of results. */
		if (currentPolicy->result.resultCode != OK) {
			currentPolicy = currentPolicy->fallbackPolicy;
		}
		else {
			currentPolicy = NULL;
		}
	}
	return res;
}

void KSI_Policy_free(KSI_Policy *policy) {
	if (policy != NULL) {
		RuleList_free(policy->rules);
		KSI_free(policy);
	}
}

