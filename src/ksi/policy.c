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

static void Rule_verify(Rule *rule, VerificationContext *context);

static void Rule_free(Rule *rule);

KSI_IMPLEMENT_LIST(Rule, Rule_free);

static void CompositeRule_free(CompositeRule *rule) {
	if (rule != NULL) {
		RuleList_free(rule->rules);
	}
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

BasicRule_verify(BasicRule *rule, VerificationContext *context) {
	rule->verifySignature(context->ctx, context->sig, &rule->result);
}

CompositeRule_verify(CompositeRule *rule, VerificationContext *context) {
	int i;

	rule->result.resultCode = OK;
	for (i = 0; i < RuleList_length(rule->rules); i++) {
		Rule *sub_rule;
		RuleList_elementAt(rule->rules, i, &sub_rule);
		Rule_verify(sub_rule, context);
		/* TODO: add rule result? */
		rule->result = sub_rule->result;
		if (rule->result.resultCode == OK && rule->skipOnFirstOk) {
			break;
		}
		if ((rule->result.resultCode == FAIL || rule->result.resultCode == NA) && !rule->skipOnFirstOk) {
			break;
		}
	}
}

void Rule_verify(Rule *rule, VerificationContext *context) {
	if (rule->type == RULE_TYPE_BASIC) {
		BasicRule_verify(rule->rule.basicRule, context);
		rule->result = rule->rule.basicRule->result;
	}
	else if (rule->type == RULE_TYPE_COMPOSITE) {
		CompositeRule_verify(rule->rule.compositeRule, context);
		rule->result = rule->rule.compositeRule->result;
	}
}

Policy_verifySignature(KSI_Policy *policy, VerificationContext *context) {
	int i;

	for (i = 0; i < RuleList_length(policy->rules); i++) {
		Rule *rule;
		RuleList_elementAt(policy->rules, i, &rule);
		Rule_verify(rule, context);
		policy->result = rule->result;
		/* Alternatively for more fine-tuned status: */
		/* Policy_resultSet(policy, rule->result); */
		if (policy->result.resultCode != OK) {
			break;
		}
	}
}

KSI_Policy_verify(KSI_Policy *policy, VerificationContext *context) {
	KSI_Policy *currentPolicy;

	currentPolicy = policy;
	while (currentPolicy != NULL) {
		Policy_verifySignature(currentPolicy, context);
		if (currentPolicy->result.resultCode != OK) {
			currentPolicy = currentPolicy->fallbackPolicy;
		}
		else {
			currentPolicy = NULL;
		}
	}
}

static int Policy_create(KSI_Policy **policy) {
	int res;
	KSI_Policy *tmp;

	tmp = KSI_new(KSI_Policy);
	RuleList_new(&tmp->rules);
	tmp->fallbackPolicy = NULL;
	*policy = tmp;
	tmp = NULL;
	res = KSI_OK;
	return res;
}

Rule_create(Rule **rule) {
	Rule *tmp;

	tmp = KSI_new(Rule);
	*rule = tmp;
	tmp = NULL;
}

BasicRule_create(Verifier verifier, Rule **rule) {
	Rule *tmp;

	Rule_create(&tmp);
	tmp->rule.basicRule = KSI_new(BasicRule);
	tmp->rule.basicRule->verifySignature = verifier;
	tmp->type = RULE_TYPE_BASIC;
	*rule = tmp;
	tmp = NULL;
}

static int Policy_addBasicRule(KSI_Policy *policy, Verifier verifier) {
	int res;
	Rule *rule;

	BasicRule_create(verifier, &rule);
	RuleList_append(policy->rules, rule);
	res = KSI_OK;
	return res;
}

CompositeRule_create(bool skip, CompositeRule **rule) {
	CompositeRule *tmp;

	tmp = KSI_new(CompositeRule);
	tmp->skipOnFirstOk = skip;
	RuleList_new(&tmp->rules);
	*rule = tmp;
	tmp = NULL;
}

CompositeRule_addBasicRule(CompositeRule *rule, Verifier verifier) {
	Rule *tmp;

	BasicRule_create(verifier, &tmp);
	RuleList_append(rule->rules, tmp);
	tmp = NULL;
}

CompositeRule_addCompositeRule(CompositeRule *rule, CompositeRule *next) {
	Rule *tmp;

	tmp = KSI_new(Rule);
	tmp->type = RULE_TYPE_COMPOSITE;
	tmp->rule.compositeRule = next;
	RuleList_append(rule->rules, tmp);
	tmp = NULL;
}

static int Policy_addCompositeRule(KSI_Policy *policy, CompositeRule *next) {
	int res = KSI_UNKNOWN_ERROR;
	Rule *tmp = NULL;

	tmp = KSI_new(Rule);
	tmp->type = RULE_TYPE_COMPOSITE;
	tmp->type = RULE_TYPE_COMPOSITE;
	tmp->rule.compositeRule = next;
	RuleList_append(policy->rules, tmp);
	tmp = NULL;
	res = KSI_OK;

cleanup:

	return res;
}

void KSI_Policy_free(KSI_Policy *policy) {
	if (policy != NULL) {
		RuleList_free(policy->rules);
		KSI_free(policy);
	}
}

#define TRY_CATCH(statement) \
	res = statement;\
	if (res != KSI_OK) {\
		KSI_pushError(ctx, res, NULL);\
		goto cleanup;\
	}\

int KSI_Policy_createInternal(KSI_CTX *ctx, KSI_Policy **policy) {
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
	res = KSI_OK;

cleanup:

	CompositeRule_free(composite_rule1);
	CompositeRule_free(composite_rule2);
	CompositeRule_free(composite_rule3);
	CompositeRule_free(composite_rule4);
	CompositeRule_free(signatureDoesNotContainCalendarChainRule);
	CompositeRule_free(alreadyExtendedSignatureRule);
	Policy_free(tmp);

	return res;
}
