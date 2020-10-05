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

#include "policy.h"
#include "verification_rule.h"
#include "hashchain.h"

#include "impl/policy_impl.h"
#include "impl/signature_impl.h"
#include "impl/ctx_impl.h"


static int KSI_RuleVerificationResult_dup(KSI_RuleVerificationResult *src, KSI_RuleVerificationResult **dest);
static void KSI_RuleVerificationResult_free(KSI_RuleVerificationResult *result);
static void VerificationTempData_clear(VerificationTempData *tmp);

KSI_IMPLEMENT_LIST(KSI_RuleVerificationResult, KSI_RuleVerificationResult_free);
KSI_IMPLEMENT_REF(KSI_PolicyVerificationResult);

static int isDuplicateRuleResult(KSI_RuleVerificationResultList *resultList, KSI_RuleVerificationResult *result) {
	int return_value = 0;
	size_t i;

	if (result == NULL) goto cleanup;
	for (i = 0; i < KSI_RuleVerificationResultList_length(resultList); i++) {
		int res;
		KSI_RuleVerificationResult *tmp = NULL;
		res = KSI_RuleVerificationResultList_elementAt(resultList, i, &tmp);
		if (res != KSI_OK || tmp == NULL) goto cleanup;
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
		res = KSI_RuleVerificationResult_dup(&result->finalResult, &tmp);
		if (res != KSI_OK) goto cleanup;

		res = KSI_RuleVerificationResultList_append(result->ruleResults, tmp);
		if (res != KSI_OK) goto cleanup;
		tmp = NULL;
	}
cleanup:
	KSI_RuleVerificationResult_free(tmp);
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
		KSI_RuleVerificationResult_clean(&policyResult->finalResult);
		policyResult->finalResult.resultCode = KSI_VER_RES_NA;
		policyResult->finalResult.errorCode = KSI_VER_ERR_GEN_2;
		switch (currentRule->type) {
			case KSI_RULE_TYPE_BASIC:
				res = ((Verifier)(currentRule->rule))(context, &policyResult->finalResult);
				KSI_LOG_debug(context->ctx, "Rule result: 0x%x 0x%x 0x%x %s %s (0x%x/%d%s%s).",
						res,
						policyResult->finalResult.resultCode,
						policyResult->finalResult.errorCode,
						policyResult->finalResult.ruleName,
						policyResult->finalResult.policyName,
						policyResult->finalResult.status,
						policyResult->finalResult.statusExt,
						policyResult->finalResult.status != KSI_OK ? ": " : "",
						policyResult->finalResult.status != KSI_OK ? policyResult->finalResult.statusMessage : "");
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

		if (currentRule->type == KSI_RULE_TYPE_BASIC &&
				!(res == KSI_OK && policyResult->finalResult.resultCode == KSI_VER_RES_NA && policyResult->finalResult.errorCode == KSI_VER_ERR_NONE)) {
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
 * EMPTY POLICY
 ******************/

static int KSI_VerificationRule_AlwaysOk(KSI_VerificationContext KSI_UNUSED(*context), KSI_RuleVerificationResult *result) {
	result->resultCode = KSI_VER_RES_OK;
	result->errorCode = KSI_VER_ERR_NONE;
	result->ruleName = __FUNCTION__;
	return KSI_OK;
}

static const KSI_Rule emptyRules[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AlwaysOk},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Policy PolicyEmpty = {
	emptyRules,
	NULL,
	"EmptyPolicy"
};

const KSI_Policy* KSI_VERIFICATION_POLICY_EMPTY = &PolicyEmpty;


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
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarChainHashAlgorithmObsoleteAtPubTime},
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
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_InputHashAlgorithmVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_DocumentHashVerification},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule documentHashRule[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, noDocumentHashRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, documentHashVerificationRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

static const KSI_Rule noRfc3161Rule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_Rfc3161DoesNotExist},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule rfc3161VerificationRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_Rfc3161Existence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_Rfc3161RecordHashAlgorithmVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_Rfc3161RecordOutputHashAlgorithmVerification},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule rfc3161Rule[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, noRfc3161Rule},
	{KSI_RULE_TYPE_COMPOSITE_OR, rfc3161VerificationRule},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

static const KSI_Rule internalRules[] = {
	{KSI_RULE_TYPE_COMPOSITE_AND, documentHashRule},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationChainInputLevelVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationChainInputHashAlgorithmVerification},
	{KSI_RULE_TYPE_COMPOSITE_AND, rfc3161Rule},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationChainInputHashVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationChainMetaDataVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationChainHashAlgorithmVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationHashChainIndexContinuation},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationHashChainTimeConsistency},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationHashChainConsistency},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_AggregationHashChainIndexConsistency},
	{KSI_RULE_TYPE_COMPOSITE_AND, calendarHashChainRule_int},
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
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendSignatureCalendarChainInputHashToHead},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule extendToCalendarChainRule[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_ExtendSignatureCalendarChainInputHashToSamePubTime},
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
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainPresenceVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarHashChainHashAlgorithmDeprecatedAtPubTime},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CalendarAuthenticationRecordPresenceVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CertificateExistence},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_CertificateValidity},
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

static const KSI_Rule extendToPublication[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileContainsSuitablePublication},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileExtendingPermittedVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileExtendToPublication},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileExtendedCalendarChainHashAlgorithmDeprecatedAtPubTime},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFilePublicationTimeMatchesExtenderResponse},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash},
	{KSI_RULE_TYPE_BASIC, NULL}
};


static const KSI_Rule suitablePubExist_pubFile[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileContainsSignaturePublication},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileSignaturePublicationVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileSignatureCalendarChainHashAlgorithmDeprecatedAtPubTime},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule suitablePubMissing_pubFile[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_PublicationsFileDoesNotContainSignaturePublication},
	{KSI_RULE_TYPE_COMPOSITE_AND, extendToPublication},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule sigPubRecExist_pubFile[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordExistence},
	{KSI_RULE_TYPE_COMPOSITE_OR, suitablePubExist_pubFile},
	{KSI_RULE_TYPE_COMPOSITE_OR, suitablePubMissing_pubFile},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule sigPubRecMissing_pubFile[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordMissing},
	{KSI_RULE_TYPE_COMPOSITE_AND, extendToPublication},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule publicationRecordRule_pubFile[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, sigPubRecExist_pubFile},
	{KSI_RULE_TYPE_COMPOSITE_OR, sigPubRecMissing_pubFile},
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

static const KSI_Rule extendToUserPublication[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationExtendingPermittedVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationExtendToPublication},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationExtendedCalendarChainHashAlgorithmDeprecatedAtPubTime},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash},
	{KSI_RULE_TYPE_BASIC, NULL}
};


static const KSI_Rule suitablePubExist[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationTimeVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationHashVerification},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationSignatureCalendarChainHashAlgorithmDeprecatedAtPubTime},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule suitablePubMissing[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_UserProvidedPublicationTimeDoesNotSuit},
	{KSI_RULE_TYPE_COMPOSITE_AND, extendToUserPublication},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule sigPubRecExist[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordExistence},
	{KSI_RULE_TYPE_COMPOSITE_OR, suitablePubExist},
	{KSI_RULE_TYPE_COMPOSITE_OR, suitablePubMissing},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule sigPubRecMissing[] = {
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_SignaturePublicationRecordMissing},
	{KSI_RULE_TYPE_COMPOSITE_AND, extendToUserPublication},
	{KSI_RULE_TYPE_BASIC, NULL}
};

static const KSI_Rule publicationRecordRule_pubString[] = {
	{KSI_RULE_TYPE_COMPOSITE_OR, sigPubRecExist},
	{KSI_RULE_TYPE_COMPOSITE_OR, sigPubRecMissing},
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
	{KSI_RULE_TYPE_COMPOSITE_OR, userProvidedPublicationBasedRules},
	{KSI_RULE_TYPE_BASIC, KSI_VerificationRule_RequireNoUserProvidedPublication },
	{KSI_RULE_TYPE_COMPOSITE_OR, publicationsFileBasedRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, keyBasedRules},
	{KSI_RULE_TYPE_COMPOSITE_OR, NULL}
};

static const KSI_Policy PolicyGeneral = {
	generalRules,
	NULL,
	"GeneralPolicy"
};

const KSI_Policy* KSI_VERIFICATION_POLICY_GENERAL = &PolicyGeneral;

const char *KSI_VerificationErrorCode_toString(int errorCode) {
	switch (errorCode) {
		case KSI_VER_ERR_NONE:	return "";
#define _(type, code, offset, strCode, desc) case KSI_VER_ERR_##type##_##code: return strCode;
		KSI_VERIFICATION_ERROR_CODE_LIST
		KSI_VERIFICATION_ERROR_CODE_DEPRECATED_LIST
#undef _
		default:				return "Unknown";
	}
}

int KSI_VerificationErrorCode_fromString(const char *errCodeStr) {
	size_t i = 0;
	const struct {
		char *name;
		int code;
	} errCodes[] = {
#define _(type, code, offset, strCode, desc) { strCode, KSI_VER_ERR_##type##_##code },
		KSI_VERIFICATION_ERROR_CODE_LIST
		KSI_VERIFICATION_ERROR_CODE_DEPRECATED_LIST
#undef _
		{ NULL, KSI_VER_ERR_NONE }
	};

	while (errCodes[i].name != NULL) {
		if (strcmp(errCodes[i].name, errCodeStr) == 0) return errCodes[i].code;
		i++;
	}
	return KSI_VER_ERR_NONE;
}

const char *KSI_Policy_getErrorString(int errorCode) {
	switch (errorCode) {
		case KSI_VER_ERR_NONE:	return "No verification errors";
#define _(type, code, offset, cor, desc) case KSI_VER_ERR_##type##_##code: return desc;
		KSI_VERIFICATION_ERROR_CODE_LIST
		KSI_VERIFICATION_ERROR_CODE_DEPRECATED_LIST
#undef _
		default:				return "Unknown verification error code";
	}
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

int KSI_RuleVerificationResult_init(KSI_RuleVerificationResult *result) {
	int res = KSI_UNKNOWN_ERROR;

	if (result == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	result->resultCode = KSI_VER_RES_NA;
	result->errorCode = KSI_VER_ERR_GEN_2;

	result->ruleName = NULL;
	result->policyName = NULL;

	result->stepsPerformed = KSI_VERIFY_NONE;
	result->stepsSuccessful = KSI_VERIFY_NONE;
	result->stepsFailed = KSI_VERIFY_NONE;

	result->status = KSI_OK;
	result->statusExt = 0;
	result->statusMessage = NULL;

	res = KSI_OK;
cleanup:
	return res;
}

void KSI_RuleVerificationResult_clean(KSI_RuleVerificationResult *result) {
	if (result != NULL) {
		KSI_free(result->statusMessage);
		result->statusMessage = NULL;
	}
}

static int KSI_RuleVerificationResult_dup(KSI_RuleVerificationResult *src, KSI_RuleVerificationResult **dest) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RuleVerificationResult *tmp = NULL;

	if (src == NULL || dest == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(KSI_RuleVerificationResult);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	*tmp = *src;

	tmp->statusMessage = NULL;
	if (src->statusMessage != NULL) {
		/* Dont care if it failes. */
		KSI_strdup(src->statusMessage, &tmp->statusMessage);
	}

	*dest = tmp;
	res = KSI_OK;
cleanup:
	return res;
}

static void KSI_RuleVerificationResult_free(KSI_RuleVerificationResult *result) {
	KSI_RuleVerificationResult_clean(result);
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

	res = KSI_RuleVerificationResult_init(&tmp->finalResult);
	if (res != KSI_OK) {
		goto cleanup;
	}

	tmp->ref = 1;
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

	res = KSI_RuleVerificationResult_dup(&result->finalResult, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_RuleVerificationResultList_append(result->policyResults, tmp);
	if (res != KSI_OK) goto cleanup;

	tmp = NULL;

cleanup:

	KSI_RuleVerificationResult_free(tmp);
	return res;
}

static int Policy_verifySignature(const KSI_Policy *policy, KSI_VerificationContext *context, KSI_PolicyVerificationResult *policyResult) {
	int res = KSI_UNKNOWN_ERROR;

	if (policy == NULL || policy->rules == NULL || context == NULL || context->ctx == NULL || policyResult == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = Rule_verify(policy->rules, context, policyResult);
	KSI_LOG_debug(context->ctx, "Policy result: 0x%x 0x%x 0x%x %s %s (0x%x/%d%s%s).",
			res,
			policyResult->finalResult.resultCode,
			policyResult->finalResult.errorCode,
			policyResult->finalResult.ruleName,
			policyResult->finalResult.policyName,
			policyResult->finalResult.status,
			policyResult->finalResult.statusExt,
			policyResult->finalResult.status != KSI_OK ? ": " : "",
			policyResult->finalResult.status != KSI_OK ? policyResult->finalResult.statusMessage : "");
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

	KSI_Signature_free(ctx->lastFailedSignature);
	ctx->lastFailedSignature = KSI_Signature_ref(context->signature);
	if (ctx->lastFailedSignature != NULL) {
		KSI_PolicyVerificationResult_free(ctx->lastFailedSignature->policyVerificationResult);
		ctx->lastFailedSignature->policyVerificationResult = NULL;
	}

	res = PolicyVerificationResult_create(&tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	tmp->resultCode = KSI_VER_RES_NA;

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

	if (tmp->finalResult.resultCode != KSI_VER_RES_OK) {
		if (ctx->lastFailedSignature != NULL) {
			ctx->lastFailedSignature->policyVerificationResult = KSI_PolicyVerificationResult_ref(tmp);
		}
	} else {
		KSI_Signature_free(ctx->lastFailedSignature);
		ctx->lastFailedSignature = NULL;
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
	if (result != NULL && --result->ref == 0) {
		KSI_RuleVerificationResultList_free(result->ruleResults);
		KSI_RuleVerificationResultList_free(result->policyResults);
		KSI_RuleVerificationResult_clean(&result->finalResult);
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
