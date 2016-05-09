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

#ifndef VERIFICATION_RULE_H_
#define VERIFICATION_RULE_H_

#include "ksi.h"
#include "policy.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * This rule verifies that if RFC3161 record is present then the calculated output hash (from RFC3161 record) equals to
	 * aggregation chain input hash. If RFC3161 record is missing then the status #KSI_VER_RES_OK is
	 * returned.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_AggregationChainInputHashVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule verifies that all aggregation hash chains are consistent (e.g, previous aggregation output hash equals to current aggregation chain input hash)
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_AggregationHashChainConsistency(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check that aggregation hash chain aggregation times are consistent (e.g previous aggregation
	 * hash chain aggregation time to current aggregation hash chain aggregation time).
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_AggregationHashChainTimeConsistency(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check whether the shape of the aggregation hash chain does match with the chain index.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_AggregationHashChainIndexConsistency(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that last aggregation hash chain output hash equals to calendar hash chain input hash.
	 * If calendar hash chain is missing then status code #KSI_OK will be returned.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainInputHashVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that calendar hash chain aggregation time equals to last aggregation hash chain
	 * aggregation time. If calendar hash chain is missing then status code #KSI_OK is returned.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainAggregationTime(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that calendar hash chain registration time (calculated from the shape of the calendar
	 * hash chain) equals to calendar hash chain aggregation time. If calendar hash chain is missing then status code
	 * #KSI_OK will be returned.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainRegistrationTime(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that calendar authentication record publication hash equals to calendar hash chain
	 * publication hash. If calendar authentication record is missing then status code #KSI_OK is returned.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that calendar authentication record publication time equals to calendar hash chain
	 * publication time. If calendar authentication record is missing then status code #KSI_OK is returned.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check if keyless signature contains publication record or not. If publication record is
	 * missing then status code #KSI_OK will be returned.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignaturePublicationRecordPublicationHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check if keyless signature contains correct publication record publication time.
	 * If publication record is missing then status code #KSI_OK will ne returned.

	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignaturePublicationRecordPublicationTime(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * Rule to check that document hash has not been provided for verification.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_DocumentHashDoesNotExist(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check if document hash has been provided for verification.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_DocumentHashExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify document hash. If RFC3161 record is present then the document hash must equal to RFC3161
	 * input hash. If RFC3161 record isn't present then document hash must equal to first aggregation hash chain input hash.
	 * If document hash isn't provided the status code #KSI_OK will be returned.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_DocumentHashVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule checks that signature does not contain publication record.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignatureDoesNotContainPublication(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule checks that:
	 * - the extended signature contains the same count of right calendar hash chain links
	 * - the extended signature right calendar hash chain links are equal to the not extended signature right links
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureCalendarChainRightLinksMatch(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check if keyless signature contains publication record or not.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignaturePublicationRecordExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check that reproduced calendar hash chain (reproduced by sending extension request with the
	 * same aggregation and publication time as the attached calendar chain) matches with the already present calendar
	 * hash chain root hash.
	 * If signature (that is being validated), does not contain calendar hash chain then status code #KSI_OK will be
	 * returned.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * Rule to check that keyless signature does not contain calendar hash chain.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainDoesNotExist(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check that extended signature contains correct calendar hash chain input hash (e.g  matches
	 * with aggregation chain root hash).
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check that extended signature contains correct aggregation time.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * Rule to check if keyless signature contains calendar hash chain. Used by key-based and publication-based
	 * verification policies.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarAuthenticationRecordExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarAuthenticationRecordDoesNotExist(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule ise used to check if publications file contains certificate with certificate id present in calendar
	 * authentication record.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CertificateExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to validate calendar authentication record signature. At first X.509 certificate is searched from
	 * publications file and when the certificate is found then the PKI signature is validated.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarAuthenticationRecordSignatureVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);


	/**
	 * This rule can be used to check if publications file contains signature publication.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_PublicationsFileContainsSignaturePublication(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check if publications file contains publication closest to signature registration time.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_PublicationsFileContainsPublication(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule can be used to check if signature extending is permitted or not.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendingPermittedVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that publications file publication hash matches with extender response calendar root hash.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_PublicationsFilePublicationHashMatchesExtenderResponse(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that publications file publication time matches with extender response calendar chain
	 * shape.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_PublicationsFilePublicationTimeMatchesExtenderResponse(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule can be used to check that extender response input hash equals with signature aggregation root hash.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_PublicationsFileExtendedSignatureInputHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify if user has provided the publication
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_UserProvidedPublicationExistence(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used verify that user provided publication equals to publication inside the signature.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_UserProvidedPublicationVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule checks that signature is created before user provided publication.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_UserProvidedPublicationCreationTimeVerification(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that user provided publication hash matches with extender response calendar root hash
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_UserProvidedPublicationHashMatchesExtendedResponse(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that user provided publication time matches with extender response calendar chain shape.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_UserProvidedPublicationTimeMatchesExtendedResponse(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

	/**
	 * This rule can be used to check that extender response input hash equals with signature aggregation root hash.
	 *
	 * \param[in]	info		Verification context to be used for given rule
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_UserProvidedPublicationExtendedSignatureInputHash(KSI_VerificationContext *info, KSI_RuleVerificationResult *result);

#ifdef __cplusplus
}
#endif

#endif /* VERIFICATION_RULE_H_ */
