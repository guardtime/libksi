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
	 * aggregation chain input hash. If RFC3161 record is missing then the status {@link VerificationResultCode#OK} is
	 * returned.
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_AggregationChainInputHashVerification(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule verifies that all aggregation hash chains are consistent (e.g previous aggregation output hash equals to
	 * current aggregation chain input hash).
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_AggregationHashChainConsistency(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check that aggregation hash chain aggregation times are consistent (e.g previous aggregation
	 * hash chain aggregation time to current aggregation hash chain aggregation time).
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_AggregationHashChainTimeConsistency(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that last aggregation hash chain output hash equals to calendar hash chain input hash.
	 * If calendar hash chain is missing then status code #KSI_OK will be returned.
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainInputHashVerification(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that calendar hash chain aggregation time equals to last aggregation hash chain
	 * aggregation time. If calendar hash chain is missing then status code #KSI_OK is returned.
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainAggregationTime(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that calendar hash chain registration time (calculated from the shape of the calendar
	 * hash chain) equals to calendar hash chain aggregation time. If calendar hash chain is missing then status code
	 * #KSI_OK will be returned.
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainRegistrationTime(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that calendar authentication record publication hash equals to calendar hash chain
	 * publication hash. If calendar authentication record is missing then status code #KSI_OK is returned.
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify that calendar authentication record publication time equals to calendar hash chain
	 * publication time. If calendar authentication record is missing then status code #KSI_OK is returned.
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check if keyless signature contains publication record or not. If publication record is
	 * missing then status code #KSI_OK will be returned.
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignaturePublicationRecordPublicationHash(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check if keyless signature contains correct publication record publication time.
	 * If publication record is missing then status code #KSI_OK will ne returned.

	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignaturePublicationRecordPublicationTime(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to verify document hash. If RFC3161 record is present then the document hash must equal to RFC3161
	 * input hash. If RFC3161 record isn't present then document hash must equal to first aggregation hash chain input hash.
	 * If document hash isn't provided the status code #KSI_OK will be returned.
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_DocumentHashVerification(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule checks that signature does not contain publication record.
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignatureDoesNotContainPublication(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule checks that:
	 * - the extended signature contains the same count of right aggregation hash chain links
	 * - the extended signature right aggregation hash chain links are equal to the not extended signature right links
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * This rule is used to check if keyless signature contains publication record or not.
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignaturePublicationRecordExistence(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 * Rule to check that keyless signature does not contain calendar hash chain.
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainDoesNotExist(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime(KSI_Signature *sig, KSI_RuleVerificationResult *result);

	/**
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */

	/**
	 *
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainExistence(KSI_Signature *sig, KSI_RuleVerificationResult *result);


#ifdef __cplusplus
}
#endif

#endif /* VERIFICATION_RULE_H_ */
