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

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_AggregationChainInputHashVerification(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);
	
	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_AggregationHashChainConsistency(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_AggregationHashChainTimeConsistency(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainInputHashVerification(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainAggregationTime(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainRegistrationTime(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarAuthenticationRecordAggregationHash(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarAuthenticationRecordAggregationTime(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignaturePublicationRecordPublicationHash(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignaturePublicationRecordPublicationTime(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_DocumentHashVerification(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignatureDoesNotContainPublication(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureAggregationChainRightLinksMatches(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_SignaturePublicationRecordExistence(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureCalendarChainRootHash(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainDoesNotExist(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureCalendarChainInputHash(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_ExtendedSignatureCalendarChainAggregationTime(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */

	/**
	 * 
	 * \param[in]	ctx			KSI context.
	 * \param[in]	sig			KSI signature.
	 * \param[out]	result		Verification result.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationRule_CalendarHashChainExistence(KSI_CTX *ctx, KSI_Signature *sig, KSI_VerificationResult *result);


#ifdef __cplusplus
}
#endif

#endif /* VERIFICATION_RULE_H_ */
