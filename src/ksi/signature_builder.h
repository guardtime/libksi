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


#ifndef SIGNATURE_BUILDER_H_
#define SIGNATURE_BUILDER_H_

#include "ksi.h"

#ifdef __cplusplus
extern "C" {
#endif
	/**
	 * \addtogroup signaturebuilder KSI Signature Builder
	 * The signature builder is used to create a signature object from components. The interface will verify
	 * the signature internally before returning it to the caller.
	 * @{
	 */

	/**
	 * Signature builder object.
	 */
	typedef struct KSI_SignatureBuilder_st KSI_SignatureBuilder;

	/**
	 * Creates a new instance of the signature builder. The builder is initialized with a copy of the input signature \c sig.
	 * \param[in]	sig		KSI signature instance.
	 * \param[out]	builder	Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note It is the responsibility of the caller to free the input parameters after use.
	 */
	int KSI_SignatureBuilder_openFromSignature(const KSI_Signature *sig, KSI_SignatureBuilder **builder);

	/**
	 * Creates a new instance of the signature builder. The builder is initialized with the aggregation response \c resp.
	 * \param[in]	resp	Aggregation response.
	 * \param[out]	builder	Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note It is users responsibility to verify the resulting singature.
	 * \note It is the responsibility of the caller to free the input parameters after use.
	 * \see #KSI_Signature_verifyWithPolicy
	 */
	int KSI_SignatureBuilder_openFromAggregationResp(const KSI_AggregationResp *resp, KSI_SignatureBuilder **builder);

	/**
	 * Creates a new instance of the signature builder.
	 * \param[in]	ctx		The KSI context.
	 * \param[out]	builder	Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_SignatureBuilder_close, #KSI_SignatureBuilder_free
	 */
	int KSI_SignatureBuilder_open(KSI_CTX *ctx, KSI_SignatureBuilder **builder);

	/**
	 * If the signature is set up properly and the resulting signature is internally verifiable, then the function
	 * closes the signature builder and returns via output parameter the resulting signature.
	 * \param[in] 	builder			Pointer to signature builder.
	 * \param[in]	rootLevel		The level of the input hash (usually 0). This is used only for the verification.
	 * \param[out]	sig				Pointer to the receiving pointer.
	 * \note The caller must also call #KSI_SignatureBuilder_free on the builder object.
	 * \note It is the responsibility of the caller to free the resulting signature object.
	 * \see #KSI_SignatureBuilder_free, #KSI_Signature_free.
	 * \return status code (#KSI_OK when operation succeeded, #KSI_INVALID_STATE when the building of the signature
	 * is in an invalid state, otherwise an error code).
	 */
	int KSI_SignatureBuilder_close(KSI_SignatureBuilder *builder, KSI_uint64_t rootLevel, KSI_Signature **sig);

	/**
	 * Cleanup method for the builder.
	 * \param[in]	builder		Pointer to the builder.
	 */
	void KSI_SignatureBuilder_free(KSI_SignatureBuilder *builder);

	/**
	 * This function sets the calendar hash chain of the signature.
	 * \param[in]	builder		Pointer to the builder.
	 * \param[in]	cal			Calendar chain.
	 * \note Calling this function more than once on a signature builder results in an error.
	 * \note It is the responsibility of the caller to free the input parameters after use.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_SignatureBuilder_setCalendarHashChain(KSI_SignatureBuilder *builder, KSI_CalendarHashChain *cal);

	/**
	 * This function applies the calendar hash chain of the signature. It will replace the existing calendar hash
	 * chain if present and remove calendar hash chain authentication record or publication recond.
	 * A use case is to apply an extended calendar hash chain to a KSI signature.
	 * \param[in]	builder		Pointer to the builder.
	 * \param[in]	cal			Calendar chain.
	 * \note It is the responsibility of the caller to free the input parameters after use.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_SignatureBuilder_openFromSignature to initialize \c builder with a KSI signature.
	 */
	int KSI_SignatureBuilder_applyCalendarHashChain(KSI_SignatureBuilder *builder, KSI_CalendarHashChain *cal);

	/**
	 * This function adds an aggregation chain to the signature.
	 * \param[in]	builder		Pointer to the builder.
	 * \param[in]	aggr		Aggregation chain.
	 * \note It is the responsibility of the caller to free the input parameters after use.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_SignatureBuilder_addAggregationChain(KSI_SignatureBuilder *builder, KSI_AggregationHashChain *aggr);

	/**
	 * This function appends the aggregation chain to the signature. The difference between
	 * #KSI_SignatureBuilder_addAggregationChain is that chain is appended to the beggining of the chain list and
	 * aggregation time and chain index are updated.
	 * \param[in]	builder		Pointer to the builder.
	 * \param[in]	aggr		Aggregation hash chain.
	 * \note It is the responsibility of the caller to free the input parameters after use.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_SignatureBuilder_appendAggregationChain(KSI_SignatureBuilder *builder, KSI_AggregationHashChain *aggr);

	/**
	 * This function appends the aggregation chain to the signature and returns the appended signature. To use this
	 * interface, first open a signature builder from a signature (#KSI_SignatureBuilder_openFromSignature), then
	 * get as many appended signatures as needed and finally free the signature builder (#KSI_SignatureBuilder_free).
	 * \param[in]	builder		Pointer to the builder.
	 * \param[in]	aggr		Aggregation hash chain.
	 * \param[out]	sig			Pointer to the receiving pointer.
	 * \note It is the responsibility of the caller to free the input parameters after use.
	 * \note There is no need to close the signature builder after use.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_SignatureBuilder_createSignatureWithAggregationChain(KSI_SignatureBuilder *builder, KSI_AggregationHashChain *aggr, KSI_Signature **sig);

	/**
	 * This function sets the calendar authentication record of the signature.
	 * \param[in]	builder		Pointer to the builder.
	 * \param[in]	calAuth		Calendar chain authentication record.
	 * \note It is the responsibility of the caller to free the input parameters after use.
	 * \note Calling this function more than once on a signature builder results in an error.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_SignatureBuilder_setCalendarAuthRecord(KSI_SignatureBuilder *builder, KSI_CalendarAuthRec *calAuth);

	/**
	 * This function sets the publication record of the signature.
	 * \param[in]	builder		Pointer to the builder.
	 * \param[in]	pub			Publication record.
	 * \note Calling this function more than once on a signature builder results in an error.
	 * \note It is the responsibility of the caller to free the input parameters after use.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_SignatureBuilder_setPublication(KSI_SignatureBuilder *builder, KSI_PublicationRecord *pub);

	/**
	 * This function sets the RFC3161 record of the signature.
	 * \param[in]	builder		Pointer to the builder.
	 * \param[in]	rfc3161	    RFC3161 record.
	 * \note Calling this function more than once on a signature builder results in an error.
	 * \note It is the responsibility of the caller to free the input parameters after use.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_SignatureBuilder_setRFC3161(KSI_SignatureBuilder *builder, KSI_RFC3161 *rfc3161);

/**
 * @}
 */


#ifdef __cplusplus
}
#endif

#endif /* SIGNATURE_BUILDER_H_ */
