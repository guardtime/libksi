/*
 * Copyright 2013-2015 Guardtime, Inc.
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

#ifndef KSI_SIGNATURE_H_
#define KSI_SIGNATURE_H_

#include "types.h"
#include "verification.h"
#include "verify_deprecated.h"

#ifdef __cplusplus
extern "C" {
#endif
	/**
	 * \addtogroup signature KSI Signature
	 * At the highest level of abstraction, a keyless signature consists of a hash chain linking the
	 * signed document to the root hash value of the aggregation tree, followed by another hash chain
	 * linking the root hash value of the aggregation tree to the published trust anchor.
	 * @{
	 */

#ifndef KSI_SIGNATURE_STRUCT
	#define KSI_SIGNATURE_STRUCT
	typedef struct KSI_Signature_st KSI_Signature;
#endif

	/**
	 * Free the signature object.
	 * \param[in]	signature		Signature object.
	 */
	void KSI_Signature_free(KSI_Signature *signature);

	/**
	 * Creates a clone of the signature object.
	 * \param[in]		sig			Signature to be cloned.
	 * \param[out]		clone		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_Signature_clone(const KSI_Signature *sig, KSI_Signature **clone);

	/**
	 * Parses a KSI signature from raw buffer. The raw buffer may be freed after
	 * this function finishes. To reserialize the signature use #KSI_Signature_serialize.
	 *
	 * \param[in]		ctx			KSI context.
	 * \param[in]		raw			Pointer to the raw signature.
	 * \param[in]		raw_len		Length of the raw signature.
	 * \param[out]		sig			Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_parse(KSI_CTX *ctx, unsigned char *raw, size_t raw_len, KSI_Signature **sig);

	/**
	 * A convenience function for reading a signature from a file.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		fileName	Name of the signature file.
	 * \param[out]		sig			Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note It must be noted that access to metadata, supported by some file systems,
	 * is limited by the use of function \c fopen. Alternate Data Streams (WIndows NTFS)
	 * and Resource Forks (OS X HFS) may or may not be supported, depending on the
	 * C standard library used in the application.
	 */
	int KSI_Signature_fromFile(KSI_CTX *ctx, const char *fileName, KSI_Signature **sig);

	/**
	 * This function serializes the signature object into raw data. To deserialize it again
	 * use #KSI_Signature_parse.
	 * \param[in]		sig			Signature object.
	 * \param[out]		raw			Pointer to the pointer to output buffer.
	 * \param[out]		raw_len		Pointer to the length of the buffer variable.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_free.
	 */
	int KSI_Signature_serialize(KSI_Signature *sig, unsigned char **raw, size_t *raw_len);

	/**
	 * This function signs the given data hash \c hsh. This function requires a access to
	 * a working aggregator and fails if it is not accessible.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		hsh			Document hash.
	 * \param[out]		signature	Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note For signing hash values, the use of #KSI_createSignature is strongly
	 * recomended.
	 * \see #KSI_createSignature, KSI_Signature_free
	 */
	int KSI_Signature_sign(KSI_CTX *ctx, KSI_DataHash *hsh, KSI_Signature **signature);

	/**
	 * \deprecated This function is deprecated and #KSI_Signature_sign should be used instead.
	 * \see #KSI_Signature_sign
	 */
	KSI_FN_DEPRECATED(int KSI_Signature_create(KSI_CTX *ctx, KSI_DataHash *hsh, KSI_Signature **signature));

	/**
	 * This function signs the given root hash value (\c rootHash) with the aggregation level (\c rootLevel)
	 * of a locally aggregated hash tree. This function requires access to a working aggregaton and fails if
	 * it is not accessible.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		rootHash	Root value of the hash tree.
	 * \param[in]		rootLevel	Level of the root node (0 =< x <= 0xff).
	 * \param[out]		signature	Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \see #KSI_createSignature, KSI_Signature_create, KSI_Signature_free.
	 */
	int KSI_Signature_signAggregated(KSI_CTX *ctx, KSI_DataHash *rootHash, KSI_uint64_t rootLevel, KSI_Signature **signature);

	/**
	 * \deprecated This function is deprecated and #KSI_Signature_signAggregated should be used instead.
	 * \see #KSI_Signature_signAggregated
	 */
	KSI_FN_DEPRECATED(int KSI_Signature_createAggregated(KSI_CTX *ctx, KSI_DataHash *rootHash, KSI_uint64_t rootLevel, KSI_Signature **signature));

	/**
	 * This function creates a new signature using the aggrehation hash chain as the input. The aggregation hash chain will
	 * be included in the signature itself.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		level		The level of the input hash of the aggregation hash chain.
	 * \param[in]		chn			Aggregation hash chain.
	 * \param[out]		signature	Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The function does not consume the aggregation hash chain - the caller must free the resource.
	 */
	int KSI_Signature_signAggregationChain(KSI_CTX *ctx, int level, KSI_AggregationHashChain *chn, KSI_Signature **signature);

	/**
	 * This function extends the signature to the given publication \c pubRec. If \c pubRec is \c NULL the signature is
	 * extended to the head of the calendar database. This function requires access to a working KSI extender or it will
	 * fail with an error.
	 * \param[in]		signature	KSI signature to be extended.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		pubRec		Publication record.
	 * \param[out]		extended	Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note The output signature is independent of the input signature and needs to be freed using #KSI_Signature_free.
	 */
	int KSI_Signature_extend(const KSI_Signature *signature, KSI_CTX *ctx, const KSI_PublicationRecord *pubRec, KSI_Signature **extended);

	/**
	 * Extends the signature to a given time \c to. If \c to is equal to \c NULL, the signature is extended to
	 * the head of the extender.
	 * \param[in]		signature	KSI signature to be extended.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		to			UTC time to extend to.
	 * \param[out]		extended 	Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note Extending to a specific time will remove calendar auth record and publication record.
	 */
	int KSI_Signature_extendTo(const KSI_Signature *signature, KSI_CTX *ctx, KSI_Integer *to, KSI_Signature **extended);

	/**
	 * Access method for the signed document hash as a #KSI_DataHash object.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		hsh			Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note The output hash \c hsh may not be freed by the caller.
	 */
	int KSI_Signature_getDocumentHash(KSI_Signature *sig, KSI_DataHash ** hsh);

	/**
	 * Access method for the hash algorithm used to hash the signed document.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		algo_id		Pointer to the receiving hash id variable.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHasher_open, #KSI_DataHash_create, #KSI_DataHasher_close,
	 * #KSI_Signature_createDataHasher.
	 */
	int KSI_Signature_getHashAlgorithm(KSI_Signature *sig, KSI_HashAlgorithm *algo_id);

	/**
	 * This method creates a data hasher object to be used on the signed data.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		hsr			Data hasher.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHasher_free, #KSI_DataHasher_close, #KSI_DataHasher_open,
	 * #KSI_Signature_getHashAlgorithm.
	 */
	int KSI_Signature_createDataHasher(KSI_Signature *sig, KSI_DataHasher **hsr);
	/**
	 * Access method for the signing time. The \c signTime is expressed as
	 * the number of seconds since 1970-01-01 00:00:00 UTC.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		signTime	Pointer to the receiving variable.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_getSigningTime(const KSI_Signature *sig, KSI_Integer **signTime);

	/**
	 * Function to get signer identity.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		identity	Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_free.
	 */
	int KSI_Signature_getSignerIdentity(KSI_Signature *sig, char **identity);

	/**
	 * Accessor method for the published data. If the signature does not have a publication
	 * record the \c pubRec will be set to \c NULL.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		pubRec		Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_getPublicationRecord(const KSI_Signature *sig, KSI_PublicationRecord **pubRec);

	/**
	 * Accessor method for the calendar authentication record.
	 * \param[in]	sig		Signature
	 * \param[out]	calendarAuthRec		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_getCalendarAuthRec (const KSI_Signature *sig, KSI_CalendarAuthRec **calendarAuthRec);

	int KSI_createSignRequest(KSI_CTX *ctx, KSI_DataHash *hsh, int lvl, KSI_AggregationReq **request);
	int KSI_createExtendRequest(KSI_CTX *ctx, KSI_Integer *start, KSI_Integer *end, KSI_ExtendReq **request);

	/**
	 * This function replaces the signatures calendar hash chain
	 * \param [in]		sig					KSI signature.
	 * \param [in]		calendarHashChain	Pointer to the calendar hash chain
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_replaceCalendarChain(KSI_Signature *sig, KSI_CalendarHashChain *calendarHashChain);

	/**
	 * Replaces the existing publication record of the signature.
	 * \param[in]	sig		KSI signature.
	 * \param[in]	pubRec	Publication record.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_replacePublicationRecord(KSI_Signature *sig, KSI_PublicationRecord *pubRec);

	/**
	 * Cleanup method for the aggregation hash chain.
	 * \param[in]	aggr		Aggregation hash chain.
	 */
	void KSI_AggregationHashChain_free(KSI_AggregationHashChain *aggr);

	/**
	 * Aggregation hash chain constructor.
	 * \param[in]	ctx			KSI context.
	 * \param[out]	out			Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AggregationHashChain_new(KSI_CTX *ctx, KSI_AggregationHashChain **out);

	/**
	 * This function appends the aggregation chain to the signature. This function also updates
	 * the aggregation time and chain index.
	 * \param[in]	sig			KSI signature.
	 * \param[in]	aggr		Aggregation chain.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_Signature_appendAggregationChain(KSI_Signature *sig, KSI_AggregationHashChain *aggr);

	/**
	 * Aggregate the aggregation chain.
	 * \param[in]	aggr		The aggregation chain.
	 * \param[in]	startLevel	The level of the first chain link.
	 * \param[out]	endLevel	The level of the root node. Can be NULL.
	 * \param[out]	root		Pointer to the receiving pointer. Can be NULL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AggregationHashChain_aggregate(const KSI_AggregationHashChain *aggr, int startLevel, int *endLevel, KSI_DataHash **root);

	/**
	 * This function will represent the shape of the aggregation chain. The bits represent the path from the root
	 * of the tree to the location of a hash value as a sequence of moves from a parent node in the tree to either
	 * the left or right child (bit values 0 and 1, respectively). Each bit sequence starts with a 1-bit to make
	 * sure no left most 0-bits are lost.
	 * \param[in]	chn			The aggregation chain.
	 * \param[out]	shape		Pointer to the receiving variable.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AggregationHashChain_calculateShape(KSI_AggregationHashChain *chn, KSI_uint64_t *shape);

	int KSI_AggregationHashChain_getAggregationTime(const KSI_AggregationHashChain *aggr, KSI_Integer **aggregationTime);
	int KSI_AggregationHashChain_getChainIndex(const KSI_AggregationHashChain * aggr, KSI_LIST(KSI_Integer) **chainIndex);
	int KSI_AggregationHashChain_getInputData(const KSI_AggregationHashChain * aggr, KSI_OctetString **inputData);
	int KSI_AggregationHashChain_getInputHash(const KSI_AggregationHashChain * aggr, KSI_DataHash **inputHash);
	int KSI_AggregationHashChain_getAggrHashId(const KSI_AggregationHashChain * aggr, KSI_Integer **aggrHashId);
	int KSI_AggregationHashChain_getChain(const KSI_AggregationHashChain * aggr, KSI_LIST(KSI_HashChainLink) **chain);

	int KSI_AggregationHashChain_setAggregationTime(KSI_AggregationHashChain *aggr, KSI_Integer *aggregationTime);
	int KSI_AggregationHashChain_setChainIndex(KSI_AggregationHashChain * aggr, KSI_LIST(KSI_Integer) *chainIndex);
	int KSI_AggregationHashChain_setInputData(KSI_AggregationHashChain * aggr, KSI_OctetString *inputData);
	int KSI_AggregationHashChain_setInputHash(KSI_AggregationHashChain * aggr, KSI_DataHash *inputHash);
	int KSI_AggregationHashChain_setAggrHashId(KSI_AggregationHashChain * aggr, KSI_Integer *aggrHashId);
	int KSI_AggregationHashChain_setChain(KSI_AggregationHashChain * aggr, KSI_LIST(KSI_HashChainLink) *chain);
	KSI_DEFINE_REF(KSI_AggregationHashChain);
	KSI_DEFINE_WRITE_BYTES(KSI_AggregationHashChain);

	/**
	 * This function aggregates the aggregation hash chain list and returns the result hash via \c outputHash parameter.
	 * \param[in]	chainList		Hash chain list (list of hash chains)
	 * \param[in]	ctx				KSI context
	 * \param[in]	level			Aggregation level
	 * \param[out]	outputHash		Pointer to the receiving pointer to data hash object.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_free.
	 */
	int KSI_AggregationHashChainList_aggregate(KSI_AggregationHashChainList *chainList, KSI_CTX *ctx, int level, KSI_DataHash **outputHash);

	/**
	 * Function for getting publication information from an extended signature.
	 * \param [in]		sig			Extended signature including publication record.
	 * \param [out]		pubHsh		Publication hash.
	 * \param [out]		pubStr		Publication data converted into a base-32 encoded string.
	 * \param [out]		pubDate		Publicatoin date
	 * \param [out]		pubRefs		Publication references.
	 * \param [out]		repUrls		Publication URL repositories.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note	The output memory has to be freed by the caller
	 * \see		#KSI_DataHash_free, #KSI_Utf8String_free, #KSI_Utf8StringList_free
	 */
	int KSI_Signature_getPublicationInfo(KSI_Signature *sig, KSI_DataHash **pubHsh, KSI_Utf8String **pubStr, time_t *pubDate, KSI_LIST(KSI_Utf8String) **pubRefs, KSI_LIST(KSI_Utf8String) **repUrls);

	/**
	 * Verifies that the document matches the signature.
	 * \param[in]	sig			KSI signature.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	doc			Pointer to document.
	 * \param[in]	doc_len		Document length.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_Signature_verifyDocument(KSI_Signature *sig, KSI_CTX *ctx, void *doc, size_t doc_len);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_SIGNATURE_H_ */
