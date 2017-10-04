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

#ifndef KSI_HASHCHAIN_H_
#define KSI_HASHCHAIN_H_

#include <time.h>

#include "hash.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup hashchain Hashchain Computation
 * This module contains hash chain computation methods.
 * General hash chains are represented as a list of #KSI_HashChainLink objects, where the first
 * element is also the first sibling.
 * @{
 */

	/**
	 * Hash chain link identity type.
	 */
	typedef enum KSI_HashChainLinkIdentityType_en {
		/**
		 * Legacy client identifier.
		 * A client identifier converted from a legacy signature.
		 */
		KSI_IDENTITY_TYPE_LEGACY_ID,
		/**
		 * Metadata.
		 * A structure that provides the ability to incorporate client identity and
		 * other information about the request into the hash chain.
		 */
		KSI_IDENTITY_TYPE_METADATA,

		KSI_IDENTITY_TYPE_UNKNOWN
	} KSI_HashChainLinkIdentityType;

	/**
	 * This function aggregates the hashchain and returns the result hash via \c outputHash parameter.
	 * \param[in]	chain			Hash chain (list of hash chain links)
	 * \param[in]	inputHash		Input hash value.
	 * \param[in]	startLevel		The initial level of this hash chain.
	 * \param[in]	algo_id			Hash algorithm to be used to calculate the next value.
	 * \param[out]	endLevel		Pointer to the receiving end level variable.
	 * \param[out]	outputHash		Pointer to the receiving pointer to data hash object.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HashChain_aggregate(KSI_CTX *, KSI_LIST(KSI_HashChainLink) *chain, const KSI_DataHash *inputHash, int startLevel, KSI_HashAlgorithm algo_id, int *endLevel, KSI_DataHash **outputHash);

	/**
	 * This function aggregates the calendar hash chain and returns the result hash via \c outputHash parameter.
	 * \param[in]	chain			Hash chain.
	 * \param[in]	inputHash		Input hash value.
	 * \param[out]	outputHash		Pointer to the receiving pointer to data hash object.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HashChain_aggregateCalendar(KSI_CTX *, KSI_LIST(KSI_HashChainLink) *chain, const KSI_DataHash *inputHash, KSI_DataHash **outputHash);

	/**
	 * Free the resources of a #KSI_HashChainLink
	 * \param[in]	t		Pointer to #KSI_HashChainLink
	 */
	void KSI_HashChainLink_free(KSI_HashChainLink *t);

	/**
	 * Creates a new empty #KSI_HashChainLink.
	 * \param[in]	ctx		KSI context.
	 * \param[out]	t		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_HashChainLink_free
	 */
	int KSI_HashChainLink_new(KSI_CTX *ctx, KSI_HashChainLink **t);

	/**
	 * Getter method for \c isLeft.
	 * \param[in]	t		Pointer to #KSI_HashChainLink.
	 * \param[out]	isLeft	Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HashChainLink_getIsLeft(const KSI_HashChainLink *t, int *isLeft);

	/**
	 * Getter method for \c levelCorrection.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[out]	levelCorrection		Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The output object still belongs to \c t.
	 */
	int KSI_HashChainLink_getLevelCorrection(const KSI_HashChainLink *t, KSI_Integer **levelCorrection);

	/**
	 * Getter method for \c legacyId.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[out]	legacyId			Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The output object still belongs to \c t.
	 */
	int KSI_HashChainLink_getLegacyId(const KSI_HashChainLink *t, KSI_OctetString **legacyId);

	/**
	 * Getter method for \c metaData.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[out]	metaData			Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The output object still belongs to \c t.
	 */
	int KSI_HashChainLink_getMetaData(const KSI_HashChainLink *t, KSI_MetaDataElement **metaData);

	/**
	 * Getter method for \c imprint.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[out]	imprint				Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The output object still belongs to \c t.
	 */
	int KSI_HashChainLink_getImprint(const KSI_HashChainLink *t, KSI_DataHash **imprint);

	/**
	 * Setter method for \c isLeft.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[in]	isLeft				Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HashChainLink_setIsLeft(KSI_HashChainLink *t, int isLeft);

	/**
	 * Setter method for \c levelCorrection.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[in]	levelCorrection		Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note After calling the setter, the the object belongs to \c t and will be freed by #KSI_HashChainLink_free.
	 */
	int KSI_HashChainLink_setLevelCorrection(KSI_HashChainLink *t, KSI_Integer *levelCorrection);

	/**
	 * Setter method for \c legacyId.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[in]	legacyId			Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note After calling the setter, the the object belongs to \c t and will be freed by #KSI_HashChainLink_free.
	 */
	int KSI_HashChainLink_setLegacyId(KSI_HashChainLink *t, KSI_OctetString *legacyId);

	/**
	 * Setter method for \c metaData.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[in]	metaData			Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note After calling the setter, the the object belongs to \c t and will be freed by #KSI_HashChainLink_free.
	 */
	int KSI_HashChainLink_setMetaData(KSI_HashChainLink *t, KSI_MetaDataElement *metaData);

	/**
	 * Setter method for \c imprint.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[in]	imprint				Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note After calling the setter, the the object belongs to \c t and will be freed by #KSI_HashChainLink_free.
	 */
	int KSI_HashChainLink_setImprint(KSI_HashChainLink *t, KSI_DataHash *imprint);

	KSI_DEFINE_FN_FROM_TLV(KSI_HashChainLink);
	KSI_DEFINE_FN_TO_TLV(KSI_HashChainLink);

	int KSI_HashChainLink_LegacyId_fromTlv(KSI_TLV *tlv, KSI_OctetString **legacyId);
	int KSI_HashChainLink_LegacyId_toTlv(KSI_CTX *ctx, const KSI_OctetString *legacyId, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

	KSI_DEFINE_FN_FROM_TLV(KSI_CalendarHashChainLink);
	KSI_DEFINE_FN_TO_TLV(KSI_CalendarHashChainLink);

	/**
	 * KSI_CalendarHashChain
	 */
	void KSI_CalendarHashChain_free(KSI_CalendarHashChain *t);
	int KSI_CalendarHashChain_new(KSI_CTX *ctx, KSI_CalendarHashChain **t);
	int KSI_CalendarHashChain_aggregate(KSI_CalendarHashChain *chain, KSI_DataHash **hsh);
	int KSI_CalendarHashChain_calculateAggregationTime(const KSI_CalendarHashChain *chain, time_t *aggrTime);
	int KSI_CalendarHashChain_getPublicationTime(const KSI_CalendarHashChain *t, KSI_Integer **publicationTime);
	int KSI_CalendarHashChain_getAggregationTime(const KSI_CalendarHashChain *t, KSI_Integer **aggregationTime);
	int KSI_CalendarHashChain_getInputHash(const KSI_CalendarHashChain *t, KSI_DataHash **inputHash);
	int KSI_CalendarHashChain_getHashChain(const KSI_CalendarHashChain *t, KSI_LIST(KSI_HashChainLink) **hashChain);
	int KSI_CalendarHashChain_setPublicationTime(KSI_CalendarHashChain *t, KSI_Integer *publicationTime);
	int KSI_CalendarHashChain_setAggregationTime(KSI_CalendarHashChain *t, KSI_Integer *aggregationTime);
	int KSI_CalendarHashChain_setInputHash(KSI_CalendarHashChain *t, KSI_DataHash *inputHash);
	int KSI_CalendarHashChain_setHashChain(KSI_CalendarHashChain *t, KSI_LIST(KSI_HashChainLink) *hashChain);
	KSI_DEFINE_REF(KSI_CalendarHashChain);
	KSI_DEFINE_WRITE_BYTES(KSI_CalendarHashChain);

	void KSI_HashChainLinkIdentity_free(KSI_HashChainLinkIdentity *identity);
	int KSI_HashChainLinkIdentity_getType(const KSI_HashChainLinkIdentity *o, KSI_HashChainLinkIdentityType *v);
	int KSI_HashChainLinkIdentity_getClientId(const KSI_HashChainLinkIdentity *o, KSI_Utf8String **v);
	int KSI_HashChainLinkIdentity_getMachineId(const KSI_HashChainLinkIdentity *o, KSI_Utf8String **v);
	int KSI_HashChainLinkIdentity_getSequenceNr(const KSI_HashChainLinkIdentity *o, KSI_Integer **v);
	int KSI_HashChainLinkIdentity_getRequestTime(const KSI_HashChainLinkIdentity *o, KSI_Integer **v);
	KSI_DEFINE_REF(KSI_HashChainLinkIdentity);

	/**
	 * Get aggregation hash chain identity. The returned list consists of individual hash chain link identities.
	 * The identities in the list are ordered - the higher-link identity is before lower-link identity.
	 * \param[in]	aggr		Aggregation hash chain.
	 * \param[in]	identity	Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AggregationHashChain_getIdentity(const KSI_AggregationHashChain *aggr, KSI_HashChainLinkIdentityList **identity);

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

	KSI_FN_DEPRECATED(int KSI_Signature_appendAggregationChain(KSI_Signature *sig, KSI_AggregationHashChain *aggr), Use #KSI_SignatureBuilder_appendAggregationChain.);

	/**
	 * Aggregate the aggregation chain.
	 * \param[in]	aggr		The aggregation chain.
	 * \param[in]	startLevel	The level of the first chain link.
	 * \param[out]	endLevel	The level of the root node. Can be NULL.
	 * \param[out]	root		Pointer to the receiving pointer. Can be NULL.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AggregationHashChain_aggregate(KSI_AggregationHashChain *aggr, int startLevel, int *endLevel, KSI_DataHash **root);

	/**
	 * This function will represent the shape of the aggregation chain. The bits represent the path from the root
	 * of the tree to the location of a hash value as a sequence of moves from a parent node in the tree to either
	 * the left or right child (bit values 0 and 1, respectively). Each bit sequence starts with a 1-bit to make
	 * sure no left most 0-bits are lost.
	 * \param[in]	chn			The aggregation chain.
	 * \param[out]	shape		Pointer to the receiving variable.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_AggregationHashChain_calculateShape(const KSI_AggregationHashChain *chn, KSI_uint64_t *shape);

	int KSI_AggregationHashChain_compare(const KSI_AggregationHashChain **left, const KSI_AggregationHashChain **right);

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
	 * \param[in]	chainList		Hash chain list (list of hash chains).
	 * \param[in]	ctx				KSI context.
	 * \param[in]	level			Aggregation level.
	 * \param[out]	outputHash		Pointer to the receiving pointer to data hash object.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_free.
	 */
	int KSI_AggregationHashChainList_aggregate(KSI_AggregationHashChainList *chainList, KSI_CTX *ctx, int level, KSI_DataHash **outputHash);


/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_HASHCHAIN_H_ */
