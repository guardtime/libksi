/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#ifndef KSI_HASHCHAIN_H_
#define KSI_HASHCHAIN_H_

#include <time.h>

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup hashchain Hashchain computation.
 * This module contains hasch chain computation methods.
 * General hash chains are represented as a list of #KSI_HashChainLink objects, where the first
 * element is also the first sibling.
 * @{
 */

	/**
	 * This function aggregates the hashchain and returns the result hash via \c outputHash parameter.
	 * \param[in]	chain			Hash chain (list of hash chain links)
	 * \param[in]	inputHash		Input hash value.
	 * \param[in]	startLevel		The initial level of this hash chain.
	 * \param[in]	hash_id			Hash algorithm to be used to calculate the next value.
	 * \param[out]	endLevel		Pointer to the receiving end level variable.
	 * \param[out]	outputHash		Pointer to the receiving pointer to data hash object.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HashChain_aggregate(KSI_CTX *, KSI_LIST(KSI_HashChainLink) *chain, const KSI_DataHash *inputHash, int startLevel, int hash_id, int *endLevel, KSI_DataHash **outputHash);

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
	 * \param[out]	t		Pointer to the receiving ponter.
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
	 * Getter method for \c metaHash.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[out]	metaHash			Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The output object still belongs to \c t.
	 */
	int KSI_HashChainLink_getMetaHash(const KSI_HashChainLink *t, KSI_DataHash **metaHash);

	/**
	 * Getter method for \c metaData.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[out]	metaData			Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The output object still belongs to \c t.
	 */
	int KSI_HashChainLink_getMetaData(const KSI_HashChainLink *t, KSI_MetaData **metaData);

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
	 * \note After celling the setter, the the object belongs to \c t and will be freed by #KSI_HashChainLink_free.
	 */
	int KSI_HashChainLink_setLevelCorrection(KSI_HashChainLink *t, KSI_Integer *levelCorrection);

	/**
	 * Setter method for \c metaHash.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[in]	metaHash			Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note After celling the setter, the the object belongs to \c t and will be freed by #KSI_HashChainLink_free.
	 */
	int KSI_HashChainLink_setMetaHash(KSI_HashChainLink *t, KSI_DataHash *metaHash);

	/**
	 * Setter method for \c metaData.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[in]	metaData			Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note After celling the setter, the the object belongs to \c t and will be freed by #KSI_HashChainLink_free.
	 */
	int KSI_HashChainLink_setMetaData(KSI_HashChainLink *t, KSI_MetaData *metaData);

	/**
	 * Setter method for \c imprint.
	 * \param[in]	t					Pointer to #KSI_HashChainLink.
	 * \param[in]	imprint				Pointer to receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note After celling the setter, the the object belongs to \c t and will be freed by #KSI_HashChainLink_free.
	 */
	int KSI_HashChainLink_setImprint(KSI_HashChainLink *t, KSI_DataHash *imprint);

	KSI_DEFINE_FN_FROM_TLV(KSI_HashChainLink);
	KSI_DEFINE_FN_TO_TLV(KSI_HashChainLink);

	KSI_DEFINE_FN_FROM_TLV(KSI_CalendarHashChainLink);
	KSI_DEFINE_FN_TO_TLV(KSI_CalendarHashChainLink);

	/**
	 * KSI_CalendarHashChain
	 */
	void KSI_CalendarHashChain_free(KSI_CalendarHashChain *t);
	int KSI_CalendarHashChain_new(KSI_CTX *ctx, KSI_CalendarHashChain **t);
	int KSI_CalendarHashChain_aggregate(KSI_CalendarHashChain *chain, KSI_DataHash **hsh);
	int KSI_CalendarHashChain_calculateAggregationTime(KSI_CalendarHashChain *chain, time_t *aggrTime);
	int KSI_CalendarHashChain_getPublicationTime(const KSI_CalendarHashChain *t, KSI_Integer **publicationTime);
	int KSI_CalendarHashChain_getAggregationTime(const KSI_CalendarHashChain *t, KSI_Integer **aggregationTime);
	int KSI_CalendarHashChain_getInputHash(const KSI_CalendarHashChain *t, KSI_DataHash **inputHash);
	int KSI_CalendarHashChain_getHashChain(const KSI_CalendarHashChain *t, KSI_LIST(KSI_HashChainLink) **hashChain);
	int KSI_CalendarHashChain_setPublicationTime(KSI_CalendarHashChain *t, KSI_Integer *publicationTime);
	int KSI_CalendarHashChain_setAggregationTime(KSI_CalendarHashChain *t, KSI_Integer *aggregationTime);
	int KSI_CalendarHashChain_setInputHash(KSI_CalendarHashChain *t, KSI_DataHash *inputHash);
	int KSI_CalendarHashChain_setHashChain(KSI_CalendarHashChain *t, KSI_LIST(KSI_HashChainLink) *hashChain);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_HASHCHAIN_H_ */
