#ifndef KSI_HASHCHAIN_H_
#define KSI_HASHCHAIN_H_

#include <time.h>

#include "list.h"
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
	 */
	int KSI_HashChain_aggregate(KSI_CTX *, KSI_LIST(KSI_HashChainLink) *chain, const KSI_DataHash *inputHash, int startLevel, int hash_id, int *endLevel, KSI_DataHash **outputHash);

	/**
	 * This function aggregates the calendar hash chain and returns the result hash via \c outputHash parameter.
	 * \param[in]	chain			Hash chain.
	 * \param[in]	inputHash		Input hash value.
	 * \param[out]	outputHash		Pointer to the receiving pointer to data hash object.
	 */
	int KSI_HashChain_aggregateCalendar(KSI_CTX *, KSI_LIST(KSI_HashChainLink) *chain, const KSI_DataHash *inputHash, KSI_DataHash **outputHash);

	/**
	 * KSI_HashChainLink
	 */
	void KSI_HashChainLink_free(KSI_HashChainLink *t);
	int KSI_HashChainLink_new(KSI_CTX *ctx, KSI_HashChainLink **t);
	int KSI_HashChainLink_getIsLeft(const KSI_HashChainLink *t, int *isLeft);
	int KSI_HashChainLink_getLevelCorrection(const KSI_HashChainLink *t, KSI_Integer **levelCorrection);
	int KSI_HashChainLink_getMetaHash(const KSI_HashChainLink *t, KSI_DataHash **metaHash);
	int KSI_HashChainLink_getMetaData(const KSI_HashChainLink *t, KSI_MetaData **metaData);
	int KSI_HashChainLink_getImprint(const KSI_HashChainLink *t, KSI_DataHash **imprint);
	int KSI_HashChainLink_setIsLeft(KSI_HashChainLink *t, int isLeft);
	int KSI_HashChainLink_setLevelCorrection(KSI_HashChainLink *t, KSI_Integer *levelCorrection);
	int KSI_HashChainLink_setMetaHash(KSI_HashChainLink *t, KSI_DataHash *metaHash);
	int KSI_HashChainLink_setMetaData(KSI_HashChainLink *t, KSI_MetaData *metaData);
	int KSI_HashChainLink_setImprint(KSI_HashChainLink *t, KSI_DataHash *imprint);

	int KSI_HashChainLink_fromTlv(KSI_TLV *tlv, KSI_HashChainLink **link);
	int KSI_HashChainLink_toTlv(KSI_CTX *ctx, KSI_HashChainLink *link, unsigned tag, int isNonCritica, int isForward, KSI_TLV **tlv);


	int KSI_CalendarHashChainLink_fromTlv(KSI_TLV *tlv, KSI_CalendarHashChainLink **link);
	int KSI_CalendarHashChainLink_toTlv(KSI_CTX *ctx, KSI_CalendarHashChainLink *link, unsigned tag, int isNonCritica, int isForward, KSI_TLV **tlv);

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
