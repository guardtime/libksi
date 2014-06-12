#ifndef KSI_HASHCHAIN_H_
#define KSI_HASHCHAIN_H_

#include "ksi_common.h"
#include "ksi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * This function joins to hash nodes by creating a common parent. The imprints
	 * of the two nodes are concatenated and added
	 *
	 * @param[in]	left		Left sibling.
	 * @param[in]	right		Right sibling.
	 * @param[out]	root		Pointer to the receiving pointer of the new root hash node.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HashChain_getCalendarAggregationTime(const KSI_LIST(KSI_HashChainLink) *chain, const KSI_Integer *aggr_time, uint32_t *utc_time);
	int KSI_HashChain_appendLink(KSI_CTX *ctx, KSI_DataHash *siblingHash, KSI_DataHash *metaHash, KSI_MetaData *metaData, int isLeft, unsigned int levelCorrection, KSI_LIST(KSI_HashChainLink) **chain);

	/**
	 * TODO!
	 */
	int KSI_HashChain_aggregate(KSI_LIST(KSI_HashChainLink) *chain, KSI_DataHash *inputHash, int startLevel, int hash_id, int *endLevel, KSI_DataHash **outputHash);

	/**
	 *
	 */
	int KSI_HashChain_aggregateCalendar(KSI_LIST(KSI_HashChainLink) *chain, KSI_DataHash *inputHash, KSI_DataHash **outputHash);


#ifdef __cplusplus
}
#endif

#endif /* KSI_HASHCHAIN_H_ */
