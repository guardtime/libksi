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
	 * Given the publication time \c pub_time and the aggregation chain \c chain, the aggregation UTC time
	 * is calculated.
	 * \param[in]	chain			Aggregation chain.
	 * \param[in]	pub_time		Publication time.
	 * \param[out]	utc_time		UTC time of the aggregation.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_HashChain_getCalendarAggregationTime(const KSI_LIST(KSI_HashChainLink) *chain, const KSI_Integer *pub_time, time_t *utc_time);

	/**
	 * This function aggregates the hashchain and returns the result hash via \c outputHash parameter.
	 * \param[in]	chain			Hash chain (list of hash chain links)
	 * \param[in]	inputHash		Input hash value.
	 * \param[in]	startLevel		The initial level of this hash chain.
	 * \param[in]	hash_id			Hash algorithm to be used to calculate the next value.
	 * \param[out]	endLevel		Pointer to the receiving end level variable.
	 * \param[out]	outputHash		Pointer to the receiving pointer to data hash object.
	 */
	int KSI_HashChain_aggregate(KSI_LIST(KSI_HashChainLink) *chain, KSI_DataHash *inputHash, int startLevel, int hash_id, int *endLevel, KSI_DataHash **outputHash);

	/**
	 * This function aggregates the calendar hash chain and returns the result hash via \c outputHash parameter.
	 * \param[in]	chain			Hash chain.
	 * \param[in]	inputHash		Input hash value.
	 * \param[out]	outputHash		Pointer to the receiving pointer to data hash object.
	 */
	int KSI_HashChain_aggregateCalendar(KSI_LIST(KSI_HashChainLink) *chain, KSI_DataHash *inputHash, KSI_DataHash **outputHash);

	/**
	 * @}
	 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_HASHCHAIN_H_ */
