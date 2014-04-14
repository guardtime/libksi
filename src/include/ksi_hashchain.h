#ifndef KSI_HASHCHAIN_H_
#define KSI_HASHCHAIN_H_

#include "ksi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * Hash node cleanup method.
	 *
	 * @param[in]	node	Hash node to be freed.
	 */
	void KSI_HashChain_free(KSI_HashChain *node);

	/**
	 * Constructor for the hash node object.
	 *
	 * @param[in]	ctx		KSI context.
	 * @param[in]	hash	Datahash object.
	 * @param[in]	level	Level of the current node (leafs have level 0).
	 * @param[out]	node	Pointer to the receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_HashChain_new(KSI_CTX *ctx, KSI_DataHash *hash, unsigned int levelCorrection, int isLeft, KSI_HashChain **node);

	/**
	 * This function joins to hash nodes by creating a common parent. The imprints
	 * of the two nodes are concatenated and added
	 *
	 * @param[in]	left		Left sibling.
	 * @param[in]	right		Right sibling.
	 * @param[out]	root		Pointer to the receiving pointer of the new root hash node.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_HashNode_join(KSI_HashChain *left, KSI_HashChain *right, int hash_id, KSI_HashChain **root);
	int KSI_HashNode_buildCalendar(KSI_CTX *ctx, KSI_DataHash *sibling, int isLeft, KSI_HashChain **root);
	int KSI_HashChain_getCalendarAggregationTime(KSI_HashChain *cal, KSI_Integer *aggr_time, uint32_t *utc_time);

	/**
	 * Extracts the data hash value from the internal data hash object.
	 *
	 * @param[in]	node		Hash node object.
	 * @param[out]	hash		Pointer to the receiving data hash pointer.
	 *
	  * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note The digest value returned by this function has to be freed by the
	 * programmer with #KSI_DataHash_free.
	 */
	int KSI_HashNode_getDataHash(KSI_HashChain *node, const KSI_DataHash ** hsh);

	/**
	 * Extracts the imprint value from the internal data hash object.
	 *
	 * @param[in]	node				Hash node object.
	 * @param[out]	imprint				Pointer to the receiving imprint pointer.
	 * @param[out]	imprint_length		Pointer to the receiving imprint length variable.
	 *
	  * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note The digest value returned by this function has to be freed by the
	 * programmer with #KSI_free.
	 */
	int KSI_HashNode_getImprint(KSI_HashChain *node, unsigned char **imprint, int *imprint_length);


#ifdef __cplusplus
}
#endif

#endif /* KSI_HASHCHAIN_H_ */
