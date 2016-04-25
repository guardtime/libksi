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

#ifndef BLOCKSIGNER_H_
#define BLOCKSIGNER_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KSI_Blocksigner_st KSI_Blocksigner;
typedef struct KSI_BlocksignerHandle_st KSI_BlocksignerHandle;

/**
 * Create a new instance of #KSI_Blocksigner.
 * \param[in]	ctx			KSI context.
 * \param[in]	algoId		Algorithm to be used for the internal hash values.
 * \param[out]	signer		Pointer to the receiving pointer.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_Blocksigner_new(KSI_CTX *ctx, KSI_HashAlgorithm algoId, KSI_Blocksigner **signer);

/**
 * Cleanup method for the #KSI_Blocksigner.
 * \param[in]	signer		Instance of the #KSI_Blocksigner.
 */
void KSI_Blocksigner_free(KSI_Blocksigner *signer);

/**
 * This function finalizes the computation of the tree but does not free the resources.
 * \param[in]	signer		Instance of the #KSI_Blocksigner.
 * \param[out]	ms			Pointer to the receiving poitner.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_Blocksigner_close(KSI_Blocksigner *signer, KSI_MultiSignature **ms);

/**
 * Resets the block signer to its initial state. This will invalidate all the
 * #KSI_BlocksignerHandle instances still remaining.
 * \param[in]	signer		Instance of the #KSI_Blocksigner.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_Blocksigner_reset(KSI_Blocksigner *signer);

/**
 * Add a new leaf to the tree.
 * \param[in]	signer		Instance of the #KSI_Blocksigner.
 * \param[in]	hsh			Hash value of the leaf.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_Blocksigner_add(KSI_Blocksigner *signer, KSI_DataHash *hsh);

/**
 * Lowlevel function for adding leafs to the aggregation tree.
 * \param[in]	signer		Instance of the #KSI_Blocksigner.
 * \param[in]	hsh			Hash value of the leaf node.
 * \param[in]	level		Level of the leaf node.
 * \param[out]	handle		Handle for the current leaf; may be NULL.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_Blocksigner_addLeaf(KSI_Blocksigner *signer, KSI_DataHash *hsh, int level, KSI_BlocksignerHandle **handle);

/**
 * This function generates an aggregation hash chain object. This method will fail if the instance of #KSI_Blocksigner has not
 * been closed, it has been reset or it has been freed.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_Blocksigner_close, #KSI_Blocksigner_free, #KSI_Blocksigner_reset.
 */
int KSI_BlocksignerHandle_getAggregationChain(KSI_BlocksignerHandle *handle, KSI_AggregationHashChain **chain);


#ifdef __cplusplus
}
#endif

#endif /* BLOCKSIGNER_H_ */
