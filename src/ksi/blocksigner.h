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

#ifndef BLOCKSIGNER_H_
#define BLOCKSIGNER_H_

#include "ksi.h"
#include "multi_signature.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KSI_BlockSigner_st KSI_BlockSigner;
typedef struct KSI_BlockSignerHandle_st KSI_BlockSignerHandle;

KSI_DEFINE_LIST(KSI_BlockSignerHandle);

/**
 * Create a new instance of #KSI_BlockSigner.
 * \param[in]	ctx			KSI context.
 * \param[in]	algoId		Algorithm to be used for the internal hash node computation.
 * \param[in]	prevLeaf	For linking two trees, the user may add the last leaf value (can be \c NULL)
 * \param[in]	initVal		The initial value for masking.
 * \param[out]	signer		Pointer to the receiving pointer.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_BlockSigner_new(KSI_CTX *ctx, KSI_HashAlgorithm algoId, KSI_DataHash *prevLeaf, KSI_OctetString *initVal, KSI_BlockSigner **signer);

/**
 * Cleanup method for the #KSI_BlockSigner.
 * \param[in]	signer		Instance of the #KSI_BlockSigner.
 */
void KSI_BlockSigner_free(KSI_BlockSigner *signer);

/**
 * This function finalizes the computation of the tree but does not free the resources.
 * \param[in]	signer		Instance of the #KSI_BlockSigner.
 * \param[out]	ms			Pointer to the receiving poitner.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_BlockSigner_close(KSI_BlockSigner *signer, KSI_MultiSignature **ms);

/**
 * Resets the block signer to its initial state. This will invalidate all the
 * #KSI_BlockSignerHandle instances still remaining.
 * \param[in]	signer		Instance of the #KSI_BlockSigner.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_BlockSigner_reset(KSI_BlockSigner *signer);

/**
 * Add a new leaf to the tree.
 * \param[in]	signer		Instance of the #KSI_BlockSigner.
 * \param[in]	hsh			Hash value of the leaf.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
#define KSI_BlockSigner_add(signer, hsh) KSI_BlockSigner_addLeaf((signer), (hsh), 0, NULL, NULL)

/**
 * Lowlevel function for adding leafs to the aggregation tree.
 * \param[in]	signer		Instance of the #KSI_BlockSigner.
 * \param[in]	hsh			Hash value of the leaf node.
 * \param[in]	level		Level of the leaf node.
 * \param[in]	metaData	A meta-data object to associate the input hash with, can be \c NULL.
 * \param[out]	handle		Handle for the current leaf; may be NULL.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \note The function does not take ownership of \c hsh, \c metaData nor \c handle, it is
 * the responsibility of the caller to free the objects.
 * \see #KSI_DataHash_free, #KSI_MetaData_free, #KSI_BlockSignerHandle_free.
 */
int KSI_BlockSigner_addLeaf(KSI_BlockSigner *signer, KSI_DataHash *hsh, int level, KSI_MetaData *metaData, KSI_BlockSignerHandle **handle);

/**
 * This function creates a new instance of a KSI signature and stores it in the output
 * parameter.
 * \param[in]	handle		Handle for the block signature.
 * \param[out]	sig			Pointer to the receiving pointer.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_BlockSigner_close, #KSI_BlockSigner_free, #KSI_BlockSigner_reset.
 */
int KSI_BlockSignerHandle_getSignature(KSI_BlockSignerHandle *handle, KSI_Signature **sig);

/**
 * Cleanup method for the handle.
 * \param[in]	handle		Instance of the #KSI_BlockSignerHandle
 */
void KSI_BlockSignerHandle_free(KSI_BlockSignerHandle *handle);

#ifdef __cplusplus
}
#endif

#endif /* BLOCKSIGNER_H_ */
