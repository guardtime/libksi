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


#ifndef TREE_NODE_H_
#define TREE_NODE_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup treebuilder Tree Builder
 * The tree builder is used to create an aggregation tree locally. This can be used to create
 * multiple signatures with a single aggregation request.
 * @{
 */

/**
 * The tree leaf handle is used to generate an aggregation hash chain for
 * a specific leaf added to the tree builder.
 */
typedef struct KSI_TreeLeafHandle_st KSI_TreeLeafHandle;

/**
 * Free the tree leaf handle.
 * \param[in]	handle		The tree leaf handle.
 * \see #KSI_TreeBuilder_addDataHash and #KSI_TreeBuilder_addMetaData
 */
void KSI_TreeLeafHandle_free(KSI_TreeLeafHandle *handle);

/**
 * Generates an aggregation hash chain starting from the added leaf that the tree leaf handle
 * is based on. The resulting object must be feed by the caller.
 * \param[in]	handle		The tree leaf handle.
 * \param[out]	chain		Pointer to the receiving pointer.
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 * \see #KSI_AggregationHashChain_free.
 */
int KSI_TreeLeafHandle_getAggregationChain(KSI_TreeLeafHandle *handle, KSI_AggregationHashChain **chain);

/**
 * An object for building an aggregation tree on the fly.
 */
typedef struct KSI_TreeBuilder_st KSI_TreeBuilder;

/**
 * Constructor for the #KSI_TreeBuilder object.
 * \param[in]	ctx			KSI context.
 * \param[in]	algo		Algorithm used for the internal nodes.
 * \param[out]	builder		Pointer to the receiving pointer.
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 * \see #KSI_TreeBuilder_free
 */
int KSI_TreeBuilder_new(KSI_CTX *ctx, KSI_HashAlgorithm algo, KSI_TreeBuilder **builder);

/**
 * Destructor for the #KSI_TreeBuilder object.
 * \param[in]	builder		Pointer to the object.
 * \see KSI_TreeNuilder_new
 */
void KSI_TreeBuilder_free(KSI_TreeBuilder *builder);

/**
 * Adds a new leaf to the tree.
 * \param[in]	builder		The builder.
 * \param[in]	hsh			The data hash of the leaf.
 * \param[in]	level		The level of the leaf.
 * \param[out]	leaf		Pointer to the receiving pointer for the handle.
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 * \see #KSI_TreeLeafHandle_free
 */
int KSI_TreeBuilder_addDataHash(KSI_TreeBuilder *builder, KSI_DataHash *hsh, int level, KSI_TreeLeafHandle **leaf);

/**
 * Adds a new leaf to the tree containing a meta-data value instead of the data hash as in #KSI_TreeBuilder_addDataHash.
 * \param[in]	builder		The builder.
 * \param[in]	metaData	The meta-data of the leaf.
 * \param[in]	level		The level of the leaf.
 * \param[out]	leaf		Pointer to the receiving pointer for the handle.
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 * \see #KSI_TreeLeafHandle_free
 */
int KSI_TreeBuilder_addMetaData(KSI_TreeBuilder *builder, KSI_MetaData *metaData, int level, KSI_TreeLeafHandle **leaf);

/**
 * This function finalizes the building of the tree. After calling this function no more leafs
 * may be added to the computation and doing so would result in an error.
 * \param[in]	buillder 	The builder.
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
int KSI_TreeBuilder_close(KSI_TreeBuilder *builder);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* TREE_NODE_H_ */