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
 * An object representing an arbitrary node of an aggregation tree.
 */
typedef struct KSI_TreeNode_st KSI_TreeNode;

/**
 * TODO!
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
int KSI_TreeNode_new(KSI_CTX *ctx, KSI_DataHash *hash, unsigned level, KSI_TreeNode **node);

/**
 *
 */
void KSI_TreeNode_free(KSI_TreeNode *node);

/**
 * TODO!
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
int KSI_TreeNode_join(KSI_CTX *ctx, KSI_HashAlgorithm algo, KSI_TreeNode *leftSibling, KSI_TreeNode *rightSibling, KSI_TreeNode **root);

KSI_DEFINE_REF(KSI_TreeNode);

KSI_DEFINE_LIST(KSI_TreeNode);

/* =================== */

/**
 * A structure to reference a leaf of an aggregation chain.
 */
typedef struct KSI_TreeLeaf_st KSI_TreeLeaf;

/**
 * Destructor for #KSI_TreeLeaf object.
 * \param[in]	leaf		Pointer to the object.
 */
void KSI_TreeLeaf_free(KSI_TreeLeaf *leaf);

/* =================== */

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
 *
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 * \see #KSI_TreeLeaf_free
 */
int KSI_TreeBuilder_addLeaf(KSI_TreeBuilder *builder, KSI_DataHash *hsh, unsigned level, KSI_TreeLeaf **leaf);

#ifdef __cplusplus
}
#endif

#endif /* TREE_NODE_H_ */
