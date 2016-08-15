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

#define KSI_TREE_BUILDER_STACK_LEN 0x100

/**
 * A structure to represent the leaf and internal nodes of a hash tree.
 */
typedef struct KSI_TreeNode_st KSI_TreeNode;

/**
 * The leaf processor structure contains the function to pre processes the node specified as
 * the input and a context for the preprocessor. The function may alter the input node and
 * optionally generate a new one - usually meaning the input hash has been aggregated and the
 * output node is the root value of the aggregation.
 */
typedef struct KSI_TreeBuilderLeafProcessor_st KSI_TreeBuilderLeafProcessor;

struct KSI_TreeNode_st {
	/** KSI context. */
	KSI_CTX *ctx;
	/** Hash value of the node, may not be not NULL when metaData is not NULL. */
	KSI_DataHash *hash;
	/** Metadata value of the node, may not be not NULL when hash is not NULL */
	KSI_MetaData *metaData;
	/** The aggregation level of this node, 0 for leafs and 0xff is the maximum value. */
	unsigned level;
	/** Pointer to the parent element. */
	KSI_TreeNode *parent;
	/** The left child node. */
	KSI_TreeNode *leftChild;
	/** The right child node. */
	KSI_TreeNode *rightChild;
};

struct KSI_TreeBuilderLeafProcessor_st {
	/** Processor function.
	 * \param[in]	in		The input tree node.
	 * \param[in]	c		The processor context.
	 * \param[out]	out		Output value, if the function creates a new node - output may be NULL.
	 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
	 */
	int (*fn)(KSI_TreeNode *in, void *c, KSI_TreeNode **out);
	/** The processor context. */
	void *c;
};

KSI_DEFINE_LIST(KSI_TreeBuilderLeafProcessor);
#define KSI_TreeBuilderLeafProcessorList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->append((lst), (o)))
#define KSI_TreeBuilderLeafProcessorList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->removeElement((lst), (pos), (o)))
#define KSI_TreeBuilderLeafProcessorList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), (lst)->indexOf((lst), (o), (i)))
#define KSI_TreeBuilderLeafProcessorList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->insertAt((lst), (pos), (o)))
#define KSI_TreeBuilderLeafProcessorList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->replaceAt((lst), (pos), (o)))
#define KSI_TreeBuilderLeafProcessorList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->elementAt((lst), (pos), (o)))
#define KSI_TreeBuilderLeafProcessorList_length(lst) (((lst) != NULL) ? (lst)->length((lst)) : 0)
#define KSI_TreeBuilderLeafProcessorList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), (lst)->sort((lst), (cmp)))
#define KSI_TreeBuilderLeafProcessorList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (lst)->foldl((lst), (foldCtx), (foldFn)) : KSI_OK)

struct KSI_TreeBuilder_st {
	/** KSI context. */
	KSI_CTX *ctx;
	/** Reference counter for the object. */
	size_t ref;
	/** The root node of the computed tree. If set, the computation is finished. */
	KSI_TreeNode *rootNode;
	/** Hashing algorithm for the internal nodes. */
	KSI_HashAlgorithm algo;
	/** Stack of the root nodes of complete binary trees. */
	KSI_TreeNode *stack[KSI_TREE_BUILDER_STACK_LEN];
	/** Callback functions for the leaf node. They are executed as a sequence
	 * where the last output tree node is the input node for the next call. The
	 * final output node is added to the tree. */
	KSI_LIST(KSI_TreeBuilderLeafProcessor) *cbList;
};

/**
 * The tree leaf handle is used to generate an aggregation hash chain for
 * a specific leaf added to the tree builder.
 */
typedef struct KSI_TreeLeafHandle_st KSI_TreeLeafHandle;
KSI_DEFINE_LIST(KSI_TreeLeafHandle);
#define KSI_TreeLeafHandleList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->append((lst), (o)))
#define KSI_TreeLeafHandleList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->removeElement((lst), (pos), (o)))
#define KSI_TreeLeafHandleList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), (lst)->indexOf((lst), (o), (i)))
#define KSI_TreeLeafHandleList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->insertAt((lst), (pos), (o)))
#define KSI_TreeLeafHandleList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->replaceAt((lst), (pos), (o)))
#define KSI_TreeLeafHandleList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->elementAt((lst), (pos), (o)))
#define KSI_TreeLeafHandleList_length(lst) (((lst) != NULL) ? (lst)->length((lst)) : 0)
#define KSI_TreeLeafHandleList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), (lst)->sort((lst), (cmp)))
#define KSI_TreeLeafHandleList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (lst)->foldl((lst), (foldCtx), (foldFn)) : KSI_OK)

KSI_DEFINE_REF(KSI_TreeLeafHandle);

/**
 * This is the constructor method for the #KSI_TreeNode structure.
 * \param[in]	ctx			KSI context.
 * \param[in]	hash		Input hash.
 * \param[in]	metaData	Metadata field.
 * \param[in]	level		The level of the tree node.
 * \param[out]	node		Pointer to the receiving ponter.
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 * \note Exactly one of \c hash or \c metaData must be a not NULL pointer.
 * \note The function will not take ownership of the \c hash or \c metaData fields and thus
 * the pointers must be freed by the caller.
 */
int KSI_TreeNode_new(KSI_CTX *ctx, KSI_DataHash *hash, KSI_MetaData *metaData, int level, KSI_TreeNode **node);

/**
 * Destructor method for #KSI_TreeNode.
 * \param[in]	node		Pointer to the object.
 */
void KSI_TreeNode_free(KSI_TreeNode *node);

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
 * \param[in]	builder 	The builder.
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
