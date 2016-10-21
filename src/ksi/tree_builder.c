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

#include <string.h>

#include "internal.h"
#include "tree_builder.h"
#include "hashchain.h"
#include "impl/meta_data_impl.h"

KSI_IMPLEMENT_LIST(KSI_TreeBuilderLeafProcessor, NULL);

struct KSI_TreeLeafHandle_st {
	size_t ref;
	KSI_TreeBuilder *pBuilder;
	KSI_TreeNode *leafNode;
};

KSI_IMPLEMENT_REF(KSI_TreeLeafHandle);

KSI_IMPLEMENT_LIST(KSI_TreeLeafHandle, KSI_TreeLeafHandle_free);

static int KSI_TreeNode_join(KSI_CTX *ctx, KSI_HashAlgorithm algo, KSI_TreeNode *leftSibling, KSI_TreeNode *rightSibling, KSI_TreeNode **root);

void KSI_TreeNode_free(KSI_TreeNode *node) {
	if (node != NULL ) {
		KSI_DataHash_free(node->hash);
		KSI_MetaData_free(node->metaData);
		KSI_TreeNode_free(node->leftChild);
		KSI_TreeNode_free(node->rightChild);
		KSI_free(node);
	}
}


int KSI_TreeNode_new(KSI_CTX *ctx, KSI_DataHash *hash, KSI_MetaData *metaData, int level, KSI_TreeNode **node) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *tmp = NULL;

	if (ctx == NULL || (hash == NULL && metaData == NULL) || (hash != NULL && metaData != NULL) || !KSI_IS_VALID_TREE_LEVEL(level) || node == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	tmp = KSI_new(KSI_TreeNode);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->hash = KSI_DataHash_ref(hash);
	tmp->metaData = KSI_MetaData_ref(metaData);
	tmp->level = level;
	tmp->parent = NULL;
	tmp->leftChild = NULL;
	tmp->rightChild = NULL;

	*node = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:

	KSI_TreeNode_free(tmp);

	return res;
}

static int KSI_DataHasher_addTreeNode(KSI_DataHasher *hsr, KSI_TreeNode *node) {
	int res = KSI_UNKNOWN_ERROR;

	if (hsr == NULL || node == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (node->hash != NULL) {
		res = KSI_DataHasher_addImprint(hsr, node->hash);
		if (res != KSI_OK) goto cleanup;
	} else if (node->metaData != NULL) {
		unsigned char buf[0xffff + 4];
		size_t len;

		res = node->metaData->serializePayload(node->metaData, buf, sizeof(buf), &len);
		if (res != KSI_OK) goto cleanup;

		res = KSI_DataHasher_add(hsr, buf, len);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int joinHashes(KSI_CTX *ctx, KSI_HashAlgorithm algo, KSI_TreeNode *left, KSI_TreeNode *right, int level, KSI_DataHash **root) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *tmp = NULL;
	unsigned char l;

	if (left == NULL || right == NULL || !KSI_IS_VALID_TREE_LEVEL(level) || root == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	l = (unsigned char) level;

	res = KSI_DataHasher_open(ctx, algo, &hsr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_addTreeNode(hsr, left);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_addTreeNode(hsr, right);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_add(hsr, &l, 1);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_close(hsr, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*root = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(tmp);

	return res;
}

static int KSI_TreeNode_join(KSI_CTX *ctx, KSI_HashAlgorithm algo, KSI_TreeNode *leftSibling, KSI_TreeNode *rightSibling, KSI_TreeNode **root) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *tmp = NULL;
	int level;
	KSI_DataHash *hsh = NULL;

	if (ctx == NULL || leftSibling == NULL || rightSibling == NULL || root == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (!KSI_IS_VALID_TREE_LEVEL(leftSibling->level) || !KSI_IS_VALID_TREE_LEVEL(rightSibling->level)) {
		KSI_pushError(ctx, res = KSI_INVALID_STATE, "One of the subtrees has an invalid level.");
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	level = (leftSibling->level > rightSibling->level ? leftSibling->level : rightSibling->level) + 1;

	/* Sanity check. */
	if (!KSI_IS_VALID_TREE_LEVEL(level)) {
		KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Tree too large.");
		goto cleanup;
	}

	/* Create the root hash value. */
	res = joinHashes(ctx, algo, leftSibling, rightSibling, level, &hsh);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Create a new tree node. */
	res = KSI_TreeNode_new(ctx, hsh, NULL, level, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Update references. */
	leftSibling->parent = tmp;
	rightSibling->parent = tmp;

	tmp->leftChild = leftSibling;
	tmp->rightChild = rightSibling;

	*root = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(hsh);
	KSI_TreeNode_free(tmp);

	return res;
}

/**/

int KSI_TreeBuilder_new(KSI_CTX *ctx, KSI_HashAlgorithm algo, KSI_TreeBuilder **builder) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeBuilder *tmp = NULL;

	if (ctx == NULL || builder == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	if (!KSI_isHashAlgorithmSupported(algo)) {
		KSI_pushError(ctx, res = KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	if (!KSI_isHashAlgorithmTrusted(algo)) {
		KSI_pushError(ctx, res = KSI_UNTRUSTED_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_TreeBuilder);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;
	tmp->rootNode = NULL;
	tmp->algo = algo;
	tmp->cbList = NULL;
	memset(tmp->stack, 0, sizeof(tmp->stack));

	res = KSI_TreeBuilderLeafProcessorList_new(&tmp->cbList);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*builder = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TreeBuilder_free(tmp);

	return res;
}

void KSI_TreeBuilder_free(KSI_TreeBuilder *builder) {
	if (builder != NULL && --builder->ref == 0) {
		size_t i;
		KSI_TreeNode_free(builder->rootNode);

		/* If the tree was not closed propperly, we have to check the stack. */
		for (i = 0; i < KSI_TREE_BUILDER_STACK_LEN; i++) {
			KSI_TreeNode_free(builder->stack[i]);
		}

		KSI_TreeBuilderLeafProcessorList_free(builder->cbList);

		KSI_free(builder);
	}
}

static int insertNode(KSI_TreeBuilder *builder, KSI_TreeNode *node) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *pSlot = NULL;
	KSI_TreeNode *root = NULL;

	if (builder == NULL || node == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (!KSI_IS_VALID_TREE_LEVEL(node->level)) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	/* Get the current value from the stack. */
	pSlot = builder->stack[node->level];

	if (pSlot == NULL) {
		/* The slot is empty - reuse the slot. */
		builder->stack[node->level] = node;
	} else {
		/* The slot is taken - create a new node from the existing ones. */
		res = KSI_TreeNode_join(builder->ctx, builder->algo, pSlot, node, &root);
		if (res != KSI_OK) {
			KSI_pushError(builder->ctx, res, NULL);
			goto cleanup;
		}

		/* Remove the existing element. */
		builder->stack[node->level] = NULL;

		res = insertNode(builder, root);
		if (res != KSI_OK) {
			KSI_pushError(builder->ctx, res, NULL);
			goto cleanup;
		}

		root = NULL;
	}

	res = KSI_OK;

cleanup:

	KSI_TreeNode_free(root);

	return res;
}

static int processAndInsertNode(KSI_TreeBuilder *builder, KSI_TreeNode *node) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *localRoot = NULL;
	KSI_TreeNode *tmp = NULL;
	size_t i;

	if (builder == NULL || node == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	for (i = 0; i < KSI_TreeBuilderLeafProcessorList_length(builder->cbList); i++) {
		KSI_TreeBuilderLeafProcessor *cb = NULL;

		tmp = NULL;

		res = KSI_TreeBuilderLeafProcessorList_elementAt(builder->cbList, i, &cb);
		if (res != KSI_OK || cb == NULL) {
			if (res == KSI_OK) res = KSI_INVALID_STATE;
			goto cleanup;
		}

		if (cb->fn == NULL) {
			res = KSI_INVALID_STATE;
			goto cleanup;
		}

		res = cb->fn((localRoot == NULL ? node : localRoot), cb->c, &tmp);
		if (res != KSI_OK) goto cleanup;

		if (tmp != NULL) {
			res = KSI_TreeNode_join(builder->ctx, builder->algo, localRoot == NULL ? node : localRoot, tmp, &localRoot);
			if (res != KSI_OK) goto cleanup;
		}
	}

	res = insertNode(builder, localRoot == NULL ? node : localRoot);
	if (res != KSI_OK) goto cleanup;

	tmp = NULL;

cleanup:

	KSI_TreeNode_free(tmp);

	return res;
}

static int addLeaf(KSI_TreeBuilder *builder, KSI_DataHash *hsh, KSI_MetaData *metaData, int level, KSI_TreeLeafHandle **leaf) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *node = NULL;
	KSI_TreeLeafHandle *tmp = NULL;

	if (builder == NULL || (hsh == NULL && metaData == NULL) || (hsh != NULL && metaData != NULL) || !KSI_IS_VALID_TREE_LEVEL(level)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(builder->ctx);

	/* Make sure the builder is in a correct state. */
	if (builder->rootNode != NULL) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The tree has been finished, new leafs may not be added.");
		goto cleanup;
	}

	/* Create new leaf node. */
	res = KSI_TreeNode_new(builder->ctx, hsh, metaData, level, &node);
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}

	/* Insert the leaf. */
	res = processAndInsertNode(builder, node);
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}

	if (leaf != NULL) {
		tmp = KSI_new(KSI_TreeLeafHandle);
		if (tmp == NULL) {
			KSI_pushError(builder->ctx, res = KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}

		tmp->pBuilder = builder;
		tmp->leafNode = node;
		tmp->ref = 1;

		*leaf = tmp;
		tmp = NULL;
	}

	node = NULL;

	res = KSI_OK;

cleanup:

	KSI_TreeLeafHandle_free(tmp);
	KSI_TreeNode_free(node);

	return res;
}

int KSI_TreeBuilder_addDataHash(KSI_TreeBuilder *builder, KSI_DataHash *hsh, int level, KSI_TreeLeafHandle **leaf) {
	return addLeaf(builder, hsh,  NULL, level, leaf);
}

int KSI_TreeBuilder_addMetaData(KSI_TreeBuilder *builder, KSI_MetaData *metaData, int level, KSI_TreeLeafHandle **leaf) {
	return addLeaf(builder, NULL, metaData, level, leaf);
}

int KSI_TreeBuilder_close(KSI_TreeBuilder *builder) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *root = NULL;
	KSI_TreeNode *tmp = NULL;

	size_t i;

	if  (builder == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(builder->ctx);

	if (builder->rootNode == NULL) {
		/* Finalize the forest of complete binary trees into a single tree. */
		for (i = 0; i < KSI_TREE_BUILDER_STACK_LEN; i++) {
			KSI_TreeNode *node = builder->stack[i];
			builder->stack[i] = NULL;

			if (node == NULL) continue;

			if (root == NULL) {
				root = node;
			} else {
				res = KSI_TreeNode_join(builder->ctx, builder->algo, node, root, &tmp);
				if (res != KSI_OK) goto cleanup;

				root = tmp;
				tmp = NULL;
			}
		}
	}

	/* Check if all is well. */
	if (root == NULL) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The tree has no leafs.");
		goto cleanup;
	}

	builder->rootNode = root;

	res = KSI_OK;

cleanup:

	KSI_TreeNode_free(tmp);

	return res;
}

void KSI_TreeLeafHandle_free(KSI_TreeLeafHandle *handle) {
	if (handle != NULL && --handle->ref == 0) {
		KSI_free(handle);
	}
}

static int getHashChainLinks(KSI_TreeNode *node, KSI_LIST(KSI_HashChainLink) *links) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HashChainLink *link = NULL;
	bool isLeft;
	unsigned levelGap = 0;
	KSI_Integer *levelCorrection = NULL;
	KSI_TreeNode *pSibling = NULL;
	KSI_MetaDataElement *mdEl = NULL;

	if (node == NULL || links == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (node->parent != NULL) {

		res = KSI_HashChainLink_new(node->ctx, &link);
		if (res != KSI_OK) goto cleanup;


		if (node->parent->leftChild == node) {
			isLeft = true;
		} else if (node->parent->rightChild == node) {
			isLeft = false;
		} else {
			/* Just in case there is a mess with the tree. */
			res = KSI_INVALID_STATE;
			goto cleanup;
		}

		res = KSI_HashChainLink_setIsLeft(link, isLeft);
		if (res != KSI_OK) goto cleanup;

		if (isLeft) {
			if (node->parent->rightChild == NULL) {
				res = KSI_INVALID_STATE;
				goto cleanup;
			}
			pSibling = node->parent->rightChild;
		} else {
			if (node->parent->leftChild == NULL) {
				res = KSI_INVALID_STATE;
				goto cleanup;
			}
			pSibling = node->parent->leftChild;
		}

		/* Sanity check. */
		if ((pSibling->hash == NULL && pSibling->metaData == NULL) || (pSibling->hash != NULL && pSibling->metaData != NULL)) {
			res = KSI_INVALID_STATE;
			goto cleanup;
		}

		/* Add the hash value. */
		{
			KSI_DataHash *ref = NULL;

			res = KSI_HashChainLink_setImprint(link, ref = KSI_DataHash_ref(pSibling->hash));
			if (res != KSI_OK) {
				/* Cleanup the reference. */
				KSI_DataHash_free(ref);

				goto cleanup;
			}
		}

		/* Add the meta-data. */
		if (pSibling->metaData != NULL) {
			KSI_MetaDataElement *ref = NULL;

			/* Convert the element to the internal representation. */
			res = pSibling->metaData->toMetaDataElement(pSibling->metaData, &mdEl);
			if (res != KSI_OK) goto cleanup;

			res = KSI_HashChainLink_setMetaData(link, ref = KSI_MetaDataElement_ref(mdEl));
			if (res != KSI_OK) {
				/* Cleanup the reference. */
				KSI_MetaDataElement_free(ref);

				goto cleanup;
			}
		}

		/* Sanity check. */
		if (node->parent->level <= node->level) {
			res = KSI_INVALID_STATE;
			goto cleanup;
		}

		/* Calculate the level correction. */
		levelGap = node->parent->level - node->level - 1;

		if (levelGap > 0) {
			res = KSI_Integer_new(node->ctx, levelGap, &levelCorrection);
			if (res != KSI_OK) goto cleanup;

			res = KSI_HashChainLink_setLevelCorrection(link, levelCorrection);
			if (res != KSI_OK) goto cleanup;

			levelCorrection = NULL;
		}

		res = KSI_HashChainLinkList_append(links, link);
		if (res != KSI_OK) goto cleanup;
		link = NULL;

		res = getHashChainLinks(node->parent, links);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_MetaDataElement_free(mdEl);
	KSI_Integer_free(levelCorrection);

	KSI_HashChainLink_free(link);

	return res;
}


int KSI_TreeLeafHandle_getAggregationChain(KSI_TreeLeafHandle *handle, KSI_AggregationHashChain **chain) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationHashChain *tmp = NULL;
	KSI_LIST(KSI_HashChainLink) *links = NULL;
	KSI_Integer *algoId = NULL;

	if (handle == NULL || chain == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Create new object. */
	res = KSI_AggregationHashChain_new(handle->pBuilder->ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(handle->pBuilder->ctx, res, NULL);
		goto cleanup;
	}

	/* Create new list. */
	res = KSI_HashChainLinkList_new(&links);
	if (res != KSI_OK) {
		KSI_pushError(handle->pBuilder->ctx, res, NULL);
		goto cleanup;
	}

	/* Extract the hash chain links. */
	res = getHashChainLinks(handle->leafNode, links);
	if (res != KSI_OK) {
		KSI_pushError(handle->pBuilder->ctx, res, NULL);
		goto cleanup;
	}

	/* Set the hash chain links to the container. */
	res = KSI_AggregationHashChain_setChain(tmp, links);
	if (res != KSI_OK) {
		KSI_pushError(handle->pBuilder->ctx, res, NULL);
		goto cleanup;
	}

	/* Set the input hash. */
	{
		KSI_DataHash *ref = NULL;

		res = KSI_AggregationHashChain_setInputHash(tmp, ref = KSI_DataHash_ref(handle->leafNode->hash));
		if (res != KSI_OK) {
			/* Cleanup the reference. */
			KSI_DataHash_free(ref);

			KSI_pushError(handle->pBuilder->ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Set the aggregation algorithm. */
	res = KSI_Integer_new(handle->pBuilder->ctx, handle->pBuilder->algo, &algoId);
	if (res != KSI_OK) {
		KSI_pushError(handle->pBuilder->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationHashChain_setAggrHashId(tmp, algoId);
	if (res != KSI_OK) {
		KSI_pushError(handle->pBuilder->ctx, res, NULL);
		goto cleanup;
	}
	algoId = NULL;

	*chain = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Integer_free(algoId);
	KSI_AggregationHashChain_free(tmp);

	return res;
}

