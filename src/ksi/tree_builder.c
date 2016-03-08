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

#include "internal.h"
#include "tree_builder.h"

#define IS_VALID_LEVEL(level) (((level) >= 0) && ((level) < 0xff))

typedef struct KSI_TreeNode_st KSI_TreeNode;
KSI_DEFINE_LIST(KSI_TreeNode);

struct KSI_TreeNode_st {
	KSI_CTX *ctx;
	size_t ref;
	KSI_DataHash *hash;
	KSI_MetaData *metaData;
	unsigned level;
	KSI_TreeNode *parent;
	KSI_TreeNode *leftChild;
	KSI_TreeNode *rightChild;
};


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
	KSI_LIST(KSI_TreeNode) *stack;
};

struct KSI_TreeLeafHandle_st {
	size_t ref;
	KSI_TreeBuilder *builder;
	KSI_TreeNode *leafNode;
};

static KSI_IMPLEMENT_REF(KSI_TreeBuilder);
static KSI_DEFINE_REF(KSI_TreeBuilder);

static void KSI_TreeNode_free(KSI_TreeNode *node);
static int KSI_TreeNode_join(KSI_CTX *ctx, KSI_HashAlgorithm algo, KSI_TreeNode *leftSibling, KSI_TreeNode *rightSibling, KSI_TreeNode **root);

KSI_DEFINE_REF(KSI_TreeNode);

static void KSI_TreeNode_free(KSI_TreeNode *node) {
	if (node != NULL && --node->ref == 0) {
		KSI_DataHash_free(node->hash);
		KSI_MetaData_free(node->metaData);
		KSI_TreeNode_free(node->leftChild);
		KSI_TreeNode_free(node->rightChild);
		KSI_free(node);
	}
}

static int KSI_TreeNode_new(KSI_CTX *ctx, KSI_DataHash *hash, KSI_MetaData *metaData, int level, KSI_TreeNode **node) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *tmp = NULL;

	if (ctx == NULL || (hash == NULL && metaData == NULL) || (hash != NULL && metaData != NULL) || !IS_VALID_LEVEL(level) || node == NULL) {
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
	tmp->ref = 1;
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
	KSI_OctetString *raw = NULL;

	if (hsr == NULL || node == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (node->hash != NULL) {
		res = KSI_DataHasher_addImprint(hsr, node->hash);
		if (res != KSI_OK) goto cleanup;
	} else if (node->metaData != NULL) {
		const unsigned char *ptr;
		size_t len;

		res = KSI_MetaData_getRaw(node->metaData, &raw);
		if (res != KSI_OK) goto cleanup;

		res = KSI_OctetString_extract(raw, &ptr, &len);
		if (res != KSI_OK) goto cleanup;

		res = KSI_DataHasher_add(hsr, ptr, len);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_OctetString_free(raw);

	return res;
}

static int joinHashes(KSI_CTX *ctx, KSI_HashAlgorithm algo, KSI_TreeNode *left, KSI_TreeNode *right, int level, KSI_DataHash **root) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *tmp = NULL;
	unsigned char l;

	if (left == NULL || right == NULL || !IS_VALID_LEVEL(level) || root == NULL) {
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

	KSI_ERR_clearErrors(ctx);

	level = (leftSibling->level > rightSibling->level ? leftSibling->level : rightSibling->level) + 1;

	/* Sanity check. */
	if (!IS_VALID_LEVEL(level)) {
		KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Tree too large");
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

	tmp->leftChild = KSI_TreeNode_ref(leftSibling);
	tmp->rightChild = KSI_TreeNode_ref(rightSibling);

	*root = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(hsh);
	KSI_TreeNode_free(tmp);

	return res;
}

KSI_IMPLEMENT_REF(KSI_TreeNode);

KSI_IMPLEMENT_LIST(KSI_TreeNode, KSI_TreeNode_free);

/**/

int KSI_TreeBuilder_new(KSI_CTX *ctx, KSI_HashAlgorithm algo, KSI_TreeBuilder **builder) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeBuilder *tmp = NULL;

	if (ctx == NULL || builder == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	tmp = KSI_new(KSI_TreeBuilder);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;
	tmp->rootNode = NULL;
	tmp->algo = algo;
	tmp->stack = NULL;

	res = KSI_TreeNodeList_new(&tmp->stack);
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
		KSI_TreeNode_free(builder->rootNode);
		KSI_TreeNodeList_free(builder->stack);
		KSI_free(builder);
	}
}

int growStack(KSI_TreeBuilder *builder, int level) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	if (builder == NULL || !IS_VALID_LEVEL(level)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	for (i = KSI_TreeNodeList_length(builder->stack); i <= level; i++) {
		res = KSI_TreeNodeList_append(builder->stack, NULL);
		if (res != KSI_OK) goto cleanup;
	}

	/* Just make sure the stack is actually the required size. */
	if (KSI_TreeNodeList_length(builder->stack) < level) {
		res = KSI_UNKNOWN_ERROR;
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int insertNode(KSI_TreeBuilder *builder, KSI_TreeNode *node) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *pSlot = NULL;
	KSI_TreeNode *root = NULL;

	if (builder == NULL || node == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Make sure the stack is big enough. */
	res = growStack(builder, node->level);
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}

	/* Get the current value from the stack. */
	res = KSI_TreeNodeList_elementAt(builder->stack, node->level, &pSlot);
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}

	if (pSlot == NULL) {
		/* The slot is empty - reuse the slot. */
		res = KSI_TreeNodeList_replaceAt(builder->stack, node->level, KSI_TreeNode_ref(node));
		if (res != KSI_OK) {
			KSI_pushError(builder->ctx, res, NULL);
			goto cleanup;
		}
	} else {
		/* The slot is taken - create a new node from the existing ones. */
		res = KSI_TreeNode_join(builder->ctx, builder->algo, pSlot, node, &root);
		if (res != KSI_OK) {
			KSI_pushError(builder->ctx, res, NULL);
			goto cleanup;
		}

		/* Remove the existing element. */
		res = KSI_TreeNodeList_replaceAt(builder->stack, node->level, NULL);
		if (res != KSI_OK) {
			KSI_pushError(builder->ctx, res, NULL);
			goto cleanup;
		}

		res = insertNode(builder, root);
		if (res != KSI_OK) {
			KSI_pushError(builder->ctx, res, NULL);
			goto cleanup;
		}
	}

cleanup:

	KSI_TreeNode_free(root);

	return res;
}

static int addLeaf(KSI_TreeBuilder *builder, KSI_DataHash *hsh, KSI_MetaData *metaData, int level, KSI_TreeLeafHandle **leaf) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *node = NULL;
	KSI_TreeLeafHandle *tmp = NULL;

	if (builder == NULL || (hsh == NULL && metaData == NULL) || (hsh != NULL && metaData != NULL) || !IS_VALID_LEVEL(level)) {
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
	res = insertNode(builder, node);
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

		tmp->builder = KSI_TreeBuilder_ref(builder);
		tmp->leafNode = KSI_TreeNode_ref(node);
		tmp->ref = 1;

		*leaf = tmp;
		tmp = NULL;
	}

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

struct KSI_TreeNodeFinalize_st {
	KSI_TreeBuilder *builder;
	KSI_TreeNode *root;
};

static int finalizeTree(KSI_TreeNode *node, void *foldCtx) {
	int res = KSI_UNKNOWN_ERROR;
	struct KSI_TreeNodeFinalize_st *c = foldCtx;
	KSI_TreeNode *root = NULL;

	if (c == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (node != NULL) {
		if (c->root == NULL) {
			root = KSI_TreeNode_ref(node);
		} else {
			res = KSI_TreeNode_join(c->builder->ctx, c->builder->algo, node, c->root, &root);
			if (res != KSI_OK) {
				KSI_pushError(c->builder->ctx, res, NULL);
				goto cleanup;
			}
		}

		KSI_TreeNode_free(c->root);
		c->root = root;
		root = NULL;
	}

	res = KSI_OK;

cleanup:

	KSI_TreeNode_free(root);

	return res;
}

int KSI_TreeBuilder_close(KSI_TreeBuilder *builder) {
	int res = KSI_UNKNOWN_ERROR;
	struct KSI_TreeNodeFinalize_st foldCtx;

	if  (builder == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(builder->ctx);

	/* Make sure the builder is in a correct state. */
	if (builder->rootNode) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The tree has been finished, new leafs may not be added.");
		goto cleanup;
	}

	foldCtx.builder = builder;
	foldCtx.root = NULL;

	/* Finalize the forest of complete binary trees into a single tree. */
	res = KSI_TreeNodeList_foldl(builder->stack, &foldCtx, finalizeTree);
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}

	if (foldCtx.root == NULL) {
		KSI_pushError(builder->ctx, res = KSI_INVALID_STATE, "The tree has no leafs.");
		goto cleanup;
	}

	builder->rootNode = foldCtx.root;
	foldCtx.root = NULL;

	res = KSI_OK;

cleanup:

	KSI_TreeNode_free(foldCtx.root);

	return res;
}

void KSI_TreeLeafHandle_free(KSI_TreeLeafHandle *handle) {
	if (handle != NULL && --handle->ref == 0) {
		KSI_TreeBuilder_free(handle->builder);
		KSI_TreeNode_free(handle->leafNode);
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
		res = KSI_HashChainLink_setImprint(link, KSI_DataHash_ref(pSibling->hash));
		if (res != KSI_OK) goto cleanup;

		/* Add the meta-data. */
		res = KSI_HashChainLink_setMetaData(link, KSI_MetaData_ref(pSibling->metaData));
		if (res != KSI_OK) goto cleanup;

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
	res = KSI_AggregationHashChain_new(handle->builder->ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(handle->builder->ctx, res, NULL);
		goto cleanup;
	}

	/* Create new list. */
	res = KSI_HashChainLinkList_new(&links);
	if (res != KSI_OK) {
		KSI_pushError(handle->builder->ctx, res, NULL);
		goto cleanup;
	}

	/* Extract the hash chain links. */
	res = getHashChainLinks(handle->leafNode, links);
	if (res != KSI_OK) {
		KSI_pushError(handle->builder->ctx, res, NULL);
		goto cleanup;
	}

	/* Set the hash chain links to the container. */
	res = KSI_AggregationHashChain_setChain(tmp, links);
	if (res != KSI_OK) {
		KSI_pushError(handle->builder->ctx, res, NULL);
		goto cleanup;
	}

	/* Set the input hash. */
	res = KSI_AggregationHashChain_setInputHash(tmp, KSI_DataHash_ref(handle->leafNode->hash));
	if (res != KSI_OK) {
		KSI_pushError(handle->builder->ctx, res, NULL);
		goto cleanup;
	}

	/* Set the aggregation algorithm. */
	res = KSI_Integer_new(handle->builder->ctx, handle->builder->algo, &algoId);
	if (res != KSI_OK) {
		KSI_pushError(handle->builder->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_AggregationHashChain_setAggrHashId(tmp, algoId);
	if (res != KSI_OK) {
		KSI_pushError(handle->builder->ctx, res, NULL);
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

