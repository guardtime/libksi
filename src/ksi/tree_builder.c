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

struct KSI_TreeNode_st {
	KSI_CTX *ctx;
	size_t ref;
	KSI_DataHash *hash;
	unsigned level;
	KSI_TreeNode *parent;
	KSI_TreeNode *leftChild;
	KSI_TreeNode *rightChild;
};

void KSI_TreeNode_free(KSI_TreeNode *node) {
	if (node != NULL && --node->ref == 0) {
		KSI_DataHash_free(node->hash);
		KSI_TreeNode_free(node->leftChild);
		KSI_TreeNode_free(node->rightChild);
		KSI_free(node);
	}
}

int KSI_TreeNode_new(KSI_CTX *ctx, KSI_DataHash *hash, unsigned level, KSI_TreeNode **node) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *tmp = NULL;

	if (ctx == NULL || hash == NULL || level > 255 || node == NULL) {
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

static int joinHashes(KSI_CTX *ctx, KSI_HashAlgorithm algo, KSI_DataHash *left, KSI_DataHash *right, unsigned level, KSI_DataHash **root) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *tmp = NULL;
	unsigned char l;

	if (left == NULL || right == NULL || level > 255 || root == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	l = (unsigned char) level;

	res = KSI_DataHasher_open(ctx, algo, &hsr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_addImprint(hsr, left);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_addImprint(hsr, right);
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

int KSI_TreeNode_join(KSI_CTX *ctx, KSI_HashAlgorithm algo, KSI_TreeNode *leftSibling, KSI_TreeNode *rightSibling, KSI_TreeNode **root) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *tmp = NULL;
	unsigned level;
	KSI_DataHash *hsh = NULL;

	if (ctx == NULL || leftSibling == NULL || rightSibling == NULL || root == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ctx);

	level = (leftSibling->level > rightSibling->level ? leftSibling->level : rightSibling->level) + 1;

	if (level > 255) {
		KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Tree too large");
		goto cleanup;
	}

	/* Create the root hash value. */
	res = joinHashes(ctx, algo, leftSibling->hash, rightSibling->hash, level, &hsh);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Create a new tree node. */
	res = KSI_TreeNode_new(ctx, hsh, level, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Update references. */
	KSI_TreeNode_free(leftSibling->parent);
	leftSibling->parent = KSI_TreeNode_ref(tmp);

	KSI_TreeNode_free(rightSibling->parent);
	rightSibling->parent = KSI_TreeNode_ref(tmp);

	tmp->leftChild = KSI_TreeNode_ref(leftSibling);
	tmp->rightChild = KSI_TreeNode_ref(rightSibling);

	*root = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TreeNode_free(tmp);

	return res;
}

KSI_IMPLEMENT_REF(KSI_TreeNode);

KSI_IMPLEMENT_LIST(KSI_TreeNode, KSI_TreeNode_free);

/**/

struct KSI_TreeLeaf_st {
	KSI_CTX *ctx;
	/* TODO! */
};

void KSI_TreeLeaf_free(KSI_TreeLeaf *leaf) {
	if (leaf != NULL) {
		KSI_free(leaf);
	}
}

/**/
struct KSI_TreeBuilder_st {
	KSI_CTX *ctx;
	KSI_HashAlgorithm algo;
	KSI_LIST(KSI_TreeNode) *stack;
};

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
	if (builder != NULL) {
		KSI_TreeNodeList_free(builder->stack);
		KSI_free(builder);
	}
}

int growStack(KSI_TreeBuilder *builder, unsigned level) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	if (builder == NULL || level > 255) {
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


int KSI_TreeBuilder_addLeaf(KSI_TreeBuilder *builder, KSI_DataHash *hsh, unsigned level, KSI_TreeLeaf **leaf) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TreeNode *node = NULL;

	if (builder == NULL || hsh == NULL || level > 255) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TreeNode_new(builder->ctx, hsh, level, &node);
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}

	res = insertNode(builder, node);
	if (res != KSI_OK) {
		KSI_pushError(builder->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_TreeNode_free(node);

	return res;
}
