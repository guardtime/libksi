#include <string.h>

#include "ksi_internal.h"
#include "ksi_hashchain.h"

static int highBit(unsigned int n) {
    n |= (n >>  1);
    n |= (n >>  2);
    n |= (n >>  4);
    n |= (n >>  8);
    n |= (n >> 16);
    return n - (n >> 1);
}

void KSI_HashNode_free(KSI_HashNode *node) {
	if (node != NULL) {
		KSI_DataHash_free(node->hash);
		KSI_HashNode_free(node->leftChild);
		KSI_HashNode_free(node->rightChild);
		KSI_free(node);
	}
}
int KSI_HashNode_new(KSI_CTX *ctx, KSI_DataHash *hash, int level, KSI_HashNode **node) {
	KSI_ERR err;
	KSI_HashNode *nd = NULL;

	KSI_BEGIN(ctx, &err);

	nd = KSI_new(KSI_HashNode);
	if (nd == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	nd->ctx = ctx;
	nd->hash = hash;
	nd->leftChild = NULL;
	nd->rightChild = NULL;
	nd->parent = NULL;
	nd->level = level;

	*node = nd;
	nd = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_HashNode_free(nd);

	return KSI_RETURN(&err);
}

int KSI_HashNode_fromImprint(KSI_CTX *ctx, unsigned char *imprint, int imprint_length, int level, KSI_HashNode **node) {
	KSI_ERR err;
	KSI_DataHash *hsh = NULL;
	KSI_HashNode *nd = NULL;

	int res;

	KSI_BEGIN(ctx, &err);

	res = KSI_DataHash_fromImprint(ctx, imprint, imprint_length, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashNode_new(ctx, hsh, level, &nd);
	KSI_CATCH(&err, res) goto cleanup;

	*node = nd;
	nd = NULL;

cleanup:

	KSI_HashNode_free(nd);

	return KSI_RETURN(&err);
}

int KSI_HashNode_join(KSI_HashNode *left, KSI_HashNode *right, int hash_id, KSI_HashNode **root) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_HashNode *hn = NULL;
	unsigned char buf[0xffff];
	int len = 0;
	int tmp_len;
	int res;
	int level;

	KSI_PRE(&err, left != NULL && right != NULL) goto cleanup;
	KSI_BEGIN(left != NULL ? left->ctx : right->ctx, &err);

	ctx = left->ctx;

	/* Append the imprints from left and right sibling. */
	KSI_DataHash_getImprint_ex(left->hash, buf + len, sizeof(buf) - len, &tmp_len);
	len += tmp_len;

	KSI_DataHash_getImprint_ex(right->hash, buf + len, sizeof(buf) - len, &tmp_len);
	len += tmp_len;

	/* Take the maximum level of the siblings and increase by one. */
	level = (left->level > right->level ? left->level : right->level) + 1;

	/* At this point the height is limited to a single byte. If this changes, the following contition
	 * and assignment have to be changed. */
	if (level > 0xff) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Tree hight exceeds 0xff.");
		goto cleanup;
	}

	/* Add the level as the last byte. */
	buf[len++] = level;

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "HashNode_join", buf, len);

	/* Create the hash for the new root. */
	res = KSI_DataHash_create(ctx, buf, len, hash_id, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	/* Create new hash node. */
	res = KSI_HashNode_new(ctx, hsh, level, &hn);
	KSI_CATCH(&err, res) goto cleanup;

	hn->leftChild = left;
	left->parent = hn;

	hn->rightChild = right;
	right->parent = hn;

	*root = hn;
	hn = NULL;
	hsh = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(hsh);
	KSI_HashNode_free(hn);

	return KSI_RETURN(&err);
}

int KSI_HashNode_buildCalendar(KSI_CTX *ctx, KSI_DataHash *sibling, int isLeft, KSI_HashNode **root) {
	KSI_ERR err;
	int res;

	KSI_DataHash *hsh = NULL;
	KSI_HashNode *hn = NULL;

	unsigned char buf[0xffff];
	int buf_len = 0;

	unsigned char *sibling_digest = NULL;
	int sibling_digestLen = 0;
	int sibling_hashId = 0;

	unsigned char *root_digest = NULL;
	int root_digestLen = 0;
	int root_hashId = 0;

	KSI_PRE(&err, sibling != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (*root == NULL) {
		res = KSI_DataHash_clone(sibling, &hsh);
		KSI_CATCH(&err, res) goto cleanup;
	} else {
		res = KSI_DataHash_getData(sibling, &sibling_hashId, &sibling_digest, &sibling_digestLen);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_DataHash_getData((*root)->hash, &root_hashId, &root_digest, &root_digestLen);
		KSI_CATCH(&err, res) goto cleanup;

		if (isLeft) {
			memcpy(buf + buf_len, root_digest, root_digestLen);
			buf_len += root_digestLen;

			memcpy(buf + buf_len, sibling_digest, sibling_digestLen);
			buf_len += sibling_digestLen;
		} else {
			memcpy(buf + buf_len, sibling_digest, sibling_digestLen);
			buf_len += sibling_digestLen;

			memcpy(buf + buf_len, root_digest, root_digestLen);
			buf_len += root_digestLen;
		}

		buf[buf_len++] = 0xff;

		KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "HashNode_buildCalendar", buf, buf_len);

		/* Create the hash for the new root. */
		res = KSI_DataHash_create(ctx, buf, buf_len, sibling_hashId, &hsh);
		KSI_CATCH(&err, res) goto cleanup;

	}
	res = KSI_HashNode_new(ctx, hsh, 0, &hn);
	KSI_CATCH(&err, res) goto cleanup;

	if (*root != NULL) {
		(*root)->parent = hn;
		if (isLeft) {
			hn->rightChild = *root;
		} else {
			hn->leftChild = *root;
		}
	}

	*root = hn;
	hn = NULL;
	hsh = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(sibling_digest);
	KSI_free(root_digest);

	KSI_DataHash_free(hsh);
	KSI_HashNode_free(hn);

	return KSI_RETURN(&err);
}

int KSI_HashNode_getCalendarAggregationTime(KSI_HashNode *cal, uint32_t aggr_time, uint32_t *utc_time) {
	KSI_ERR err;
	uint32_t r = aggr_time;
	uint32_t t = 0;
	KSI_HashNode *hn = NULL;

	KSI_PRE(&err, cal != NULL) goto cleanup;
	KSI_BEGIN(cal->ctx, &err);

	hn = cal;
	while(hn != NULL && (hn->leftChild != NULL || hn->rightChild != NULL)) {
		if (hn->leftChild != NULL) {
			r = highBit(r) - 1;
			hn = hn->leftChild;
		} else {
			t += highBit(r);
			r -= highBit(r);
			hn = hn->rightChild;
		}
	}

	if (r != 0) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	*utc_time = t;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(hn);

	return KSI_RETURN(&err);
}

int KSI_HashNode_getDataHash(KSI_HashNode *node, KSI_DataHash **hash) {
	KSI_ERR err;
	int res;
	KSI_DataHash *hsh = NULL;

	KSI_PRE(&err, node != NULL) goto cleanup;

	KSI_BEGIN(node->ctx, &err);

	res = KSI_DataHash_clone(node->hash, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	*hash = hsh;
	hsh = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(hsh);

	return KSI_RETURN(&err);
}

int KSI_HashNode_getImprint(KSI_HashNode *node, unsigned char **imprint, int *imprint_length) {
	return KSI_DataHash_getImprint(node->hash, imprint, imprint_length);
}

