#include <string.h>

#include "ksi_internal.h"

struct KSI_HashChain_st {
	KSI_CTX *ctx;
	KSI_DataHash *hash;
	unsigned int levelCorrection;
	int isLeft;

	KSI_HashChain *last;
	KSI_HashChain *prev;
	KSI_HashChain *next;
};

static int highBit(unsigned int n) {
    n |= (n >>  1);
    n |= (n >>  2);
    n |= (n >>  4);
    n |= (n >>  8);
    n |= (n >> 16);
    return n - (n >> 1);
}

static int addNvlImprint(KSI_DataHash *first, KSI_DataHash *second, unsigned char *buf, int buf_size, int *buf_len) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = first;

	if (hsh == NULL) {
		if (second == NULL) {
			res = KSI_INVALID_ARGUMENT;
			goto cleanup;
		}
		hsh = second;
	}

	res = KSI_DataHash_getImprint_ex(hsh, buf, buf_size, buf_len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static int aggregateChain(KSI_HashChain *chain, KSI_DataHash *inputHash, int startLevel, int hash_id, int isCalendar, KSI_DataHash **outputHash) {
	KSI_ERR err;
	int res;
	int tmp_len;
	int level = startLevel;
	unsigned char buf[0xffff];
	int len = 0;
	KSI_DataHash *hsh = NULL;

	KSI_PRE(&err, chain != NULL) goto cleanup;
	KSI_PRE(&err, inputHash != NULL) goto cleanup;
	KSI_PRE(&err, outputHash != NULL) goto cleanup;
	KSI_BEGIN(chain->ctx, &err);

	res = KSI_DataHash_getImprint_ex(inputHash, buf, sizeof(buf), &len);
	KSI_CATCH(&err, res) goto cleanup;

	while (chain != NULL) {
		len = 0;
		if (chain->isLeft) {
			res = addNvlImprint(hsh, inputHash, buf + len, sizeof(buf) - len,  &tmp_len);
			KSI_CATCH(&err, res) goto cleanup;

			len += tmp_len;
			res = KSI_DataHash_getImprint_ex(chain->hash, buf + len, sizeof(buf) - len, &tmp_len);
		} else {
			res = KSI_DataHash_getImprint_ex(chain->hash, buf + len, sizeof(buf) - len, &tmp_len);
			KSI_CATCH(&err, res) goto cleanup;

			len += tmp_len;

			res = addNvlImprint(hsh, inputHash, buf + len, sizeof(buf) - len, &tmp_len);
		}
		KSI_CATCH(&err, res) goto cleanup;
		len += tmp_len;

		if(!isCalendar) {
			level += chain->levelCorrection + 1;
		}

		if (level > 0xff) {
			KSI_FAIL(&err, KSI_INVALID_FORMAT, "Aggregation chain length exceeds 0xff");
			goto cleanup;
		}

		buf[len++] = (char)(level & 0xff);

		if (hsh != NULL) KSI_DataHash_free(hsh);

		res = KSI_DataHash_create(chain->ctx, buf, len, hash_id, &hsh);
		KSI_CATCH(&err, res) goto cleanup;

		chain = chain->next;
	}

	*outputHash = hsh;
	hsh = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(hsh);

	return KSI_RETURN(&err);
}

/**
 *
 */
void KSI_HashChain_free(KSI_HashChain *node) {
	while (node != NULL) {
		KSI_HashChain *tmp = node->next;

		KSI_DataHash_free(node->hash);
		KSI_free(node);

		node = tmp;
	}
}

/**
 *
 */
int KSI_HashChain_new(KSI_CTX *ctx, KSI_DataHash *hash, unsigned int levelCorrection, int isLeft, KSI_HashChain **node) {
	KSI_ERR err;
	KSI_HashChain *nd = NULL;

	KSI_BEGIN(ctx, &err);

	nd = KSI_new(KSI_HashChain);
	if (nd == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	nd->ctx = ctx;
	nd->hash = hash;
	nd->next = NULL;
	nd->last = nd;
	nd->levelCorrection = levelCorrection;
	nd->isLeft = isLeft;

	*node = nd;
	nd = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_HashChain_free(nd);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_HashChain_fromImprint(KSI_CTX *ctx, unsigned char *imprint, int imprint_length, unsigned int levelCorrection, int isLeft, KSI_HashChain **node) {
	KSI_ERR err;
	KSI_DataHash *hsh = NULL;
	KSI_HashChain *nd = NULL;

	int res;

	KSI_BEGIN(ctx, &err);

	res = KSI_DataHash_fromImprint(ctx, imprint, imprint_length, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChain_new(ctx, hsh, levelCorrection, isLeft, &nd);
	KSI_CATCH(&err, res) goto cleanup;

	*node = nd;
	nd = NULL;

cleanup:

	KSI_HashChain_free(nd);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_HashChain_appendLink(KSI_CTX *ctx, KSI_DataHash *siblingHash, int isLeft, unsigned int levelCorrection, KSI_HashChain **root) {
	KSI_ERR err;
	KSI_HashChain *chainLink = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_HashChain_new(ctx, siblingHash, levelCorrection, isLeft, &chainLink);
	KSI_CATCH(&err, res) goto cleanup;

	if (*root == NULL) {
		*root = chainLink;
	} else {
		(*root)->last->next = chainLink;
		chainLink->prev = (*root)->last;
	}

	(*root)->last = chainLink;
	chainLink = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_HashChain_free(chainLink);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_HashChain_getCalendarAggregationTime(KSI_HashChain *cal, uint32_t aggr_time, uint32_t *utc_time) {
	KSI_ERR err;
	long long r = aggr_time;
	uint32_t t = 0;
	KSI_HashChain *hn = NULL;

	KSI_PRE(&err, cal != NULL) goto cleanup;
	KSI_BEGIN(cal->ctx, &err);

	hn = cal->last;
	while(hn != NULL) {
		if (r <= 0) {
			KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
			goto cleanup;
		}
		if (hn->isLeft) {
			r = highBit(r) - 1;
		} else {
			t += highBit(r);
			r -= highBit(r);
		}
		hn = hn->prev;
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

/**
 *
 */
int KSI_HashChain_aggregate(KSI_HashChain *chain, KSI_DataHash *inputHash, int startLevel, int hash_id, KSI_DataHash **outputHash) {
	return aggregateChain(chain, inputHash, startLevel, hash_id, 0, outputHash);
}

/**
 *
 */
int KSI_HashChain_aggregateCalendar(KSI_HashChain *chain, KSI_DataHash *inputHash, int hash_id, KSI_DataHash **outputHash) {
	return aggregateChain(chain, inputHash, 0xff, hash_id, 1, outputHash);
}
