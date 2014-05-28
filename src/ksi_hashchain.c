#include <string.h>

#include "ksi_tlv_easy.h"
#include "ksi_internal.h"

static int highBit(unsigned int n) {
    n |= (n >>  1);
    n |= (n >>  2);
    n |= (n >>  4);
    n |= (n >>  8);
    n |= (n >> 16);
    return n - (n >> 1);
}

static int addNvlImprint(KSI_DataHash *first, KSI_DataHash *second, KSI_DataHasher *hsr) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = first;
	const unsigned char *imprint;
	int imprint_len;

	if (hsh == NULL) {
		if (second == NULL) {
			res = KSI_INVALID_ARGUMENT;
			goto cleanup;
		}
		hsh = second;
	}

	res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHasher_add(hsr, imprint, imprint_len);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	KSI_nofree(imprint);

	return res;
}

static int addChainImprint(KSI_DataHasher *hsr, KSI_HashChainLink *link) {
	KSI_ERR err;
	KSI_CTX *ctx;
	int res;
	int mode = 0;
	const unsigned char *imprint;
	int imprint_len;
	KSI_MetaData *metaData = NULL;
	KSI_DataHash *metaHash = NULL;
	KSI_DataHash *hash = NULL;
	KSI_OctetString *tmpOctStr = NULL;

	KSI_PRE(&err, hsr != NULL) goto cleanup;
	KSI_PRE(&err, link != NULL) goto cleanup;

	ctx = KSI_DataHasher_getCtx(hsr);
	KSI_BEGIN(ctx, &err);

	res = KSI_HashChainLink_getImprint(link, &hash);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChainLink_getMetaData(link, &metaData);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChainLink_getMetaHash(link, &metaHash);


	if (hash != NULL) mode |= 0x01;
	if (metaHash != NULL) mode |= 0x02;
	if (metaData != NULL) mode |= 0x04;

	switch(mode) {
		case 0x01:
			res = KSI_DataHash_getImprint(hash, &imprint, &imprint_len);
			KSI_CATCH(&err, res) goto cleanup;
			break;
		case 0x02:
			res = KSI_DataHash_getImprint(metaHash, &imprint, &imprint_len);
			KSI_CATCH(&err, res) goto cleanup;
			break;
		case 0x04:
			res = KSI_MetaData_getRaw(metaData, &tmpOctStr);
			KSI_CATCH(&err, res) goto cleanup;

			res = KSI_OctetString_extract(tmpOctStr, &imprint, &imprint_len);
			KSI_CATCH(&err, res) goto cleanup;
			break;
		default:
			KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
			goto cleanup;
	}

	res = KSI_DataHasher_add(hsr, imprint, imprint_len);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(hash);
	KSI_nofree(metaHash);
	KSI_nofree(metaData);
	KSI_nofree(imprint);
	KSI_nofree(tmpOctStr);

	return KSI_RETURN(&err);
}

static int aggregateChain(KSI_LIST(KSI_HashChainLink) *chain, KSI_DataHash *inputHash, int startLevel, int hash_id, int isCalendar, int *endLevel, KSI_DataHash **outputHash) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	int level = startLevel;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_HashChainLink *link = NULL;
	int algo_id = hash_id;
	char chr_level;
	char logMsg[0xff];
	int i;

	/* Extracted data. */
	int levelCorrection;
	int isLeft;
	KSI_DataHash *linkHsh = NULL;

	KSI_PRE(&err, chain != NULL) goto cleanup;
	KSI_PRE(&err, inputHash != NULL) goto cleanup;
	KSI_PRE(&err, outputHash != NULL) goto cleanup;

	ctx = KSI_DataHash_getCtx(inputHash);
	KSI_BEGIN(ctx, &err);

	sprintf(logMsg, "Starting %s hash chain aggregation with input  hash", isCalendar ? "calendar": "aggregation");
	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, logMsg, inputHash);

	for (i = 0; i < KSI_HashChainLinkList_length(chain); i++) {
		res = KSI_HashChainLinkList_elementAt(chain, i, &link);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_HashChainLink_getLevelCorrection(link, &levelCorrection);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_HashChainLink_getImprint(link, &linkHsh);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_HashChainLink_getIsLeft(link, &isLeft);
		KSI_CATCH(&err, res) goto cleanup;

		if(!isCalendar) {
			level += levelCorrection + 1;
		} else {
			res = KSI_DataHash_getData(linkHsh, &algo_id, NULL, NULL);
			KSI_CATCH(&err, res) goto cleanup;
		}

		/* Create or reset the hasher. */
		if (hsr == NULL) {
			res = KSI_DataHasher_open(ctx, algo_id, &hsr);
		} else {
			KSI_DataHasher_reset(hsr);
		}

		if (isLeft) {
			res = addNvlImprint(hsh, inputHash, hsr);
			KSI_CATCH(&err, res) goto cleanup;

			res = addChainImprint(hsr, link);
			KSI_CATCH(&err, res) goto cleanup;
		} else {
			res = addChainImprint(hsr, link);
			KSI_CATCH(&err, res) goto cleanup;

			res = addNvlImprint(hsh, inputHash, hsr);
			KSI_CATCH(&err, res) goto cleanup;
		}


		if (level > 0xff) {
			KSI_FAIL(&err, KSI_INVALID_FORMAT, "Aggregation chain length exceeds 0xff");
			goto cleanup;
		}

		chr_level = (char) level;
		KSI_DataHasher_add(hsr, &chr_level, 1);

		if (hsh != NULL) KSI_DataHash_free(hsh);

		res = KSI_DataHasher_close(hsr, &hsh);
		KSI_CATCH(&err, res) goto cleanup;
	}


	if (endLevel != NULL) *endLevel = level;
	*outputHash = hsh;
	hsh = NULL;

	sprintf(logMsg, "Finished %s hash chain aggregation with output hash", isCalendar ? "calendar": "aggregation");
	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, logMsg, *outputHash);

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hsh);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_HashChain_appendLink(KSI_CTX *ctx, KSI_DataHash *siblingHash, KSI_DataHash *metaHash, KSI_MetaData *metaData, int isLeft, unsigned int levelCorrection, KSI_LIST(KSI_HashChainLink) **chain) {
	KSI_ERR err;
	KSI_HashChainLink *link = NULL;
	int res;
	KSI_LIST(KSI_HashChainLink) *tmp = NULL;
	int mode = 0;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, chain != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	/* Create new link. */
	res = KSI_HashChainLink_new(ctx, &link);
	KSI_CATCH(&err, res) goto cleanup;

	/* Is the siblin right of left. */
	res = KSI_HashChainLink_setIsLeft(link, isLeft);
	KSI_CATCH(&err, res) goto cleanup;

	/* Chain link level correction. */
	res = KSI_HashChainLink_setLevelCorrection(link, levelCorrection);
	KSI_CATCH(&err, res) goto cleanup;

	if (siblingHash != NULL) mode |= 0x01;
	if (metaHash != NULL) mode |= 0x02;
	if (metaData != NULL) mode |= 0x04;

	switch (mode) {
		case 0x01:
			res = KSI_HashChainLink_setImprint(link, siblingHash);
			KSI_CATCH(&err, res) goto cleanup;
			break;
		case 0x02:
			res = KSI_HashChainLink_setMetaHash(link, metaHash);
			KSI_CATCH(&err, res) goto cleanup;
			break;
		case 0x04:
			res = KSI_HashChainLink_setMetaData(link, metaData);
			KSI_CATCH(&err, res) goto cleanup;
			break;
		default:
			KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Not implemented");
			goto cleanup;
	}

	tmp = *chain;

	if (tmp == NULL) {
		res = KSI_HashChainLinkList_new(ctx, &tmp);
		KSI_CATCH(&err, res) goto cleanup;
	}

	res = KSI_HashChainLinkList_append(tmp, link);
	KSI_CATCH(&err, res) goto cleanup;
	link = NULL;

	*chain = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_HashChainLinkList_free(tmp);
	KSI_HashChainLink_free(link);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_HashChain_getCalendarAggregationTime(const KSI_LIST(KSI_HashChainLink) *chain, const KSI_Integer *aggr_time, uint32_t *utc_time) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_uint64_t r;
	uint32_t t = 0;
	KSI_HashChainLink *hn = NULL;
	int i;
	int isLeft;

	if (chain == NULL || aggr_time == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	r = KSI_Integer_getUInt64(aggr_time);

	/* Traverse the list from the end to the beginning. */
	for (i = KSI_HashChainLinkList_length(chain) - 1; i >= 0; i--) {
		if (r <= 0) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}
		res = KSI_HashChainLinkList_elementAt(chain, i, &hn);
		if (res != KSI_OK) goto cleanup;

		res = KSI_HashChainLink_getIsLeft(hn, &isLeft);
		if (res != KSI_OK) goto cleanup;

		if (isLeft) {
			r = highBit(r) - 1;
		} else {
			t += highBit(r);
			r -= highBit(r);
		}
	}

	if (r != 0) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	*utc_time = t;

	res = KSI_OK;

cleanup:

	KSI_nofree(hn);

	return res;
}

/**
 *
 */
int KSI_HashChain_aggregate(KSI_LIST(KSI_HashChainLink) *chain, KSI_DataHash *inputHash, int startLevel, int hash_id, int *endLevel, KSI_DataHash **outputHash) {
	return aggregateChain(chain, inputHash, startLevel, hash_id, 0, endLevel, outputHash);
}

/**
 *
 */
int KSI_HashChain_aggregateCalendar(KSI_LIST(KSI_HashChainLink) *chain, KSI_DataHash *inputHash, KSI_DataHash **outputHash) {
	return aggregateChain(chain, inputHash, 0xff, -1, 1, NULL, outputHash);
}
