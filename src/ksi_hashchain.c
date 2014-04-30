#include <string.h>

#include "ksi_tlv_easy.h"
#include "ksi_internal.h"

struct KSI_HashChain_MetaHash_st {
	KSI_CTX *ctx;
	unsigned char *data;
	int data_length;
};


struct KSI_HashChain_MetaData_st {
	KSI_CTX *ctx;
	unsigned char *raw;
	int raw_length;
	char *clientId;
	KSI_Integer *machineId;
	KSI_Integer *sequenceNr;
};

static int highBit(unsigned int n) {
    n |= (n >>  1);
    n |= (n >>  2);
    n |= (n >>  4);
    n |= (n >>  8);
    n |= (n >> 16);
    return n - (n >> 1);
}

static int addNvlImprint(KSI_DataHash *first, KSI_DataHash *second, KSI_DataHasher *hsr, int *buf_len) {
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
	const KSI_MetaData *metaData = NULL;
	const KSI_MetaHash *metaHash = NULL;
	const KSI_DataHash *hash = NULL;

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
			res = KSI_MetaHash_getRaw(metaHash, &imprint, &imprint_len);
			KSI_CATCH(&err, res) goto cleanup;
			break;
		case 0x04:
			res = KSI_MetaData_getRaw(metaData, &imprint, &imprint_len);
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

	return KSI_RETURN(&err);
}

static int aggregateChain(KSI_LIST(KSI_HashChainLink) *chain, KSI_DataHash *inputHash, int startLevel, int hash_id, int isCalendar, int *endLevel, KSI_DataHash **outputHash) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	int tmp_len;
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
	const KSI_DataHash *linkHsh = NULL;

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
			res = addNvlImprint(hsh, inputHash, hsr,  &tmp_len);
			KSI_CATCH(&err, res) goto cleanup;

			res = addChainImprint(hsr, link);
			KSI_CATCH(&err, res) goto cleanup;
		} else {
			res = addChainImprint(hsr, link);
			KSI_CATCH(&err, res) goto cleanup;

			res = addNvlImprint(hsh, inputHash, hsr, &tmp_len);
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
int KSI_HashChain_new(KSI_CTX *ctx, KSI_DataHash *hash, unsigned int levelCorrection, int isLeft, KSI_HashChainLink **node) {
	KSI_ERR err;
	int res;
	KSI_HashChainLink *tmp = NULL;

	KSI_BEGIN(ctx, &err);

	res = KSI_HashChainLink_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChainLink_setIsLeft(tmp, isLeft);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChainLink_setLevelCorrection(tmp, levelCorrection);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChainLink_setImprint(tmp, hash);
	KSI_CATCH(&err, res) goto cleanup;

	*node = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_HashChainLink_free(tmp);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_HashChain_appendLink(KSI_CTX *ctx, KSI_DataHash *siblingHash, int isLeft, unsigned int levelCorrection, KSI_LIST(KSI_HashChainLink) **chain) {
	KSI_ERR err;
	KSI_HashChainLink *chainLink = NULL;
	int res;
	KSI_LIST(KSI_HashChainLink) *tmp = NULL;


	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, chain != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_HashChain_new(ctx, siblingHash, levelCorrection, isLeft, &chainLink);
	KSI_CATCH(&err, res) goto cleanup;

	tmp = *chain;

	if (tmp == NULL) {
		res = KSI_HashChainLinkList_new(ctx, &tmp);
		KSI_CATCH(&err, res) goto cleanup;
	}

	res = KSI_HashChainLinkList_append(tmp, chainLink);
	KSI_CATCH(&err, res) goto cleanup;
	chainLink = NULL;

	*chain = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_HashChainLinkList_free(tmp);
	KSI_HashChainLink_free(chainLink);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_HashChain_getCalendarAggregationTime(KSI_LIST(KSI_HashChainLink) *chain, KSI_Integer *aggr_time, uint32_t *utc_time) {
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
void KSI_MetaHash_free(KSI_MetaHash *mhs) {
	if (mhs != NULL) {
		KSI_free(mhs->data);
		KSI_nofree(mhs->str);

		KSI_free(mhs);
	}
}

void KSI_MetaData_free(KSI_MetaData *p) {
	if (p != NULL) {
		KSI_free(p->clientId);
		KSI_free(p->raw);
		KSI_Integer_free(p->machineId);
		KSI_Integer_free(p->sequenceNr);
		KSI_free(p);
	}
}


/**
 *
 */
int KSI_MetaHash_create(KSI_CTX *ctx, unsigned char *data, int data_length, KSI_MetaHash **mth) {
	KSI_ERR err;
	KSI_MetaHash *tmp = NULL;
	int payload_len;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, data != NULL) goto cleanup;
	KSI_PRE(&err, data_length >= 3) goto cleanup;
	KSI_BEGIN(ctx, &err);

	/* Validate the internal structure, first two bytes represent the length. */
	payload_len = data[1] << 8 | data[2];
	if (payload_len + 2 != data_length) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Not a meta hash");
		goto cleanup;
	}

	tmp = KSI_new(KSI_MetaHash);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->data = NULL;

	if (data == NULL) {
		tmp->data_length = 0;
	} else {
		tmp->data = KSI_calloc(data_length + 1, 1);
		if (tmp->data == NULL) {
			KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
			goto cleanup;
		}
		memcpy(tmp->data, data, data_length);
		tmp->data_length = data_length;
	}

	/* Set extra byte to zero for easy return of UTF-8 string. */
	tmp->data[data_length] = '\0';

	*mth = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_MetaHash_free(tmp);

	return KSI_RETURN(&err);

}

/**
 *
 */
int KSI_MetaHash_getUtf8Value(KSI_MetaHash *mth, const char **value) {
	KSI_ERR err;
	KSI_PRE(&err, mth != NULL) goto cleanup;

	KSI_BEGIN(mth->ctx, &err);

	*value = (char *)mth->data + 2;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_MetaHash_getHashId(KSI_MetaHash *mth, int *hash_id) {
	KSI_ERR err;
	KSI_PRE(&err, mth != NULL) goto cleanup;

	*hash_id = (char) mth->data[0];

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_MetaHash_getRaw(const KSI_MetaHash *mth, const unsigned char **data, int *data_len) {
	KSI_ERR err;
	KSI_PRE(&err, mth != NULL) goto cleanup;

	*data = mth->data;
	*data_len = mth->data_length;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
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

int KSI_MetaData_parse(KSI_MetaData *mtd, char **clientId, KSI_Integer **machineId, KSI_Integer **sequenceNr) {
	KSI_ERR err;
	int res;

	char *cId = NULL;
	KSI_Integer *mId = NULL;
	KSI_Integer *sNr = NULL;

	KSI_PRE(&err, mtd != NULL) goto cleanup;
	KSI_BEGIN(mtd->ctx, &err);
// FIXME!
/*	KSI_TLV_PARSE_RAW_BEGIN(mtd->ctx, mtd->data, mtd->data_length)
		KSI_PARSE_TLV_ELEMENT_UTF8STR(0x01, &cId)
		KSI_PARSE_TLV_ELEMENT_INTEGER(0x02, &mId)
		KSI_PARSE_TLV_ELEMENT_INTEGER(0x03, &sNr)
		KSI_PARSE_TLV_ELEMENT_UNKNONW_NON_CRITICAL_IGNORE
	KSI_TLV_PARSE_RAW_END(res, NULL);
	KSI_CATCH(&err, res) goto cleanup;
*/
	if (clientId != NULL) {
		*clientId = cId;
		cId = NULL;
	}

	if (machineId != NULL) {
		*machineId = mId;
		mId = NULL;
	}

	if (sequenceNr != NULL) {
		*sequenceNr = sNr;
		sNr = NULL;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(cId);
	KSI_free(mId);
	KSI_free(sNr);

	return KSI_RETURN(&err);
}

int KSI_MetaData_getRaw(const KSI_MetaData *mtd, const unsigned char **data, int *data_len) {
	KSI_ERR err;
	KSI_PRE(&err, mtd != NULL) goto cleanup;
// FIXME
/*	*data = mtd->data;
	*data_len = mtd->data_length;
*/
	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}
