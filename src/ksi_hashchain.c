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

struct KSI_HashChain_st {
	KSI_CTX *ctx;

	KSI_DataHash *hash;
	KSI_MetaHash *metaHash;
	KSI_MetaData *metaData;

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

static int addChainImprint(KSI_DataHasher *hsr, KSI_HashChain *chain) {
	KSI_ERR err;
	int res;
	int mode = 0;
	const unsigned char *imprint;
	int imprint_len;

	KSI_PRE(&err, hsr != NULL) goto cleanup;
	KSI_PRE(&err, chain != NULL) goto cleanup;
	KSI_BEGIN(chain->ctx, &err);

	if (chain->hash != NULL) mode |= 0x01;
	if (chain->metaHash != NULL) mode |= 0x02;
	if (chain->metaData != NULL) mode |= 0x04;

	switch(mode) {
		case 0x01:
			res = KSI_DataHash_getImprint(chain->hash, &imprint, &imprint_len);
			KSI_CATCH(&err, res) goto cleanup;
			break;
		case 0x02:
			res = KSI_MetaHash_getRaw(chain->metaHash, &imprint, &imprint_len);
			KSI_CATCH(&err, res) goto cleanup;
			break;
		case 0x04:
			res = KSI_MetaData_getRaw(chain->metaData, &imprint, &imprint_len);
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

static int aggregateChain(KSI_HashChain *chain, KSI_DataHash *inputHash, int startLevel, int hash_id, int isCalendar, int *endLevel, KSI_DataHash **outputHash) {
	KSI_ERR err;
	int res;
	int tmp_len;
	int level = startLevel;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_HashChain *ch = chain;
	int algo_id = hash_id;
	char chr_level;
	char logMsg[0xff];

	KSI_PRE(&err, chain != NULL) goto cleanup;
	KSI_PRE(&err, inputHash != NULL) goto cleanup;
	KSI_PRE(&err, outputHash != NULL) goto cleanup;
	KSI_BEGIN(chain->ctx, &err);

	sprintf(logMsg, "Starting %s hash chain aggregation with input  hash", isCalendar ? "calendar": "aggregation");
	KSI_LOG_logDataHash(chain->ctx, KSI_LOG_DEBUG, logMsg, inputHash);

	while (ch != NULL) {
		if(!isCalendar) {
			level += ch->levelCorrection + 1;
		} else {
			res = KSI_DataHash_getData(ch->hash, &algo_id, NULL, NULL);
			KSI_CATCH(&err, res) goto cleanup;
		}

		/* Create or reset the hasher. */
		if (hsr == NULL) {
			res = KSI_DataHasher_open(ch->ctx, algo_id, &hsr);
		} else {
			KSI_DataHasher_reset(hsr);
		}

		if (ch->isLeft) {
			res = addNvlImprint(hsh, inputHash, hsr,  &tmp_len);
			KSI_CATCH(&err, res) goto cleanup;

			res = addChainImprint(hsr, ch);
			KSI_CATCH(&err, res) goto cleanup;
		} else {
			res = addChainImprint(hsr, ch);
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

		ch = ch->next;

	}


	if (endLevel != NULL) *endLevel = level;
	*outputHash = hsh;
	hsh = NULL;

	sprintf(logMsg, "Finished %s hash chain aggregation with output hash", isCalendar ? "calendar": "aggregation");
	KSI_LOG_logDataHash(chain->ctx, KSI_LOG_DEBUG, logMsg, *outputHash);

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHasher_free(hsr);
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
	nd->metaData = NULL;
	nd->metaHash = NULL;

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
int KSI_HashChain_getCalendarAggregationTime(KSI_HashChain *cal, KSI_Integer *aggr_time, uint32_t *utc_time) {
	KSI_ERR err;
	KSI_uint64_t r;
	uint32_t t = 0;
	KSI_HashChain *hn = NULL;

	KSI_PRE(&err, cal != NULL) goto cleanup;
	KSI_PRE(&err, aggr_time != NULL) goto cleanup;
	KSI_BEGIN(cal->ctx, &err);

	r = KSI_Integer_getUInt64(aggr_time);


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
void KSI_MetaHash_free(KSI_MetaHash *mhs) {
	if (mhs != NULL) {
		KSI_free(mhs->data);
		KSI_nofree(mhs->str);

		KSI_free(mhs);
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

int KSI_MetaHash_getRaw(KSI_MetaHash *mth, const unsigned char **data, int *data_len) {
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
int KSI_HashChain_aggregate(KSI_HashChain *chain, KSI_DataHash *inputHash, int startLevel, int hash_id, int *endLevel, KSI_DataHash **outputHash) {
	return aggregateChain(chain, inputHash, startLevel, hash_id, 0, endLevel, outputHash);
}

/**
 *
 */
int KSI_HashChain_aggregateCalendar(KSI_HashChain *chain, KSI_DataHash *inputHash, KSI_DataHash **outputHash) {
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

	KSI_TLV_PARSE_RAW_BEGIN(mtd->ctx, mtd->data, mtd->data_length)
		KSI_PARSE_TLV_ELEMENT_UTF8STR(0x01, &cId)
		KSI_PARSE_TLV_ELEMENT_INTEGER(0x02, &mId)
		KSI_PARSE_TLV_ELEMENT_INTEGER(0x03, &sNr)
		KSI_PARSE_TLV_ELEMENT_UNKNONW_NON_CRITICAL_IGNORE
	KSI_TLV_PARSE_RAW_END(res, NULL);
	KSI_CATCH(&err, res) goto cleanup;

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

int KSI_MetaData_getRaw(KSI_MetaData *mtd, const unsigned char **data, int *data_len) {
	KSI_ERR err;
	KSI_PRE(&err, mtd != NULL) goto cleanup;

	*data = mtd->data;
	*data_len = mtd->data_length;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}
