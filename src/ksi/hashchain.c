#include <string.h>

#include "internal.h"

KSI_IMPORT_TLV_TEMPLATE(KSI_HashChainLink)

struct KSI_HashChainLink_st {
	KSI_CTX *ctx;
	int isLeft;
	KSI_Integer *levelCorrection;
	KSI_DataHash *metaHash;
	KSI_MetaData *metaData;
	KSI_DataHash *imprint;
};

struct KSI_CalendarHashChain_st {
	KSI_CTX *ctx;
	KSI_Integer *publicationTime;
	KSI_Integer *aggregationTime;
	KSI_DataHash *inputHash;
	KSI_LIST(KSI_HashChainLink) *hashChain;
};

KSI_IMPLEMENT_LIST(KSI_HashChainLink, KSI_HashChainLink_free);
KSI_IMPLEMENT_LIST(KSI_CalendarHashChainLink, KSI_HashChainLink_free);
KSI_IMPLEMENT_LIST(KSI_CalendarHashChain, KSI_CalendarHashChain_free);

static long long int highBit(long long int n) {
    n |= (n >>  1);
    n |= (n >>  2);
    n |= (n >>  4);
    n |= (n >>  8);
    n |= (n >> 16);
    n |= (n >> 32);
    return n - (n >> 1);
}


static int addNvlImprint(const KSI_DataHash *first, const KSI_DataHash *second, KSI_DataHasher *hsr) {
	int res = KSI_UNKNOWN_ERROR;
	const KSI_DataHash *hsh = first;
	const unsigned char *imprint = NULL;
	unsigned int imprint_len;

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

static int addChainImprint(KSI_CTX *ctx, KSI_DataHasher *hsr, KSI_HashChainLink *link) {
	KSI_ERR err;
	int res;
	int mode = 0;
	const unsigned char *imprint = NULL;
	unsigned int imprint_len;
	KSI_MetaData *metaData = NULL;
	KSI_DataHash *metaHash = NULL;
	KSI_DataHash *hash = NULL;
	KSI_OctetString *tmpOctStr = NULL;

	KSI_PRE(&err, hsr != NULL) goto cleanup;
	KSI_PRE(&err, link != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_HashChainLink_getImprint(link, &hash);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChainLink_getMetaData(link, &metaData);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChainLink_getMetaHash(link, &metaHash);
	KSI_CATCH(&err, res) goto cleanup;

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

static int aggregateChain(KSI_LIST(KSI_HashChainLink) *chain, const KSI_DataHash *inputHash, int startLevel, int hash_id, int isCalendar, int *endLevel, KSI_DataHash **outputHash) {
	KSI_ERR err;
	int res;
	int level = startLevel;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_HashChainLink *link = NULL;
	int algo_id = hash_id;
	char chr_level;
	char logMsg[0xff];
	size_t i;

	/* Extracted data. */
	int levelCorrection;

	KSI_PRE(&err, chain != NULL) goto cleanup;
	KSI_PRE(&err, inputHash != NULL) goto cleanup;
	KSI_PRE(&err, outputHash != NULL) goto cleanup;

	KSI_BEGIN(chain->ctx, &err);

	sprintf(logMsg, "Starting %s hash chain aggregation with input  hash", isCalendar ? "calendar": "aggregation");
	KSI_LOG_logDataHash(chain->ctx, KSI_LOG_DEBUG, logMsg, inputHash);

	for (i = 0; i < KSI_HashChainLinkList_length(chain); i++) {
		res = KSI_HashChainLinkList_elementAt(chain, i, &link);
		KSI_CATCH(&err, res) goto cleanup;

		levelCorrection = KSI_Integer_getUInt64(link->levelCorrection);

		if(!isCalendar) {
			level += levelCorrection + 1;
		} else {
			res = KSI_DataHash_extract(link->imprint, &algo_id, NULL, NULL);
			KSI_CATCH(&err, res) goto cleanup;
		}

		/* Create or reset the hasher. */
		if (hsr == NULL) {
			res = KSI_DataHasher_open(chain->ctx, algo_id, &hsr);
		} else {
			res = KSI_DataHasher_reset(hsr);
		}
		KSI_CATCH(&err, res) goto cleanup;

		if (link->isLeft) {
			res = addNvlImprint(hsh, inputHash, hsr);
			KSI_CATCH(&err, res) goto cleanup;

			res = addChainImprint(chain->ctx, hsr, link);
			KSI_CATCH(&err, res) goto cleanup;
		} else {
			res = addChainImprint(chain->ctx, hsr, link);
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

		if (hsh != NULL) {
			res = KSI_DataHasher_close_ex(hsr, hsh);
		} else {
			res = KSI_DataHasher_close(hsr, &hsh);
		}
		KSI_CATCH(&err, res) goto cleanup;
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
static int calculateCalendarAggregationTime(const KSI_LIST(KSI_HashChainLink) *chain, const KSI_Integer *pub_time, time_t *utc_time) {
	int res = KSI_UNKNOWN_ERROR;
	long long int r;
	long long int t = 0;
	KSI_HashChainLink *hn = NULL;
	size_t i;
	int isLeft;

	if (chain == NULL || pub_time == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (KSI_HashChainLinkList_length(chain) == 0) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	r = (time_t) KSI_Integer_getUInt64(pub_time);

	/* Traverse the list from the end to the beginning. */
	for (i = 0; i < KSI_HashChainLinkList_length(chain); i++) {
		if (r <= 0) {
			res = KSI_INVALID_FORMAT;
			goto cleanup;
		}
		res = KSI_HashChainLinkList_elementAt(chain, KSI_HashChainLinkList_length(chain) - i - 1, &hn);
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

	*utc_time = (time_t) t;

	res = KSI_OK;

cleanup:

	KSI_nofree(hn);

	return res;
}

/**
 *
 */
int KSI_HashChain_aggregate(KSI_LIST(KSI_HashChainLink) *chain, const KSI_DataHash *inputHash, int startLevel, int hash_id, int *endLevel, KSI_DataHash **outputHash) {
	return aggregateChain(chain, inputHash, startLevel, hash_id, 0, endLevel, outputHash);
}

/**
 *
 */
int KSI_HashChain_aggregateCalendar(KSI_LIST(KSI_HashChainLink) *chain, const KSI_DataHash *inputHash, KSI_DataHash **outputHash) {
	return aggregateChain(chain, inputHash, 0xff, -1, 1, NULL, outputHash);
}

/**
 * KSI_CalendarHashChain
 */
void KSI_CalendarHashChain_free(KSI_CalendarHashChain *t) {
	if(t != NULL) {
		KSI_Integer_free(t->publicationTime);
		KSI_Integer_free(t->aggregationTime);
		KSI_DataHash_free(t->inputHash);
		KSI_HashChainLinkList_freeAll(t->hashChain);
		KSI_free(t);
	}
}

int KSI_CalendarHashChain_new(KSI_CTX *ctx, KSI_CalendarHashChain **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CalendarHashChain *tmp = NULL;
	tmp = KSI_new(KSI_CalendarHashChain);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->publicationTime = NULL;
	tmp->aggregationTime = NULL;
	tmp->inputHash = NULL;
	tmp->hashChain = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_CalendarHashChain_free(tmp);
	return res;
}

int KSI_CalendarHashChain_aggregate(KSI_CalendarHashChain *chain, KSI_DataHash **hsh) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, chain != NULL) goto cleanup;
	KSI_PRE(&err, hsh != NULL) goto cleanup;
	KSI_BEGIN(chain->ctx, &err);

	res = KSI_HashChain_aggregateCalendar(chain->hashChain, chain->inputHash, hsh);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_CalendarHashChain_calculateAggregationTime(KSI_CalendarHashChain *chain, time_t *aggrTime) {
	KSI_ERR err;
	int res;
	KSI_PRE(&err, chain != NULL) goto cleanup;
	KSI_PRE(&err, aggrTime != NULL) goto cleanup;
	KSI_BEGIN(chain->ctx, &err);

	res = calculateCalendarAggregationTime(chain->hashChain, chain->publicationTime, aggrTime);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);

}

KSI_IMPLEMENT_GETTER(KSI_CalendarHashChain, KSI_Integer*, publicationTime, PublicationTime);
KSI_IMPLEMENT_GETTER(KSI_CalendarHashChain, KSI_Integer*, aggregationTime, AggregationTime);
KSI_IMPLEMENT_GETTER(KSI_CalendarHashChain, KSI_DataHash*, inputHash, InputHash);
KSI_IMPLEMENT_GETTER(KSI_CalendarHashChain, KSI_LIST(KSI_HashChainLink)*, hashChain, HashChain);

KSI_IMPLEMENT_SETTER(KSI_CalendarHashChain, KSI_Integer*, publicationTime, PublicationTime);
KSI_IMPLEMENT_SETTER(KSI_CalendarHashChain, KSI_Integer*, aggregationTime, AggregationTime);
KSI_IMPLEMENT_SETTER(KSI_CalendarHashChain, KSI_DataHash*, inputHash, InputHash);
KSI_IMPLEMENT_SETTER(KSI_CalendarHashChain, KSI_LIST(KSI_HashChainLink)*, hashChain, HashChain);

/**
 * KSI_HashChainLink
 */
void KSI_HashChainLink_free(KSI_HashChainLink *t) {
	if(t != NULL) {
		KSI_DataHash_free(t->metaHash);
		KSI_MetaData_free(t->metaData);
		KSI_DataHash_free(t->imprint);
		KSI_Integer_free(t->levelCorrection);
		KSI_free(t);
	}
}

int KSI_HashChainLink_new(KSI_CTX *ctx, KSI_HashChainLink **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HashChainLink *tmp = NULL;
	tmp = KSI_new(KSI_HashChainLink);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->isLeft = 0;
	tmp->levelCorrection = NULL;
	tmp->metaHash = NULL;
	tmp->metaData = NULL;
	tmp->imprint = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_HashChainLink_free(tmp);
	return res;
}


int KSI_CalendarHashChainLink_fromTlv(KSI_TLV *tlv, KSI_CalendarHashChainLink **link) {
	KSI_ERR err;
	int res;
	KSI_HashChainLink *tmp = NULL;
	KSI_DataHash *hsh = NULL;
	int isLeft = 0;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, link != NULL) goto cleanup;
	KSI_BEGIN(KSI_TLV_getCtx(tlv), &err);

	switch(KSI_TLV_getTag(tlv)) {
		case 0x07: isLeft = 1; break;
		case 0x08: isLeft = 0; break;
		default: {
			char errm[0xff];
			snprintf(errm, sizeof(errm), "Unknown tag for hash chain link: 0x%02x", KSI_TLV_getTag(tlv));
			KSI_FAIL(&err, KSI_INVALID_FORMAT, errm);
			goto cleanup;
		}
	}

	res = KSI_HashChainLink_new(KSI_TLV_getCtx(tlv), &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	tmp->isLeft = isLeft;

	res = KSI_DataHash_fromTlv(tlv, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	tmp->imprint = hsh;
	hsh = NULL;

	*link = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_HashChainLink_free(tmp);
	KSI_DataHash_free(hsh);

	return KSI_RETURN(&err);
}


int KSI_CalendarHashChainLink_toTlv(KSI_CTX *ctx, KSI_CalendarHashChainLink *link, unsigned tag, int isNonCritica, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;
	unsigned tagOverride = 0;

	KSI_PRE(&err, link != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (link->isLeft) tagOverride = 0x07;
	else tagOverride = 0x08;

	res = KSI_DataHash_toTlv(ctx, link->imprint, tagOverride, isNonCritica, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_HashChainLink_fromTlv(KSI_TLV *tlv, KSI_HashChainLink **link) {
	KSI_ERR err;
	int res;
	KSI_HashChainLink *tmp = NULL;
	int isLeft = 0;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, link != NULL) goto cleanup;
	KSI_BEGIN(KSI_TLV_getCtx(tlv), &err);

	switch(KSI_TLV_getTag(tlv)) {
		case 0x07: isLeft = 1; break;
		case 0x08: isLeft = 0; break;
		default: {
			char errm[0xff];
			snprintf(errm, sizeof(errm), "Unknown tag for hash chain link: 0x%02x", KSI_TLV_getTag(tlv));
			KSI_FAIL(&err, KSI_INVALID_FORMAT, errm);
			goto cleanup;
		}
	}

	res = KSI_HashChainLink_new(KSI_TLV_getCtx(tlv), &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_extract(KSI_TLV_getCtx(tlv), tmp, tlv, KSI_TLV_TEMPLATE(KSI_HashChainLink));
	KSI_CATCH(&err, res) goto cleanup;

	tmp->isLeft = isLeft;


	*link = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_HashChainLink_free(tmp);

	return KSI_RETURN(&err);
}


int KSI_HashChainLink_toTlv(KSI_CTX *ctx, KSI_HashChainLink *link, unsigned tag, int isNonCritica, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;
	unsigned tagOverride = 0;

	KSI_PRE(&err, link != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (link->isLeft) tagOverride = 0x07;
	else tagOverride = 0x08;

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tagOverride, isNonCritica, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_construct(ctx, tmp, link, KSI_TLV_TEMPLATE(KSI_HashChainLink));
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}


KSI_IMPLEMENT_GETTER(KSI_HashChainLink, int, isLeft, IsLeft);
KSI_IMPLEMENT_GETTER(KSI_HashChainLink, KSI_Integer*, levelCorrection, LevelCorrection);
KSI_IMPLEMENT_GETTER(KSI_HashChainLink, KSI_DataHash*, metaHash, MetaHash);
KSI_IMPLEMENT_GETTER(KSI_HashChainLink, KSI_MetaData*, metaData, MetaData);
KSI_IMPLEMENT_GETTER(KSI_HashChainLink, KSI_DataHash*, imprint, Imprint);

KSI_IMPLEMENT_SETTER(KSI_HashChainLink, int, isLeft, IsLeft);
KSI_IMPLEMENT_SETTER(KSI_HashChainLink, KSI_Integer*, levelCorrection, LevelCorrection);
KSI_IMPLEMENT_SETTER(KSI_HashChainLink, KSI_DataHash*, metaHash, MetaHash);
KSI_IMPLEMENT_SETTER(KSI_HashChainLink, KSI_MetaData*, metaData, MetaData);
KSI_IMPLEMENT_SETTER(KSI_HashChainLink, KSI_DataHash*, imprint, Imprint);

