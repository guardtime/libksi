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
#include <stdio.h>

#include "multi_signature_impl.h"
#include "types.h"
#include "internal.h"
#include "multi_signature.h"
#include "verification_impl.h"
#include "signature_impl.h"
#include "hashchain_impl.h"
#include "publicationsfile_impl.h"
#include "tlv.h"
#include "tlv_template.h"
#include "hashchain.h"
#include "fast_tlv.h"
#include "ctx_impl.h"
#include "net.h"

#define KSI_MULTI_SIGNATURE_HDR (const char *) "MULTISIG"

KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationHashChain);
KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarHashChain);
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationAuthRec);
KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarAuthRec);
KSI_IMPORT_TLV_TEMPLATE(KSI_RFC3161);

typedef struct ParserHelper_st {
	KSI_CTX *ctx;
	const unsigned char *ptr;
	size_t ptr_len;
	KSI_TLV *tlv;
	FILE *file;
	KSI_LIST(KSI_AggregationHashChain) *aggregationChainList;
	KSI_LIST(KSI_CalendarHashChain) *calendarChainList;
	KSI_LIST(KSI_PublicationRecord) *publicationRecordList;
	KSI_LIST(KSI_AggregationAuthRec) *aggregationAuthRecordList;
	KSI_LIST(KSI_CalendarAuthRec) *calendarAuthRecordList;
	KSI_LIST(KSI_RFC3161) *rfc3161List;
} ParserHelper;

static KSI_IMPLEMENT_SETTER(ParserHelper, KSI_LIST(KSI_AggregationHashChain) *, aggregationChainList, AggregationChainList);
static KSI_IMPLEMENT_SETTER(ParserHelper, KSI_LIST(KSI_CalendarHashChain) *, calendarChainList, CalendarChainList);
static KSI_IMPLEMENT_SETTER(ParserHelper, KSI_LIST(KSI_PublicationRecord) *, publicationRecordList, PublicationRecordList);
static KSI_IMPLEMENT_SETTER(ParserHelper, KSI_LIST(KSI_AggregationAuthRec) *, aggregationAuthRecordList, AggregationAuthRecordList);
static KSI_IMPLEMENT_SETTER(ParserHelper, KSI_LIST(KSI_CalendarAuthRec) *, calendarAuthRecordList, CalendarAuthRecordList);
static KSI_IMPLEMENT_SETTER(ParserHelper, KSI_LIST(KSI_RFC3161) *, rfc3161List, Rfc3161List);

static KSI_IMPLEMENT_GETTER(ParserHelper, KSI_LIST(KSI_AggregationHashChain) *, aggregationChainList, AggregationChainList);
static KSI_IMPLEMENT_GETTER(ParserHelper, KSI_LIST(KSI_CalendarHashChain) *, calendarChainList, CalendarChainList);
static KSI_IMPLEMENT_GETTER(ParserHelper, KSI_LIST(KSI_PublicationRecord) *, publicationRecordList, PublicationRecordList);
static KSI_IMPLEMENT_GETTER(ParserHelper, KSI_LIST(KSI_AggregationAuthRec) *, aggregationAuthRecordList, AggregationAuthRecordList);
static KSI_IMPLEMENT_GETTER(ParserHelper, KSI_LIST(KSI_CalendarAuthRec) *, calendarAuthRecordList, CalendarAuthRecordList);
static KSI_IMPLEMENT_GETTER(ParserHelper, KSI_LIST(KSI_RFC3161) *, rfc3161List, Rfc3161List);

KSI_DEFINE_TLV_TEMPLATE(ParserHelper)
	KSI_TLV_COMPOSITE_LIST(0x0801, KSI_TLV_TMPL_FLG_NONE, ParserHelper_getAggregationChainList, ParserHelper_setAggregationChainList, KSI_AggregationHashChain, "aggr_chain")
	KSI_TLV_COMPOSITE_LIST(0x0802, KSI_TLV_TMPL_FLG_NONE, ParserHelper_getCalendarChainList, ParserHelper_setCalendarChainList, KSI_CalendarHashChain, "cal_chain")
	KSI_TLV_COMPOSITE_LIST(0x0803, KSI_TLV_TMPL_FLG_NONE, ParserHelper_getPublicationRecordList, ParserHelper_setPublicationRecordList, KSI_PublicationRecord, "pub_rec")
	KSI_TLV_COMPOSITE_LIST(0x0804, KSI_TLV_TMPL_FLG_NONE, ParserHelper_getAggregationAuthRecordList, ParserHelper_setAggregationAuthRecordList, KSI_AggregationAuthRec, "aggr_auth_rec")
	KSI_TLV_COMPOSITE_LIST(0x0805, KSI_TLV_TMPL_FLG_NONE, ParserHelper_getCalendarAuthRecordList, ParserHelper_setCalendarAuthRecordList, KSI_CalendarAuthRec, "cal_auth_rec")
	KSI_TLV_COMPOSITE_LIST(0x0806, KSI_TLV_TMPL_FLG_NONE, ParserHelper_getRfc3161List, ParserHelper_setRfc3161List, KSI_RFC3161, "rfc3161_rec")
KSI_END_TLV_TEMPLATE

static void ChainIndexMapper_free(ChainIndexMapper *cim) {
	if (cim != NULL) {
		KSI_Integer_free(cim->key_index);
		KSI_AggregationHashChain_free(cim->aggrChain);
		ChainIndexMapperList_free(cim->children);
		KSI_RFC3161_free(cim->rfc3161);
		KSI_free(cim);
	}
}

static int ChainIndexMapper_new(ChainIndexMapper **cim) {
	int res = KSI_UNKNOWN_ERROR;

	ChainIndexMapper *tmp = NULL;
	tmp = KSI_new(ChainIndexMapper);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->aggrChain = NULL;
	tmp->children = NULL;
	tmp->key_index = NULL;
	tmp->rfc3161 = NULL;
	tmp->aggrAuthRec = NULL;

	*cim = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	ChainIndexMapper_free(tmp);

	return res;
}

static void TimeMapper_free(TimeMapper *tm) {
	if (tm != NULL) {
		KSI_Integer_free(tm->key_time);
		ChainIndexMapperList_free(tm->chainIndexeList);
		KSI_CalendarHashChain_free(tm->calendarChain);
		KSI_CalendarAuthRec_free(tm->calendarAuthRec);
		KSI_PublicationRecord_free(tm->publication);
		KSI_free(tm);
	}
}

static int TimeMapper_new(TimeMapper **tm) {
	int res = KSI_UNKNOWN_ERROR;
	TimeMapper *tmp = NULL;

	tmp = KSI_new(TimeMapper);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->chainIndexeList = NULL;
	tmp->key_time = NULL;
	tmp->calendarChain = NULL;
	tmp->calendarAuthRec = NULL;
	tmp->publication = NULL;

	*tm = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	TimeMapper_free(tmp);

	return res;
}


KSI_IMPLEMENT_LIST(ChainIndexMapper, ChainIndexMapper_free);
KSI_IMPLEMENT_LIST(TimeMapper, TimeMapper_free);

int KSI_MultiSignature_new(KSI_CTX *ctx, KSI_MultiSignature **ms) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MultiSignature *tmp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || ms == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	tmp = KSI_new(KSI_MultiSignature);
	if (tmp == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->timeList_ordered = false;
	tmp->timeList = NULL;


	*ms = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_MultiSignature_free(tmp);

	return res;
}

void KSI_MultiSignature_free(KSI_MultiSignature *ms) {
	if (ms != NULL) {
		TimeMapperList_free(ms->timeList);
		KSI_free(ms);
	}
}


static int TimeMapperList_select(KSI_LIST(TimeMapper) **mapper, KSI_Integer *tm, TimeMapper **exact, int create) {
	int res = KSI_UNKNOWN_ERROR;
	TimeMapper *hit = NULL;
	TimeMapper *hitp = NULL;
	KSI_LIST(TimeMapper) *list = NULL;
	KSI_LIST(TimeMapper) *listp = NULL;
	size_t i;

	if (mapper == NULL || tm == NULL || exact == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Optimize */
	if (*exact != NULL && KSI_Integer_equals(tm, (*exact)->key_time)) {
		res = KSI_OK;
		goto cleanup;
	}

	listp = *mapper;

	if (listp == NULL) {
		res = TimeMapperList_new(&list);
		if (res != KSI_OK) goto cleanup;

		listp = list;
	}

	for (i = 0; i < TimeMapperList_length(listp); i++) {
		TimeMapper *ptr = NULL;

		res = TimeMapperList_elementAt(listp, i, &ptr);
		if (res != KSI_OK || ptr == NULL) {
			if (res == KSI_OK) res = KSI_INVALID_STATE;
			goto cleanup;
		}

		if (KSI_Integer_equals(ptr->key_time, tm)) {
			hitp = ptr;
			break;
		}
	}

	if (hitp == NULL) {
		if (!create) {
			res = KSI_OK;
			goto cleanup;
		}
		res = TimeMapper_new(&hit);
		if (res != KSI_OK) goto cleanup;

		hit->key_time = KSI_Integer_ref(tm);

		res = TimeMapperList_append(listp, hit);
		if (res != KSI_OK) goto cleanup;

		hitp = hit;
		hit = NULL;
	}

	*exact = hitp;

	if (list != NULL && *mapper == NULL) {
		*mapper = list;
		list = NULL;
	}


	res = KSI_OK;

cleanup:

	TimeMapperList_free(list);
	TimeMapper_free(hit);

	return res;

}

static int ChainIndexMapperList_selectCreate(KSI_LIST(ChainIndexMapper) **mapper, KSI_LIST(KSI_Integer) *index, size_t lvl, KSI_LIST(ChainIndexMapper) *out, ChainIndexMapper **exact) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	KSI_Integer *key = NULL;
	ChainIndexMapper *hit = NULL;
	ChainIndexMapper *hitp = NULL;
	KSI_LIST(ChainIndexMapper) *list = NULL;
	KSI_LIST(ChainIndexMapper) *listp = NULL;


	if (mapper == NULL || index == NULL || lvl >= KSI_IntegerList_length(index)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_IntegerList_elementAt(index, lvl, &key);
	if (res != KSI_OK) goto cleanup;

	/* Assignment needed for the unlikely case that KSI_Integer_ref returns NULL
	 * even if key is not NULL. */
	key = KSI_Integer_ref(key);

	listp = *mapper;

	/* Create a new list, if empty. */
	if (listp == NULL) {
		res = ChainIndexMapperList_new(&list);
		if (res != KSI_OK) goto cleanup;

		listp = list;
	}

	/* Search for the container with the matching key. */
	for (i = 0; i < ChainIndexMapperList_length(listp); i++) {
		ChainIndexMapper *ptr = NULL;
		res = ChainIndexMapperList_elementAt(listp, i, &ptr);
		if (res != KSI_OK || ptr == NULL) {
			if (res == KSI_OK) res = KSI_INVALID_STATE;
			goto cleanup;
		}

		if (KSI_Integer_equals(ptr->key_index, key)) {
			hitp = ptr;
			break;
		}
	}

	/* Create a new container, if it does not exist. */
	if (hitp == NULL) {
		res = ChainIndexMapper_new(&hit);
		if (res != KSI_OK) goto cleanup;

		hit->key_index = key;
		key = NULL;

		res = ChainIndexMapperList_append(listp, hit);
		if (res != KSI_OK) goto cleanup;

		hitp = hit;
		hit = NULL;
	}

	/* Add the container to the output result. */
	if (out != NULL) {
		res = ChainIndexMapperList_append(out, hitp);
		if (res != KSI_OK) goto cleanup;
	}

	/* Continue search if the chain index continues. */
	if (lvl + 1 < KSI_IntegerList_length(index)) {
		res = ChainIndexMapperList_selectCreate(&hitp->children, index, lvl + 1, out, exact);
		if (res != KSI_OK) goto cleanup;
	} else {
		if (exact != NULL) {
			*exact = hitp;
		}
	}

	*mapper = listp;
	list = NULL;

	res = KSI_OK;

cleanup:

	ChainIndexMapperList_free(list);
	ChainIndexMapper_free(hit);
	KSI_Integer_free(key);

	return res;
}

static int ChainIndexMapperList_select(KSI_LIST(ChainIndexMapper) **mapper, KSI_LIST(KSI_Integer) *index, KSI_LIST(ChainIndexMapper) **path, ChainIndexMapper **exact) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(ChainIndexMapper) *list = NULL;

	if (mapper == NULL || index == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (path != NULL) {
		res = ChainIndexMapperList_new(&list);
		if (res != KSI_OK) goto cleanup;
	}

	res = ChainIndexMapperList_selectCreate(mapper, index, 0, list, exact);
	if (res != KSI_OK) goto cleanup;

	if (path != NULL) {
		*path = list;
		list = NULL;
	}

	res = KSI_OK;

cleanup:

	ChainIndexMapperList_free(list);

	return res;
}

static int addAggregationHashChain(KSI_AggregationHashChain *chn, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MultiSignature *ms = fctx;
	TimeMapper *tm = NULL;
	ChainIndexMapper *last = NULL;

	if (chn == NULL || ms == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ms->ctx);

	/* Select the appropriate time element. */
	res = TimeMapperList_select(&ms->timeList, chn->aggregationTime, &tm, 1);
	if (res != KSI_OK) goto cleanup;

	/* Add the element to the container. */
	res = ChainIndexMapperList_select(&tm->chainIndexeList, chn->chainIndex, NULL, &last);
	if (res != KSI_OK) {
		KSI_pushError(ms->ctx, res, NULL);
		goto cleanup;
	}

	/* If the aggregation chain is missing from the last node, add it. */
	if (last->aggrChain == NULL) {
		last->aggrChain = KSI_AggregationHashChain_ref(chn);
	} else {
		KSI_LOG_debug(ms->ctx, "Discarding aggregation hash chain, as it is already present.");
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int addRfc3161(KSI_RFC3161 *rfc, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(TimeMapper) *tmList = fctx;
	ChainIndexMapper *last = NULL;
	TimeMapper *tm = NULL;

	if (rfc == NULL || tmList == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = TimeMapperList_select(&tmList, rfc->aggregationTime, &tm, 1);
	if (res != KSI_OK) goto cleanup;

	res = ChainIndexMapperList_select(&tm->chainIndexeList, rfc->chainIndex, NULL, &last);
	if (res != KSI_OK) {
		KSI_pushError(rfc->ctx, res, NULL);
		goto cleanup;
	}

	last->rfc3161 = KSI_RFC3161_ref(rfc);

	res = KSI_OK;

cleanup:

	return res;
}

static int addCalendarChain(KSI_CalendarHashChain *cal, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(TimeMapper) *tmList = fctx;
	TimeMapper *calTm = NULL;
	TimeMapper *newTm = NULL;
	TimeMapper *oldTm = NULL;

	if (cal == NULL || tmList == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = TimeMapperList_select(&tmList, cal->aggregationTime, &calTm, 1);
	if (res != KSI_OK) goto cleanup;

	if (calTm->calendarChain == NULL) {
		/* If the's no calendar chain present. Add it no matter what. */
		calTm->calendarChain = KSI_CalendarHashChain_ref(cal);
	} else if (!KSI_Integer_equals(cal->publicationTime, calTm->calendarChain->publicationTime)) {
		bool prefer_newer;
		/* Update the calendar chain only if it has a stronger proof or if equally strong,
		 * use the nearest (oldest). */
		res = TimeMapperList_select(&tmList, cal->publicationTime, &newTm, 0);
		if (res != KSI_OK) goto cleanup;

		res = TimeMapperList_select(&tmList, calTm->calendarChain->publicationTime, &oldTm, 0);
		if (res != KSI_OK) goto cleanup;

		prefer_newer = KSI_Integer_compare(cal->publicationTime, calTm->calendarChain->publicationTime) < 0;

		if (/* Only update the calendar chain if the new proof exists and is new. */
				newTm != NULL && (newTm->calendarAuthRec != NULL || newTm->publication != NULL) && oldTm != newTm && (
						/* If the old proof was missing or empty, or */
						oldTm == NULL || (oldTm->calendarAuthRec == NULL && oldTm->publication == NULL) ||
						/* If new new proof is stronger with publication, or */
						(newTm->publication != NULL && (oldTm->publication == NULL || prefer_newer)) ||
						/* The new proof has calendar auth record. */
						(oldTm->publication == NULL && newTm->publication == NULL && newTm->calendarAuthRec != NULL && (oldTm->calendarAuthRec == NULL || prefer_newer)))
		) {
			KSI_CalendarHashChain_free(calTm->calendarChain);
			calTm->calendarChain = KSI_CalendarHashChain_ref(cal);
		} else {
			KSI_LOG_debug(cal->ctx, "Ignoring calendar hash chain, as there is already an existing one with equal or stronger proof.");
		}
	} else {
		KSI_LOG_debug(cal->ctx, "Ignoring duplicate calendar chain.");
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int addCalendarAuthRec(KSI_CalendarAuthRec *auth, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(TimeMapper) *tmList = fctx;
	TimeMapper *tm = NULL;

	if (auth == NULL || tmList == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(auth->ctx);

	res = TimeMapperList_select(&tmList, auth->pubData->time, &tm, 1);
	if (res != KSI_OK) goto cleanup;

	if (tm->calendarAuthRec == NULL && tm->publication == NULL) {
		tm->calendarAuthRec = KSI_CalendarAuthRec_ref(auth);
	} else {
		KSI_LOG_debug(auth->ctx, "Discarding calendar authentication record, as it is already present.");
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int addPublication(KSI_PublicationRecord *pub, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(TimeMapper) *tmList = fctx;
	TimeMapper *tm = NULL;

	if (pub == NULL || fctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(pub->ctx);

	res = TimeMapperList_select(&tmList, pub->publishedData->time, &tm, 1);
	if (res != KSI_OK) {
		KSI_pushError(pub->ctx, res, NULL);
		goto cleanup;
	}

	if (tm->publication == NULL) {
		tm->publication = KSI_PublicationRecord_ref(pub);

		/* If we have a publication we really do not need the auth record. */
		if (tm->calendarAuthRec != NULL) {
			KSI_CalendarAuthRec_free(tm->calendarAuthRec);
			tm->calendarAuthRec = NULL;
		}
	} else {
		char buf[1024];
		/* TODO! We could try merging the publication records instead. */
		KSI_LOG_debug(pub->ctx, "Discarding publication as a value already present: %s", KSI_PublicationRecord_toString(pub, buf, sizeof(buf)));
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int addAggregationAuthRec(KSI_AggregationAuthRec *auth, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(TimeMapper) *ms = fctx;
	TimeMapper *tm = NULL;
	ChainIndexMapper *last = NULL;

	if (auth == NULL || ms == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(auth->ctx);


	/* Select the appropriate time element. */
	res = TimeMapperList_select(&ms, auth->aggregationTime, &tm, 1);
	if (res != KSI_OK) {
		KSI_pushError(auth->ctx, res, NULL);
		goto cleanup;
	}

	/* Add the element to the container. */
	res = ChainIndexMapperList_select(&tm->chainIndexeList, auth->chainIndexesList, NULL, &last);
	if (res != KSI_OK) {
		KSI_pushError(auth->ctx, res, NULL);
		goto cleanup;
	}

	if (last->aggrAuthRec == NULL) {
		last->aggrAuthRec = KSI_AggregationAuthRec_ref(auth);
	} else {
		KSI_LOG_debug(auth->ctx, "Discarding aggregation auth record, as it already is present.");
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MultiSignature_add(KSI_MultiSignature *ms, const KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;

	if (ms == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ms->ctx);

	if (sig == NULL) {
		KSI_pushError(ms->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* Cycle through all aggregation hash chains and add them to the container. */
	res = KSI_AggregationHashChainList_foldl(sig->aggregationChainList, ms, addAggregationHashChain);
	if (res != KSI_OK) {
		KSI_pushError(ms->ctx, res, NULL);
		goto cleanup;
	}

	/* Add the rfc3161 element. */
	if (sig->rfc3161 != NULL) {
		res = addRfc3161(sig->rfc3161, ms->timeList);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Add the publication. */
	if (sig->publication != NULL) {
		res = addPublication(sig->publication, ms->timeList);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Add the calendar auth record. */
	if (sig->calendarAuthRec != NULL) {
		res = addCalendarAuthRec(sig->calendarAuthRec, ms->timeList);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Add the calendar chain.
	 * NB! Before this, the publication and calendar auth record must be stored. */
	if (sig->calendarChain != NULL) {
		res = addCalendarChain(sig->calendarChain, ms->timeList);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}
	}

	/* Add the aggregation auth record. */
	if (sig->aggregationAuthRec != NULL) {
		res = addAggregationAuthRec(sig->aggregationAuthRec, ms->timeList);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}
	}

	/* The list is now probably out of order. */
	ms->timeList_ordered = false;

	res = KSI_OK;

cleanup:

	return res;
}

static int findAggregationHashChainList(KSI_LIST(ChainIndexMapper) *cimList, const KSI_DataHash *hsh, KSI_LIST(KSI_AggregationHashChain) *aggList) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	ChainIndexMapper *cim = NULL;
	KSI_DataHash *inputHash = NULL;

	if (hsh == NULL || aggList == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	for (i = 0; i < ChainIndexMapperList_length(cimList); i++) {
		res = ChainIndexMapperList_elementAt(cimList, i, &cim);
		if (res != KSI_OK || cim == NULL) {
			if (res == KSI_OK) res = KSI_INVALID_STATE;
			goto cleanup;
		}

		if (cim->aggrChain == NULL) {
			/* When there is no aggregation chain, there are no siblings containing a chain either. */
			continue;
		}

		/* If RFC3161 record exist, extract the real input hash! */
		if (cim->rfc3161 != NULL) {
			inputHash = cim->rfc3161->inputHash;
		} else {
			inputHash = cim->aggrChain->inputHash;
		}

		if (KSI_DataHash_equals(inputHash, hsh)) {
			KSI_AggregationHashChain *ref = NULL;
			res = KSI_AggregationHashChainList_append(aggList, ref = KSI_AggregationHashChain_ref(cim->aggrChain));
			if (res != KSI_OK) {
				/* Cleanup the reference. */
				KSI_AggregationHashChain_free(ref);

				goto cleanup;
			}

			break;
		}

		/* Search for sub elements. */
		if (ChainIndexMapperList_length(cim->children) > 0) {
			KSI_AggregationHashChain *ref = NULL;

			res = findAggregationHashChainList(cim->children, hsh, aggList);
			if (res != KSI_OK) goto cleanup;

			if (KSI_AggregationHashChainList_length(aggList) > 0) {
				res = KSI_AggregationHashChainList_append(aggList, ref = KSI_AggregationHashChain_ref(cim->aggrChain));
				if (res != KSI_OK) {
					/* Cleanup the reference. */
					KSI_AggregationHashChain_free(ref);

					goto cleanup;
				}

				break;
			}
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int findAggregationHashChain(KSI_LIST(TimeMapper) *tmList, const KSI_DataHash *hsh, TimeMapper **mapper, KSI_LIST(KSI_AggregationHashChain) **aggrList) {
	int res = KSI_SERVICE_UNKNOWN_ERROR;
	size_t i;
	TimeMapper *tm = NULL;
	KSI_LIST(KSI_AggregationHashChain) *agl = NULL;

	if (hsh == NULL || mapper == NULL || aggrList == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_AggregationHashChainList_new(&agl);
	if (res != KSI_OK) goto cleanup;

	for (i = 0; i < TimeMapperList_length(tmList); i++) {
		res = TimeMapperList_elementAt(tmList, i, &tm);
		if (res != KSI_OK || tm == NULL) {
			if (res == KSI_OK) res = KSI_INVALID_STATE;
			goto cleanup;
		}

		res = findAggregationHashChainList(tm->chainIndexeList, hsh, agl);
		if (res != KSI_OK) goto cleanup;

		/* Stop when there are results. */
		if (KSI_AggregationHashChainList_length(agl) > 0) {
			break;
		}
	}

	if (KSI_AggregationHashChainList_length(agl) == 0) {
		res = KSI_MULTISIG_NOT_FOUND;
		goto cleanup;
	}

	*mapper = tm;
	*aggrList = agl;
	agl = NULL;

	res = KSI_OK;

cleanup:

	KSI_AggregationHashChainList_free(agl);

	return res;
}

static int TimeMapper_cmp(const TimeMapper **a, const TimeMapper **b) {
	/* NB! We assume a and b are not NULL - otherwise, there is something wrong with
	 * the container. Null checks added only for safety. */
	return (*a == NULL || *b == NULL) ? 0 : KSI_Integer_compare((*a)->key_time, (*b)->key_time);
}

int KSI_MultiSignature_get(KSI_MultiSignature *ms, const KSI_DataHash *hsh, KSI_Signature **sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;
	TimeMapper *tm = NULL;

	if (ms == NULL || hsh == NULL || sig == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ms->ctx);

	tmp = KSI_new(KSI_Signature);
	if (tmp == NULL) {
		KSI_pushError(ms->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	tmp->ctx = ms->ctx;
	tmp->ref = 1;
	tmp->aggregationAuthRec = NULL;
	tmp->aggregationChainList = NULL;
	tmp->baseTlv = NULL;
	tmp->calendarAuthRec = NULL;
	tmp->calendarChain = NULL;
	tmp->publication = NULL;
	tmp->rfc3161 = NULL;
	memset(&tmp->verificationResult, 0, sizeof(tmp->verificationResult));
	tmp->policyVerificationResult = NULL;

	/* If the list is not ordered, order it, to find always the earliest signature possible. This
	 * is an issue if there are more than one signatures for the same inputhash. */
	if (!ms->timeList_ordered && ms->timeList != NULL) {
		res = TimeMapperList_sort(ms->timeList, TimeMapper_cmp);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}

		ms->timeList_ordered = true;
	}

	/* Select all the hash chains. */
	res = findAggregationHashChain(ms->timeList, hsh, &tm, &tmp->aggregationChainList);
	if (res != KSI_OK) {
		KSI_pushError(ms->ctx, res, NULL);
		goto cleanup;
	}

	if (tm == NULL) {
		KSI_pushError(ms->ctx, res = KSI_MULTISIG_INVALID_STATE, NULL);
		goto cleanup;
	}

	tmp->calendarChain = tm->calendarChain;

	if (tmp->calendarChain != NULL) {
		TimeMapper *proof = NULL;
		KSI_CalendarHashChain *ref = NULL;

		/* Make a reference. */
		ref = KSI_CalendarHashChain_ref(tmp->calendarChain);
		/* Find proof. */
		res = TimeMapperList_select(&ms->timeList, tmp->calendarChain->publicationTime, &proof, 0);
		if (res != KSI_OK) {
			/* Cleanup the reference. */
			KSI_CalendarHashChain_free(ref);

			goto cleanup;
		}

		if (proof != NULL) {
			KSI_CalendarAuthRec_free(tmp->calendarAuthRec);
			KSI_CalendarAuthRec_ref(proof->calendarAuthRec);
			tmp->calendarAuthRec = proof->calendarAuthRec;

			KSI_PublicationRecord_free(tmp->publication);
			KSI_PublicationRecord_ref(proof->publication);
			tmp->publication = proof->publication;
		}
	}

	*sig = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_Signature_free(tmp);

	return res;
}

/**
 * Remove all empty nodes in this list (non-recursive).
 */
static int ChainIndexMapperList_vacuum(KSI_LIST(ChainIndexMapper) *cimList) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	for (i = ChainIndexMapperList_length(cimList); i > 0; i--) {
		ChainIndexMapper *cim = NULL;

		res = ChainIndexMapperList_elementAt(cimList, i - 1, &cim);
		if (res != KSI_OK || cim == NULL) {
			if (res == KSI_OK) res = KSI_INVALID_STATE;
			goto cleanup;
		}

		/* Check if the chain index mapper should be removed. */
		if ((cim->aggrAuthRec == NULL && cim->aggrChain == NULL) || (cim->children != NULL && ChainIndexMapperList_length(cim->children) == 0)) {
			res = ChainIndexMapperList_remove(cimList, i - 1, NULL);
			if (res != KSI_OK) goto cleanup;
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int TimeMapper_unpaint(TimeMapper *tm, void *foldCtx) {
	if (tm == NULL) return KSI_INVALID_ARGUMENT;
	tm->paint = false;
	return KSI_OK;
}

static int ChainIndexMapper_deleteSignature(ChainIndexMapper *cim, void *foldCtx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = foldCtx;

	if (cim == NULL || foldCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Deletion should be performed only on leafs. */
	if (cim->children != NULL) {
		/* Intermediate node. */
		res = ChainIndexMapperList_foldl(cim->children, foldCtx, ChainIndexMapper_deleteSignature);
		if (res != KSI_OK) goto cleanup;
		res = ChainIndexMapperList_vacuum(cim->children);

	} else {
		/* Leaf node. */
		if ((cim->rfc3161 != NULL && KSI_DataHash_equals(cim->rfc3161->inputHash, hsh))
				|| (cim->rfc3161 == NULL && cim->aggrChain != NULL && KSI_DataHash_equals(cim->aggrChain->inputHash, hsh))) {
			/* Remove the KSI aggregation hash chain. */
			KSI_AggregationHashChain_free(cim->aggrChain);
			cim->aggrChain = NULL;
		}

		if (cim->rfc3161 != NULL && KSI_DataHash_equals(cim->rfc3161->inputHash, hsh)) {
			/* Remove the RFC-3161 legacy aggregation hash chain. */
			KSI_RFC3161_free(cim->rfc3161);
			cim->rfc3161 = NULL;
		}

		/* If there are no aggregation chains left, delete the aggregation auth record. */
		if (cim->aggrChain == NULL && cim->rfc3161 == NULL && cim->aggrAuthRec != NULL) {
			KSI_AggregationAuthRec_free(cim->aggrAuthRec);
			cim->aggrAuthRec = NULL;
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int TimeMapper_deleteSignature(TimeMapper *tm, void *foldCtx) {
	int res = KSI_UNKNOWN_ERROR;

	res = ChainIndexMapperList_foldl(tm->chainIndexeList, foldCtx, ChainIndexMapper_deleteSignature);
	if (res != KSI_OK) goto cleanup;

	res = ChainIndexMapperList_vacuum(tm->chainIndexeList);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static int TimeMapper_markUsedCalendarChains(TimeMapper *tm, void *foldCtx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(TimeMapper) *tmList = foldCtx;
	size_t i;

	if (tm == NULL || foldCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
	}

	for (i = 0; i < ChainIndexMapperList_length(tm->chainIndexeList); i++) {
		ChainIndexMapper *cim = NULL;
		TimeMapper *calTm = NULL;
		res = ChainIndexMapperList_elementAt(tm->chainIndexeList, i, &cim);
		if (res != KSI_OK || cim == NULL) {
			if (res == KSI_OK) res = KSI_INVALID_STATE;
			goto cleanup;
		}

		if (cim->aggrChain != NULL) {
			res = TimeMapperList_select(&tmList, cim->aggrChain->aggregationTime, &calTm, 0);
			if (res != KSI_OK) goto cleanup;

			if (calTm == NULL) {
				res = KSI_MULTISIG_INVALID_STATE;
				goto cleanup;
			}

			calTm->paint = true;
		}

		if (cim->rfc3161 != NULL) {
			res = TimeMapperList_select(&tmList, cim->rfc3161->aggregationTime, &calTm, 0);
			if (res != KSI_OK) goto cleanup;

			if (calTm == NULL) {
				res = KSI_MULTISIG_INVALID_STATE;
				goto cleanup;
			}

			calTm->paint = true;
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int TimeMapper_markUsedProofs(TimeMapper *tm, void *foldCtx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(TimeMapper) *tmList = foldCtx;

	if (tm == NULL || foldCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Exit if this element is not painted. */
	if (!tm->paint) return KSI_OK;

	if (tm->calendarChain != NULL) {
		TimeMapper *pubTm = NULL;

		res = TimeMapperList_select(&tmList,  tm->calendarChain->publicationTime, &pubTm, 0);
		if (res != KSI_OK) goto cleanup;

		if (pubTm->calendarAuthRec != NULL || pubTm->publication != NULL) {
			pubTm->paint = true;
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int TimeMapperList_vacuum(KSI_LIST(TimeMapper) *tmList) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	for (i = TimeMapperList_length(tmList); i > 0; i--) {
		TimeMapper *tm = NULL;
		res = TimeMapperList_elementAt(tmList, i - 1, &tm);
		if (res != KSI_OK || tm == NULL) {
			if (res == KSI_OK) res = KSI_INVALID_STATE;
			goto cleanup;
		}

		if (!tm->paint && ChainIndexMapperList_length(tm->chainIndexeList) == 0) {
			res = TimeMapperList_remove(tmList, i - 1, NULL);
			if (res != KSI_OK) goto cleanup;
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MultiSignature_remove(KSI_MultiSignature *ms, const KSI_DataHash *hsh) {
	int res = KSI_UNKNOWN_ERROR;

	if (ms == NULL || hsh == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = TimeMapperList_foldl(ms->timeList, (void *)hsh, TimeMapper_deleteSignature);
	if (res != KSI_OK) {
		KSI_pushError(ms->ctx, res, NULL);
		goto cleanup;
	}

	/* Cleanup. */

	/* Reset the paint markers. */
	res = TimeMapperList_foldl(ms->timeList, NULL, TimeMapper_unpaint);
	if (res != KSI_OK) goto cleanup;

	/* Mark all the used calendar chains. */
	res = TimeMapperList_foldl(ms->timeList, ms->timeList, TimeMapper_markUsedCalendarChains);
	if (res != KSI_OK) goto cleanup;

	/* Mark all the proofs used by the marked calendars. */
	res = TimeMapperList_foldl(ms->timeList, ms->timeList, TimeMapper_markUsedProofs);
	if (res != KSI_OK) goto cleanup;

	res = TimeMapperList_vacuum(ms->timeList);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

struct hash_finder_st {
	bool used[KSI_NUMBER_OF_KNOWN_HASHALGS];
};

static int ChainIndexMapper_findAlgos(ChainIndexMapper *ciMap, void *fc) {
	int res = KSI_UNKNOWN_ERROR;
	struct hash_finder_st *foldCtx = fc;

	if (ciMap != NULL) {
		if (ChainIndexMapperList_length(ciMap->children) > 0) {
			res = ChainIndexMapperList_foldl(ciMap->children, foldCtx, ChainIndexMapper_findAlgos);
			if (res != KSI_OK) goto cleanup;
		} else {
			KSI_HashAlgorithm hashAlgo;
			if (ciMap->aggrChain != NULL) {
				res = KSI_DataHash_getHashAlg(ciMap->aggrChain->inputHash, &hashAlgo);
				if (res != KSI_OK) goto cleanup;

				/* Just to be on the safe side. */
				if (hashAlgo >= (sizeof(foldCtx->used) / sizeof(bool))) {
					res = KSI_UNKNOWN_ERROR;
					goto cleanup;
				}
				foldCtx->used[hashAlgo] = true;
			}

			if (ciMap->rfc3161 != NULL) {
				res = KSI_DataHash_getHashAlg(ciMap->rfc3161->inputHash, &hashAlgo);
				if (res != KSI_OK) goto cleanup;

				/* Just to be on the safe side. */
				if (hashAlgo >= (sizeof(foldCtx->used) / sizeof(bool))) {
					res = KSI_UNKNOWN_ERROR;
					goto cleanup;
				}
				foldCtx->used[hashAlgo] = true;
			}
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}


static int TimeMapper_findAlgos(TimeMapper *tmMap, void *foldCtx) {
	int res = KSI_UNKNOWN_ERROR;

	if (tmMap != NULL) {
		res = ChainIndexMapperList_foldl(tmMap->chainIndexeList, foldCtx, ChainIndexMapper_findAlgos);
		if (res != KSI_OK) goto cleanup;
	}
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MultiSignature_getUsedHashAlgorithms(KSI_MultiSignature *ms, KSI_HashAlgorithm **arr, size_t *arr_len) {
	int res = KSI_UNKNOWN_ERROR;
	struct hash_finder_st used;
	KSI_HashAlgorithm *tmp = NULL;
	size_t tmp_len = 0;
	size_t i;

	if (ms == NULL || arr == NULL || arr_len == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(&used, 0, sizeof(used));

	res = TimeMapperList_foldl(ms->timeList, &used, TimeMapper_findAlgos);
	if (res != KSI_OK) goto cleanup;

	for (i = 0; i < KSI_NUMBER_OF_KNOWN_HASHALGS; i++) {
		if (used.used[i]) tmp_len++;
	}

	if (tmp_len > 0) {
		KSI_HashAlgorithm *ptr = NULL;
		tmp = KSI_calloc(tmp_len, sizeof(KSI_HashAlgorithm));
		if (tmp == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}

		ptr = tmp;
		for (i = 0; i < KSI_NUMBER_OF_KNOWN_HASHALGS; i++) {
			if (used.used[i]) {
				*ptr++ = i;
			}
		}

		*arr = tmp;
		tmp = NULL;
	}

	*arr_len = tmp_len;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);

	return res;
}

typedef struct ExtendHelper_st {
	KSI_LIST(TimeMapper) *tmList;
	KSI_PublicationRecord *pubRec;
} ExtendHelper;

static int extendUnextended(TimeMapper *tm, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	ExtendHelper *helper = fctx;
	KSI_RequestHandle *handle = NULL;
	KSI_ExtendReq *req = NULL;
	KSI_ExtendResp *resp = NULL;
	KSI_Integer *aggregationTime = NULL;
	KSI_Integer *publicationTime = NULL;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_PublicationRecord *pubRec = NULL;

	if (tm == NULL || helper == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Handle only calendar chains. */
	if (tm->calendarChain != NULL) {
		TimeMapper *proof = NULL;

		res = TimeMapperList_select(&helper->tmList, tm->calendarChain->publicationTime, &proof, 0);
		if (res != KSI_OK) goto cleanup;

		if (proof == NULL) {
			res = KSI_INVALID_STATE;
			goto cleanup;
		}

		/* Extend only if there is no publication, or there is a publication given. */
		if (proof->publication == NULL || helper->pubRec != NULL) {
			bool verifyPubFile = (tm->calendarChain->ctx->publicationsFile == NULL);

			/* As there is no publication attached, try to find suitable publication. */
			res = KSI_receivePublicationsFile(tm->calendarChain->ctx, &pubFile);
			if (res != KSI_OK) goto cleanup;

			if (verifyPubFile == true) {
				res = KSI_verifyPublicationsFile(tm->calendarChain->ctx, pubFile);
				if (res != KSI_OK) goto cleanup;
			}

			if (helper->pubRec != NULL) {
				KSI_Integer *pubRecTime = NULL;
				KSI_PublicationData *pubDat = NULL;

				/* Extract the published data from the publication record. */
				res = KSI_PublicationRecord_getPublishedData(helper->pubRec, &pubDat);
				if (res != KSI_OK) goto cleanup;

				/* Extract the publication time from the publication data. */
				res = KSI_PublicationData_getTime(pubDat, &pubRecTime);
				if (res != KSI_OK) goto cleanup;

				/* Update the publication record only if it is applicable to the current chain. */
				if (KSI_Integer_compare(pubRecTime, aggregationTime) > 0) {
					pubRec = helper->pubRec;
				}
			} else {
				/* Find the nearest publication. */
				res = KSI_PublicationsFile_getNearestPublication(pubFile, tm->calendarChain->publicationTime, &pubRec);
				if (res != KSI_OK) goto cleanup;
			}

			/* Only continue, if there is such a publication available. */
			if (pubRec != NULL) {
				KSI_CalendarHashChain *chn = NULL;

				/* Add the publication to the container. */
				res = addPublication(pubRec, helper->tmList);
				if (res != KSI_OK) goto cleanup;

				/* Create a new extension request. */
				res = KSI_ExtendReq_new(tm->calendarChain->ctx, &req);
				if (res != KSI_OK) goto cleanup;

				/* Create a reference to aggregation time. */
				aggregationTime = KSI_Integer_ref(tm->calendarChain->aggregationTime);

				/* Create reference to publication time. */
				publicationTime = KSI_Integer_ref(pubRec->publishedData->time);

				/* Populate the aggregation time. */
				res = KSI_ExtendReq_setAggregationTime(req, aggregationTime);
				if (res != KSI_OK) goto cleanup;

				/* Populate the publication time. */
				res = KSI_ExtendReq_setPublicationTime(req, publicationTime);
				if (res != KSI_OK) goto cleanup;

				/* Send the extension request. */
				res = KSI_sendExtendRequest(tm->calendarChain->ctx, req, &handle);
				if (res != KSI_OK) goto cleanup;

				/* Perform the request. */
				res = KSI_RequestHandle_perform(handle);
				if (res != KSI_OK) goto cleanup;

				/* Call a blocking call to receive the response. */
				res = KSI_RequestHandle_getExtendResponse(handle, &resp);
				if (res != KSI_OK) goto cleanup;

				/* Extract the calendar chain from the extension request. */
				res = KSI_ExtendResp_getCalendarHashChain(resp, &chn);
				if (res != KSI_OK) goto cleanup;

				/* Add the response calendar chain to the multi signature. */
				res = addCalendarChain(chn, helper->tmList);
				if (res != KSI_OK) goto cleanup;
			}
		}
	}

	res = KSI_OK;

cleanup:

	KSI_PublicationRecord_free(pubRec);
	KSI_PublicationsFile_free(pubFile);
	KSI_RequestHandle_free(handle);
	KSI_ExtendReq_free(req);
	KSI_ExtendResp_free(resp);

	return res;
}

static int extend(KSI_MultiSignature *ms, const KSI_PublicationRecord *pubRec) {
	int res = KSI_UNKNOWN_ERROR;
	ExtendHelper helper;

	if (ms == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ms->ctx);

	memset(&helper, 0, sizeof(helper));

	helper.tmList = ms->timeList;
	helper.pubRec = (KSI_PublicationRecord *) pubRec;

	res = TimeMapperList_foldl(ms->timeList, &helper, extendUnextended);
	if (res != KSI_OK) {
		KSI_pushError(ms->ctx, res, NULL);
		goto cleanup;
	}

	/* Reset the paint markers. */
	res = TimeMapperList_foldl(ms->timeList, NULL, TimeMapper_unpaint);
	if (res != KSI_OK) goto cleanup;

	/* Mark all the used calendar chains. */
	res = TimeMapperList_foldl(ms->timeList, ms->timeList, TimeMapper_markUsedCalendarChains);
	if (res != KSI_OK) goto cleanup;

	/* Mark all the proofs used by the marked calendars. */
	res = TimeMapperList_foldl(ms->timeList, ms->timeList, TimeMapper_markUsedProofs);
	if (res != KSI_OK) goto cleanup;

	res = TimeMapperList_vacuum(ms->timeList);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}


int KSI_MultiSignature_extend(KSI_MultiSignature *ms) {
	return extend(ms, NULL);
}

int KSI_MultiSignature_extendToPublication(KSI_MultiSignature *ms, const KSI_PublicationRecord *pubRec) {
	return extend(ms, pubRec);
}

static int ChainIndexMapper_writeBytes(KSI_LIST(ChainIndexMapper) *cimList, unsigned char *buf, size_t buf_size, size_t *buf_len) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	size_t len = 0;
	size_t tmp_len;

	if ((buf == NULL && buf_size != 0) || buf_len == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	for (i = ChainIndexMapperList_length(cimList); i > 0; i--) {
		ChainIndexMapper *cim = NULL;
		res = ChainIndexMapperList_elementAt(cimList, i - 1, &cim);
		if (res != KSI_OK || cim == NULL) {
			if (res == KSI_OK) res = KSI_INVALID_STATE;
			goto cleanup;
		}

		/* Write the children. */
		res = ChainIndexMapper_writeBytes(cim->children, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len);
		if (res != KSI_OK) goto cleanup;

		len += tmp_len;
		if (buf != NULL && len > buf_size) {
			res = KSI_BUFFER_OVERFLOW;
			goto cleanup;
		}

		if (cim->aggrChain != NULL) {
			res = KSI_AggregationHashChain_writeBytes(cim->aggrChain, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len, KSI_TLV_OPT_NO_MOVE);
			if (res != KSI_OK) goto cleanup;

			len += tmp_len;
			if (buf != NULL && len > buf_size) {
				res = KSI_BUFFER_OVERFLOW;
				goto cleanup;
			}
		}

		if (cim->aggrAuthRec != NULL) {
			res = KSI_AggregationAuthRec_writeBytes(cim->aggrAuthRec, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len, KSI_TLV_OPT_NO_MOVE);
			if (res != KSI_OK) goto cleanup;

			len += tmp_len;
			if (buf != NULL && len > buf_size) {
				res = KSI_BUFFER_OVERFLOW;
				goto cleanup;
			}
		}

		if (cim->rfc3161 != NULL) {
			res = KSI_RFC3161_writeBytes(cim->rfc3161, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len, KSI_TLV_OPT_NO_MOVE);
			if (res != KSI_OK) goto cleanup;

			len += tmp_len;
			if (buf != NULL && len > buf_size) {
				res = KSI_BUFFER_OVERFLOW;
				goto cleanup;
			}
		}

	}

	*buf_len = len;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MultiSignature_writeBytes(KSI_MultiSignature *ms, unsigned char *buf, size_t buf_size, size_t *buf_len, int opt) {
	int res = KSI_UNKNOWN_ERROR;
	size_t len = 0;
	size_t i;

	if (ms == NULL || (buf == NULL && buf_size != 0)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ms->ctx);

	for (i = 0; i < TimeMapperList_length(ms->timeList); i++) {
		TimeMapper *tm = NULL;
		size_t tmp_len;

		res = TimeMapperList_elementAt(ms->timeList, i, &tm);
		if (res != KSI_OK || tm == NULL) {
			if (res == KSI_OK) res = KSI_INVALID_STATE;
			goto cleanup;
		}

		if (tm->calendarAuthRec != NULL) {

			/* Write the bytes to the end of the buffer. */
			res = KSI_CalendarAuthRec_writeBytes(tm->calendarAuthRec, buf, ((buf == NULL) ? 0 : buf_size - len), &tmp_len, KSI_TLV_OPT_NO_MOVE);
			if (res != KSI_OK) {
				KSI_pushError(ms->ctx, res, NULL);
				goto cleanup;
			}

			len += tmp_len;
			/* Just to be sure - should never happen. */
			if (buf != NULL && len > buf_size) {
				KSI_pushError(ms->ctx, res = KSI_BUFFER_OVERFLOW, NULL);
				goto cleanup;
			}
		}

		if (tm->publication != NULL) {
			/* Write the bytes to the end of the buffer. */
			res = KSI_PublicationRecord_writeBytes(tm->publication, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len, KSI_TLV_OPT_NO_MOVE);
			if (res != KSI_OK) {
				KSI_pushError(ms->ctx, res, NULL);
				goto cleanup;
			}

			len += tmp_len;
			/* Just to be sure - should never happen. */
			if (buf != NULL && len > buf_size) {
				KSI_pushError(ms->ctx, res = KSI_BUFFER_OVERFLOW, NULL);
				goto cleanup;
			}
		}

		if (tm->calendarChain != NULL) {
			res = KSI_CalendarHashChain_writeBytes(tm->calendarChain, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len, KSI_TLV_OPT_NO_MOVE);
			if (res != KSI_OK) {
				KSI_pushError(ms->ctx, res, NULL);
				goto cleanup;
			}

			len += tmp_len;
			/* Just to be sure - should never happen. */
			if (buf != NULL && len > buf_size) {
				KSI_pushError(ms->ctx, res = KSI_BUFFER_OVERFLOW, NULL);
				goto cleanup;
			}
		}

		res = ChainIndexMapper_writeBytes(tm->chainIndexeList, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}

		len += tmp_len;
		/* Just to be sure - should never happen. */
		if (buf != NULL && len > buf_size) {
			KSI_pushError(ms->ctx, res = KSI_BUFFER_OVERFLOW, NULL);
			goto cleanup;
		}
	}

	if ((opt & KSI_TLV_OPT_NO_HEADER) == 0) {
		size_t hdr_len = strlen(KSI_MULTI_SIGNATURE_HDR);
		len += hdr_len;

		if (buf != NULL) {
			if (len > buf_size) {
				KSI_pushError(ms->ctx, res = KSI_BUFFER_OVERFLOW, NULL);
				goto cleanup;
			}

			memcpy(buf + buf_size - len, KSI_MULTI_SIGNATURE_HDR, hdr_len);
		}
	}

	if ((opt & KSI_TLV_OPT_NO_MOVE) == 0 && buf != NULL) {
		/* Just be sure. */
		if (len > buf_size) {
			KSI_pushError(ms->ctx, res = KSI_BUFFER_OVERFLOW, NULL);
			goto cleanup;
		}

		/* Shift all the bytes to the beginning of the buffer. */
		for (i = 0; i < len; i++) {
			buf[i] = buf[buf_size - len + i];
		}

		/* If the serialized value is short enough, log its value for debug'ing. */
		if (len < 0xffff) {
			KSI_LOG_logBlob(ms->ctx, KSI_LOG_DEBUG, "Serialized multi signature container", buf, len);
		}
	}

	if (buf_len != NULL) {
		*buf_len = len;
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int parserGenerator(void *pctx, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	ParserHelper *hlpr = pctx;
	KSI_FTLV ftlv;

	memset(&ftlv, 0, sizeof(ftlv));

	if (hlpr == NULL || tlv == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (hlpr->tlv != NULL) {
		KSI_TLV_free(hlpr->tlv);
		hlpr->tlv = NULL;
	}

	KSI_ERR_clearErrors(hlpr->ctx);

	if (hlpr->ptr_len > 0 || (hlpr->file != NULL && !feof(hlpr->file))) {
		size_t tlv_len;

		if (hlpr->file != NULL) {
			unsigned char buf[0xffff + 4];
			res = KSI_FTLV_fileRead(hlpr->file, buf, sizeof(buf), NULL, &ftlv);
			if (res != KSI_OK) {
				if (feof(hlpr->file)) {
					*tlv = NULL;
					res = KSI_OK;
					goto cleanup;
				}
				KSI_pushError(hlpr->ctx, res, NULL);
				goto cleanup;
			}

			tlv_len = ftlv.hdr_len + ftlv.dat_len;

			res = KSI_TLV_parseBlob(hlpr->ctx, buf, tlv_len, &hlpr->tlv);
			if (res != KSI_OK) {
				KSI_pushError(hlpr->ctx, res, NULL);
				goto cleanup;
			}
		} else {
			res = KSI_FTLV_memRead(hlpr->ptr, hlpr->ptr_len, &ftlv);
			if (res != KSI_OK) {
				KSI_pushError(hlpr->ctx, res, NULL);
				goto cleanup;
			}

			tlv_len = ftlv.hdr_len + ftlv.dat_len;
			if (tlv_len > hlpr->ptr_len) {
				KSI_pushError(hlpr->ctx, res = KSI_INVALID_FORMAT, NULL);
				goto cleanup;
			}

			/* Cast is safe, as the data is not modified. */
			res = KSI_TLV_parseBlob2(hlpr->ctx, (unsigned char *)hlpr->ptr, tlv_len, 0, &hlpr->tlv);
			if (res != KSI_OK) {
				KSI_pushError(hlpr->ctx, res, NULL);
				goto cleanup;
			}

			hlpr->ptr += tlv_len;
			hlpr->ptr_len -= tlv_len;
		}
	}

	*tlv = hlpr->tlv;
	res = KSI_OK;

cleanup:

	return res;
}

static int readMultiSignature(KSI_CTX *ctx, ParserHelper *hlpr, KSI_MultiSignature **ms) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MultiSignature *tmp = NULL;

	res = KSI_TlvTemplate_extractGenerator(ctx, hlpr, hlpr, KSI_TLV_TEMPLATE(ParserHelper), parserGenerator);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Create an empty multi signature container. */
	res = KSI_MultiSignature_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add all the aggregation hash chains to the container. */
	res = KSI_AggregationHashChainList_foldl(hlpr->aggregationChainList, tmp, addAggregationHashChain);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add all the publications to the container. */
	res = KSI_PublicationRecordList_foldl(hlpr->publicationRecordList, tmp->timeList, addPublication);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add all the calendar auth records to the container. */
	res = KSI_CalendarAuthRecList_foldl(hlpr->calendarAuthRecordList, tmp->timeList, addCalendarAuthRec);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add all the calendar hash chains to the container.
	 * NB! It is essential that the publications and calendar auth records are processed by now. */
	res = KSI_CalendarHashChainList_foldl(hlpr->calendarChainList, tmp->timeList, addCalendarChain);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add all the aggregation auth records to the container. */
	res = KSI_AggregationAuthRecList_foldl(hlpr->aggregationAuthRecordList, tmp->timeList, addAggregationAuthRec);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add all the rfc3161 elements to the container. */
	res = KSI_RFC3161List_foldl(hlpr->rfc3161List, tmp->timeList, addRfc3161);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*ms = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_MultiSignature_free(tmp);
	KSI_AggregationHashChainList_free(hlpr->aggregationChainList);
	KSI_CalendarHashChainList_free(hlpr->calendarChainList);
	KSI_PublicationRecordList_free(hlpr->publicationRecordList);
	KSI_AggregationAuthRecList_free(hlpr->aggregationAuthRecordList);
	KSI_CalendarAuthRecList_free(hlpr->calendarAuthRecordList);
	KSI_RFC3161List_free(hlpr->rfc3161List);
	KSI_TLV_free(hlpr->tlv);

	return res;
}

static void ParserHelper_init(KSI_CTX *ctx, ParserHelper *h) {
	if (h != NULL) {
		h->ctx = ctx;
		h->aggregationAuthRecordList = NULL;
		h->aggregationChainList = NULL;
		h->calendarAuthRecordList = NULL;
		h->calendarChainList = NULL;
		h->file = NULL;
		h->ptr = NULL;
		h->ptr_len = 0;
		h->publicationRecordList = NULL;
		h->rfc3161List = NULL;
		h->tlv = NULL;
	}
}

int KSI_MultiSignature_parse(KSI_CTX *ctx, const unsigned char *raw, size_t raw_len, KSI_MultiSignature **ms) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MultiSignature *tmp = NULL;
	ParserHelper hlpr;
	size_t hdr_len;

	ParserHelper_init(ctx, &hlpr);
	hdr_len = strlen(KSI_MULTI_SIGNATURE_HDR);

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || raw == NULL || raw_len == 0 || ms == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (raw_len < hdr_len) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Input shorter than expected magic number.");
		goto cleanup;
	}

	if (memcmp(raw, KSI_MULTI_SIGNATURE_HDR, hdr_len)) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Multi signature container magic number mismatch.");
		goto cleanup;
	}

	hlpr.ptr = raw + hdr_len;
	hlpr.ptr_len = raw_len - hdr_len;

	res = readMultiSignature(ctx, &hlpr, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*ms = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_MultiSignature_free(tmp);

	return res;
}

int KSI_MultiSignature_fromFile(KSI_CTX *ctx, const char *fileName, KSI_MultiSignature **ms) {
	int res = KSI_UNKNOWN_ERROR;
	FILE *fd = NULL;
	KSI_MultiSignature *tmp = NULL;
	ParserHelper hlpr;
	size_t len;
	size_t hdr_len;
	char buf[1024];

	ParserHelper_init(ctx, &hlpr);
	hdr_len = strlen(KSI_MULTI_SIGNATURE_HDR);

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || fileName == NULL || *fileName == '\0' || ms == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	fd = fopen(fileName, "rb");
	if (fd == NULL) {
		KSI_snprintf(buf, sizeof(buf), "Unable to open file '%s'", fileName);
		KSI_pushError(ctx, res = KSI_IO_ERROR, buf);
		goto cleanup;
	}

	len = fread(buf, 1, hdr_len, fd);
	if (len != hdr_len) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Input shorter than expected magic number.");
		goto cleanup;
	}

	if (strncmp(buf, KSI_MULTI_SIGNATURE_HDR, hdr_len)) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Multi signature container magic number mismatch.");
		goto cleanup;
	}

	hlpr.file = fd;

	res = readMultiSignature(ctx, &hlpr, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*ms = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	if (fd != NULL) fclose(fd);

	KSI_MultiSignature_free(tmp);

	return res;
}

int KSI_MultiSignature_serialize(KSI_MultiSignature *ms, unsigned char **raw, size_t *raw_len) {
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *buf = NULL;
	size_t len;

	res = KSI_MultiSignature_writeBytes(ms, NULL, 0, &len, 0);
	if (res != KSI_OK) goto cleanup;

	buf = KSI_malloc(len);
	if (buf == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = KSI_MultiSignature_writeBytes(ms, buf, len, NULL, 0);
	if (res != KSI_OK) goto cleanup;

	*raw = buf;
	buf = NULL;
	*raw_len = len;

	res = KSI_OK;

cleanup:

	KSI_free(buf);
	return res;
}

