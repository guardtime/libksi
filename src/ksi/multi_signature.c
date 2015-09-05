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

#define KSI_MULTI_SIGNATURE_HDR "MULTISIG"

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

static void chainIndexMapper_free(chainIndexMapper *cim) {
	if (cim != NULL) {
		KSI_Integer_free(cim->key_index);
		KSI_AggregationHashChain_free(cim->aggrChain);
		chainIndexMapperList_free(cim->children);
		KSI_RFC3161_free(cim->rfc3161);
		KSI_free(cim);
	}
}

static int chainIndexMapper_new(chainIndexMapper **cim) {
	int res = KSI_UNKNOWN_ERROR;

	chainIndexMapper *tmp = NULL;
	tmp = KSI_new(chainIndexMapper);
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

	chainIndexMapper_free(tmp);

	return res;
}

static void timeMapper_free(timeMapper *tm) {
	if (tm != NULL) {
		KSI_Integer_free(tm->key_time);
		chainIndexMapperList_free(tm->chainIndexeList);
		KSI_CalendarHashChain_free(tm->calendarChain);
		KSI_CalendarAuthRec_free(tm->calendarAuthRec);
		KSI_PublicationRecord_free(tm->publication);
		KSI_free(tm);
	}
}

static int timeMapper_new(timeMapper **tm) {
	int res = KSI_UNKNOWN_ERROR;
	timeMapper *tmp = NULL;

	tmp = KSI_new(timeMapper);
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

	timeMapper_free(tmp);

	return res;
}


KSI_IMPLEMENT_LIST(chainIndexMapper, chainIndexMapper_free);
KSI_IMPLEMENT_LIST(timeMapper, timeMapper_free);

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
		timeMapperList_free(ms->timeList);
		KSI_free(ms);
	}
}


static int timeMapperList_select(KSI_LIST(timeMapper) **mapper, KSI_Integer *tm, timeMapper **exact, int create) {
	int res = KSI_UNKNOWN_ERROR;
	timeMapper *hit = NULL;
	timeMapper *hitp = NULL;
	KSI_LIST(timeMapper) *list = NULL;
	KSI_LIST(timeMapper) *listp = NULL;
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
		res = timeMapperList_new(&list);
		if (res != KSI_OK) goto cleanup;

		listp = list;
	}

	for (i = 0; i < timeMapperList_length(listp); i++) {
		timeMapper *ptr = NULL;

		res = timeMapperList_elementAt(listp, i, &ptr);
		if (res != KSI_OK) goto cleanup;

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
		res = timeMapper_new(&hit);
		if (res != KSI_OK) goto cleanup;

		res = KSI_Integer_ref(tm);
		if (res != KSI_OK) goto cleanup;

		hit->key_time = tm;

		res = timeMapperList_append(listp, hit);
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

	timeMapperList_free(list);
	timeMapper_free(hit);

	return res;

}

static int chainIndexMapperList_selectCreate(KSI_LIST(chainIndexMapper) **mapper, KSI_LIST(KSI_Integer) *index, size_t lvl, KSI_LIST(chainIndexMapper) *out, chainIndexMapper **exact) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	KSI_Integer *key = NULL;
	chainIndexMapper *hit = NULL;
	chainIndexMapper *hitp = NULL;
	KSI_LIST(chainIndexMapper) *list = NULL;
	KSI_LIST(chainIndexMapper) *listp = NULL;


	if (mapper == NULL || index == NULL || lvl >= KSI_IntegerList_length(index)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_IntegerList_elementAt(index, lvl, &key);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_ref(key);
	if (res != KSI_OK) goto cleanup;

	listp = *mapper;
	/* Create a new list, if empty. */
	if (listp == NULL) {
		res = chainIndexMapperList_new(&list);
		if (res != KSI_OK) goto cleanup;

		listp = list;
	}

	/* Search for the container with the matching key. */
	for (i = 0; i < chainIndexMapperList_length(listp); i++) {
		chainIndexMapper *ptr = NULL;
		res = chainIndexMapperList_elementAt(listp, i, &ptr);
		if (res != KSI_OK) goto cleanup;

		if (KSI_Integer_equals(ptr->key_index, key)) {
			hitp = ptr;
			break;
		}
	}

	/* Create a new container, if it does not exist. */
	if (hitp == NULL) {
		res = chainIndexMapper_new(&hit);
		if (res != KSI_OK) goto cleanup;

		hit->key_index = key;
		key = NULL;

		res = chainIndexMapperList_append(listp, hit);
		if (res != KSI_OK) goto cleanup;

		hitp = hit;
		hit = NULL;
	}

	/* Add the container to the output result. */
	if (out != NULL) {
		res = chainIndexMapperList_append(out, hitp);
		if (res != KSI_OK) goto cleanup;
	}

	/* Continue search if the chain index continues. */
	if (lvl + 1 < KSI_IntegerList_length(index)) {
		res = chainIndexMapperList_selectCreate(&hitp->children, index, lvl + 1, out, exact);
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

	chainIndexMapperList_free(list);
	chainIndexMapper_free(hit);
	KSI_Integer_free(key);

	return res;
}

static int chainIndexMapperList_select(KSI_LIST(chainIndexMapper) **mapper, KSI_LIST(KSI_Integer) *index, KSI_LIST(chainIndexMapper) **path, chainIndexMapper **exact) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(chainIndexMapper) *list = NULL;

	if (mapper == NULL || index == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (path != NULL) {
		res = chainIndexMapperList_new(&list);
		if (res != KSI_OK) goto cleanup;
	}

	res = chainIndexMapperList_selectCreate(mapper, index, 0, list, exact);
	if (res != KSI_OK) goto cleanup;

	if (path != NULL) {
		*path = list;
		list = NULL;
	}

	res = KSI_OK;

cleanup:

	chainIndexMapperList_free(list);

	return res;
}

static int addAggregationHashChain(KSI_AggregationHashChain *chn, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MultiSignature *ms = fctx;
	timeMapper *tm = NULL;
	chainIndexMapper *last = NULL;

	if (chn == NULL || ms == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ms->ctx);

	/* Select the appropriate time element. */
	res = timeMapperList_select(&ms->timeList, chn->aggregationTime, &tm, 1);
	if (res != KSI_OK) goto cleanup;

	/* Add the element to the container. */
	res = chainIndexMapperList_select(&tm->chainIndexeList, chn->chainIndex, NULL, &last);
	if (res != KSI_OK) {
		KSI_pushError(ms->ctx, res, NULL);
		goto cleanup;
	}

	/* If the aggregation chain is missing from the last node, add it. */
	if (last->aggrChain == NULL) {
		res = KSI_AggregationHashChain_ref(chn);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}
		last->aggrChain = chn;
	} else {
		KSI_LOG_debug(ms->ctx, "Discarding aggregation hash chain, as it is already present.");
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int addRfc3161(KSI_RFC3161 *rfc, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(timeMapper) *tmList = fctx;
	chainIndexMapper *last = NULL;
	timeMapper *tm = NULL;

	if (rfc == NULL || tmList == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = timeMapperList_select(&tmList, rfc->aggregationTime, &tm, 1);
	if (res != KSI_OK) goto cleanup;

	res = chainIndexMapperList_select(&tm->chainIndexeList, rfc->chainIndex, NULL, &last);
	if (res != KSI_OK) {
		KSI_pushError(rfc->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_RFC3161_ref(rfc);
	if (res != KSI_OK) goto cleanup;

	last->rfc3161 = rfc;

	res = KSI_OK;

cleanup:

	return res;
}

static int addCalendarChain(KSI_CalendarHashChain *cal, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(timeMapper) *tmList = fctx;
	timeMapper *calTm = NULL;
	timeMapper *newTm = NULL;
	timeMapper *oldTm = NULL;

	if (cal == NULL || tmList == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}


	res = timeMapperList_select(&tmList, cal->aggregationTime, &calTm, 1);
	if (res != KSI_OK) goto cleanup;

	if (calTm->calendarChain == NULL) {
		/* If the's no calendar chain present. Add it no matter what. */
		KSI_CalendarHashChain_ref(cal);
		calTm->calendarChain = cal;
	} else if (!KSI_Integer_equals(cal->publicationTime, calTm->calendarChain->publicationTime)) {
		bool prefer_newer;
		/* Update the calendar chain only if it has a stronger proof or if equally strong,
		 * use the nearest (oldest). */
		res = timeMapperList_select(&tmList, cal->publicationTime, &newTm, 0);
		if (res != KSI_OK) goto cleanup;

		res = timeMapperList_select(&tmList, calTm->calendarChain->publicationTime, &oldTm, 0);
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
			KSI_CalendarHashChain_ref(cal);
			calTm->calendarChain = cal;
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
	KSI_LIST(timeMapper) *tmList = fctx;
	timeMapper *tm = NULL;

	if (auth == NULL || tmList == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(auth->ctx);

	res = timeMapperList_select(&tmList, auth->pubData->time, &tm, 1);
	if (res != KSI_OK) goto cleanup;

	if (tm->calendarAuthRec == NULL && tm->publication == NULL) {
		res = KSI_CalendarAuthRec_ref(auth);
		if (res != KSI_OK) goto cleanup;

		tm->calendarAuthRec = auth;
	} else {
		KSI_LOG_debug(auth->ctx, "Discarding calendar authentication record, as it is already present.");
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int addPublication(KSI_PublicationRecord *pub, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(timeMapper) *tmList = fctx;
	timeMapper *tm = NULL;

	if (pub == NULL || fctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(pub->ctx);

	res = timeMapperList_select(&tmList, pub->publishedData->time, &tm, 1);
	if (res != KSI_OK) {
		KSI_pushError(pub->ctx, res, NULL);
		goto cleanup;
	}

	if (tm->publication == NULL) {
		res = KSI_PublicationRecord_ref(pub);
		if (res != KSI_OK) {
			KSI_pushError(pub->ctx, res, NULL);
			goto cleanup;
		}

		tm->publication = pub;

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
	KSI_LIST(timeMapper) *ms = fctx;
	timeMapper *tm = NULL;
	chainIndexMapper *last = NULL;

	if (auth == NULL || ms == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(auth->ctx);


	/* Select the appropriate time element. */
	res = timeMapperList_select(&ms, auth->aggregationTime, &tm, 1);
	if (res != KSI_OK) {
		KSI_pushError(auth->ctx, res, NULL);
		goto cleanup;
	}

	/* Add the element to the container. */
	res = chainIndexMapperList_select(&tm->chainIndexeList, auth->chainIndexesList, NULL, &last);
	if (res != KSI_OK) {
		KSI_pushError(auth->ctx, res, NULL);
		goto cleanup;
	}

	if (last->aggrAuthRec == NULL) {
		res = KSI_AggregationAuthRec_ref(auth);
		if (res != KSI_OK) {
			KSI_pushError(auth->ctx, res, NULL);
			goto cleanup;
		}

		last->aggrAuthRec = auth;
	} else {
		KSI_LOG_debug(auth->ctx, "Discarding aggregation auth record, as it already is present.");
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MultiSignature_add(KSI_MultiSignature *ms, const KSI_Signature *sig) {
	int res = KSI_UNKNOWN_ERROR;
	timeMapper *mpr = NULL;

	size_t i;

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

static int findAggregationHashChainList(KSI_LIST(chainIndexMapper) *cimList, const KSI_DataHash *hsh, KSI_LIST(KSI_AggregationHashChain) *aggList) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	chainIndexMapper *cim = NULL;

	if (hsh == NULL || aggList == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	for (i = 0; i < chainIndexMapperList_length(cimList); i++) {
		res = chainIndexMapperList_elementAt(cimList, i, &cim);
		if (res != KSI_OK) goto cleanup;

		if (cim->aggrChain == NULL) {
			/* When there is no calendar chain, there are no siblings containing a chain either. */
			continue;
		}

		if (KSI_DataHash_equals(cim->aggrChain->inputHash, hsh)) {
			res = KSI_AggregationHashChain_ref(cim->aggrChain);
			if (res != KSI_OK) goto cleanup;

			res = KSI_AggregationHashChainList_append(aggList, cim->aggrChain);
			if (res != KSI_OK) goto cleanup;

			break;
		}

		/* Search for sub elements. */
		if (chainIndexMapperList_length(cim->children) > 0) {
			res = findAggregationHashChainList(cim->children, hsh, aggList);
			if (res != KSI_OK) goto cleanup;

			if (KSI_AggregationHashChainList_length(aggList) > 0) {
				res = KSI_AggregationHashChain_ref(cim->aggrChain);
				if (res != KSI_OK) goto cleanup;

				res = KSI_AggregationHashChainList_append(aggList, cim->aggrChain);
				if (res != KSI_OK) goto cleanup;

				break;
			}
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int findAggregationHashChain(KSI_LIST(timeMapper) *tmList, const KSI_DataHash *hsh, timeMapper **mapper, KSI_LIST(KSI_AggregationHashChain) **aggrList) {
	int res = KSI_SERVICE_UNKNOWN_ERROR;
	size_t i;
	timeMapper *tm = NULL;
	KSI_LIST(KSI_AggregationHashChain) *agl = NULL;

	if (hsh == NULL || mapper == NULL || aggrList == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_AggregationHashChainList_new(&agl);
	if (res != KSI_OK) goto cleanup;

	for (i = 0; i < timeMapperList_length(tmList); i++) {
		res = timeMapperList_elementAt(tmList, i, &tm);
		if (res != KSI_OK) goto cleanup;

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

static int timeMapper_cmp(const timeMapper **a, const timeMapper **b) {
	/* NB! We assume a and b are not NULL - otherwise, there is something wrong with
	 * the container. Null checks added only for safety. */
	return (*a == NULL || *b == NULL) ? 0 : KSI_Integer_compare((*a)->key_time, (*b)->key_time);
}

int KSI_MultiSignature_get(KSI_MultiSignature *ms, const KSI_DataHash *hsh, KSI_Signature **sig) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Signature *tmp = NULL;
	chainIndexMapper *cim = NULL;
	KSI_LIST(chainIndexMapper) *cimList = NULL;
	timeMapper *tm = NULL;
	size_t i;

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
	tmp->aggregationAuthRec = NULL;
	tmp->aggregationChainList = NULL;
	tmp->baseTlv = NULL;
	tmp->calendarAuthRec = NULL;
	tmp->calendarChain = NULL;
	tmp->publication = NULL;
	tmp->rfc3161 = NULL;
	memset(&tmp->verificationResult, 0, sizeof(tmp->verificationResult));

	/* If the list is not ordered, order it, to find always the earliest signature possible. This
	 * is an issue if there are more than one signatures for the same inputhash. */
	if (!ms->timeList_ordered && ms->timeList != NULL) {
		res = timeMapperList_sort(ms->timeList, timeMapper_cmp);
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
		timeMapper *proof = NULL;

		/* Make a reference. */
		KSI_CalendarHashChain_ref(tmp->calendarChain);
		/* Find proof. */
		res = timeMapperList_select(&ms->timeList, tmp->calendarChain->publicationTime, &proof, 0);
		if (res != KSI_OK) goto cleanup;

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
static int chainIndexMapperList_vacuum(KSI_LIST(chainIndexMapper) *cimList) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	for (i = chainIndexMapperList_length(cimList); i > 0; i--) {
		chainIndexMapper *cim = NULL;

		res = chainIndexMapperList_elementAt(cimList, i - 1, &cim);
		if (res != KSI_OK) goto cleanup;

		/* Check if the chain index mapper should be removed. */
		if ((cim->aggrAuthRec == NULL && cim->aggrChain == NULL) || (cim->children != NULL && chainIndexMapperList_length(cim->children) == 0)) {
			res = chainIndexMapperList_remove(cimList, i - 1, NULL);
			if (res != KSI_OK) goto cleanup;
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int timeMapper_unpaint(timeMapper *tm, void *foldCtx) {
	if (tm == NULL) return KSI_INVALID_ARGUMENT;
	tm->paint = false;
	return KSI_OK;
}

static int chainIndexMapper_deleteSignature(chainIndexMapper *cim, void *foldCtx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = foldCtx;

	if (cim == NULL || foldCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Deletion should be performed only on leafs. */
	if (cim->children != NULL) {
		/* Intermediate node. */
		res = chainIndexMapperList_foldl(cim->children, foldCtx, chainIndexMapper_deleteSignature);
		if (res != KSI_OK) goto cleanup;
		res = chainIndexMapperList_vacuum(cim->children);

	} else {
		/* Leaf node. */
		if (cim->aggrChain != NULL && KSI_DataHash_equals(cim->aggrChain->inputHash, hsh)) {
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

static int timeMapper_deleteSignature(timeMapper *tm, void *foldCtx) {
	int res = KSI_UNKNOWN_ERROR;

	res = chainIndexMapperList_foldl(tm->chainIndexeList, foldCtx, chainIndexMapper_deleteSignature);
	if (res != KSI_OK) goto cleanup;

	res = chainIndexMapperList_vacuum(tm->chainIndexeList);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static int timeMapper_markUsedCalendarChains(timeMapper *tm, void *foldCtx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(timeMapper) *tmList = foldCtx;
	size_t i;

	if (tm == NULL || foldCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
	}

	for (i = 0; i < chainIndexMapperList_length(tm->chainIndexeList); i++) {
		chainIndexMapper *cim = NULL;
		timeMapper *calTm = NULL;
		res = chainIndexMapperList_elementAt(tm->chainIndexeList, i, &cim);
		if (res != KSI_OK) goto cleanup;

		if (cim->aggrChain != NULL) {
			res = timeMapperList_select(&tmList, cim->aggrChain->aggregationTime, &calTm, 0);
			if (res != KSI_OK) goto cleanup;

			if (calTm == NULL) {
				res = KSI_MULTISIG_INVALID_STATE;
				goto cleanup;
			}

			calTm->paint = true;
		}

		if (cim->rfc3161 != NULL) {
			res = timeMapperList_select(&tmList, cim->rfc3161->aggregationTime, &calTm, 0);
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

static int timeMapper_markUsedProofs(timeMapper *tm, void *foldCtx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(timeMapper) *tmList = foldCtx;
	size_t i;

	if (tm == NULL || foldCtx == NULL) {
		res = KSI_INVALID_ARGUMENT;
	}

	/* Exit if this element is not painted. */
	if (!tm->paint) return KSI_OK;

	if (tm->calendarChain != NULL) {
		timeMapper *pubTm = NULL;

		res = timeMapperList_select(&tmList,  tm->calendarChain->publicationTime, &pubTm, 0);
		if (res != KSI_OK) goto cleanup;

		if (pubTm->calendarAuthRec != NULL || pubTm->publication != NULL) {
			pubTm->paint = true;
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int timeMapperList_vacuum(KSI_LIST(timeMapper) *tmList) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	for (i = timeMapperList_length(tmList); i > 0; i--) {
		timeMapper *tm = NULL;
		res = timeMapperList_elementAt(tmList, i - 1, &tm);
		if (res != KSI_OK) goto cleanup;

		if (!tm->paint && chainIndexMapperList_length(tm->chainIndexeList) == 0) {
			res = timeMapperList_remove(tmList, i - 1, NULL);
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

	res = timeMapperList_foldl(ms->timeList, (void *)hsh, timeMapper_deleteSignature);
	if (res != KSI_OK) {
		KSI_pushError(ms->ctx, res, NULL);
		goto cleanup;
	}

	/* Cleanup. */

	/* Reset the paint markers. */
	res = timeMapperList_foldl(ms->timeList, NULL, timeMapper_unpaint);
	if (res != KSI_OK) goto cleanup;

	/* Mark all the used calendar chains. */
	res = timeMapperList_foldl(ms->timeList, ms->timeList, timeMapper_markUsedCalendarChains);
	if (res != KSI_OK) goto cleanup;

	/* Mark all the proofs used by the marked calendars. */
	res = timeMapperList_foldl(ms->timeList, ms->timeList, timeMapper_markUsedProofs);
	if (res != KSI_OK) goto cleanup;

	res = timeMapperList_vacuum(ms->timeList);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

struct hash_finder_st {
	bool used[KSI_NUMBER_OF_KNOWN_HASHALGS];
};

static int chainIndexMapper_findAlgos(chainIndexMapper *ciMap, void *fc) {
	int res = KSI_UNKNOWN_ERROR;
	struct hash_finder_st *foldCtx = fc;

	if (ciMap != NULL) {
		if (chainIndexMapperList_length(ciMap->children) > 0) {
			res = chainIndexMapperList_foldl(ciMap->children, foldCtx, chainIndexMapper_findAlgos);
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


static int timeMapper_findAlgos(timeMapper *tmMap, void *foldCtx) {
	int res = KSI_UNKNOWN_ERROR;

	if (tmMap != NULL) {
		res = chainIndexMapperList_foldl(tmMap->chainIndexeList, foldCtx, chainIndexMapper_findAlgos);
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

	res = timeMapperList_foldl(ms->timeList, &used, timeMapper_findAlgos);
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

static int extendUnextended(timeMapper *tm, void *fctx) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(timeMapper) *tmList = fctx;
	KSI_RequestHandle *handle = NULL;
	KSI_ExtendReq *req = NULL;
	KSI_ExtendResp *resp = NULL;
	KSI_Integer *aggregationTime = NULL;
	KSI_Integer *publicationTime = NULL;

	if (tm == NULL || tmList == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Handle only calendar chains. */
	if (tm->calendarChain != NULL) {
		timeMapper *proof = NULL;
		res = timeMapperList_select(&tmList, tm->calendarChain->publicationTime, &proof, 0);
		if (res != KSI_OK) goto cleanup;

		if (proof->publication == NULL) {
			KSI_PublicationsFile *pubFile = NULL;
			KSI_PublicationRecord *pubRec = NULL;
			/* As there is no publication attached, try to find suitable publication. */
			res = KSI_receivePublicationsFile(tm->calendarChain->ctx, &pubFile);
			if (res != KSI_OK) goto cleanup;

			res = KSI_PublicationsFile_getNearestPublication(pubFile, tm->calendarChain->publicationTime, &pubRec);
			if (res != KSI_OK) goto cleanup;

			/* Only continue, if there is such a publication available. */
			if (pubRec != NULL) {
				KSI_CalendarHashChain *chn = NULL;

				res = addPublication(pubRec, tmList);
				if (res != KSI_OK) goto cleanup;

				res = KSI_ExtendReq_new(tm->calendarChain->ctx, &req);
				if (res != KSI_OK) goto cleanup;

				KSI_Integer_ref(aggregationTime = tm->calendarChain->aggregationTime);
				KSI_Integer_ref(publicationTime = pubRec->publishedData->time);

				KSI_ExtendReq_setAggregationTime(req, aggregationTime);
				KSI_ExtendReq_setPublicationTime(req, publicationTime);

				res = KSI_sendExtendRequest(tm->calendarChain->ctx, req, &handle);
				if (res != KSI_OK) goto cleanup;

				res = KSI_RequestHandle_getExtendResponse(handle, &resp);
				if (res != KSI_OK) goto cleanup;

				res = KSI_ExtendResp_getCalendarHashChain(resp, &chn);
				if (res != KSI_OK) goto cleanup;

				res = addCalendarChain(chn, tmList);
				if (res != KSI_OK) goto cleanup;
			}
		}
	}

	res = KSI_OK;

cleanup:

	KSI_RequestHandle_free(handle);
	KSI_ExtendReq_free(req);
	KSI_ExtendResp_free(resp);

	return res;
}

int KSI_MultiSignature_extend(KSI_MultiSignature *ms) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	if (ms == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ms->ctx);

	res = timeMapperList_foldl(ms->timeList, ms->timeList, extendUnextended);
	if (res != KSI_OK) {
		KSI_pushError(ms->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MultiSignature_extendToPublication(KSI_MultiSignature *ms, const KSI_PublicationRecord *pubRec) {
	int res = KSI_UNKNOWN_ERROR;

	res = KSI_OK;

cleanup:

	return res;
}

static int chainIndexMapper_writeBytes(KSI_LIST(chainIndexMapper) *cimList, unsigned char *buf, size_t buf_size, size_t *buf_len) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	size_t len = 0;
	size_t tmp_len;

	if ((buf == NULL && buf_size != 0) || buf_len == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	for (i = chainIndexMapperList_length(cimList); i > 0; i--) {
		chainIndexMapper *cim = NULL;
		res = chainIndexMapperList_elementAt(cimList, i - 1, &cim);
		if (res != KSI_OK) goto cleanup;

		/* Write the children. */
		res = chainIndexMapper_writeBytes(cim->children, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len);
		if (res != KSI_OK) goto cleanup;

		len += tmp_len;
		if (buf != NULL && len >= buf_size) {
			res = KSI_BUFFER_OVERFLOW;
			goto cleanup;
		}

		if (cim->aggrChain != NULL) {
			res = KSI_AggregationHashChain_writeBytes(cim->aggrChain, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len, KSI_TLV_OPT_NO_MOVE);
			if (res != KSI_OK) goto cleanup;

			len += tmp_len;
			if (buf != NULL && len >= buf_size) {
				res = KSI_BUFFER_OVERFLOW;
				goto cleanup;
			}
		}

		if (cim->aggrAuthRec != NULL) {
			res = KSI_AggregationAuthRec_writeBytes(cim->aggrAuthRec, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len, KSI_TLV_OPT_NO_MOVE);
			if (res != KSI_OK) goto cleanup;

			len += tmp_len;
			if (buf != NULL && len >= buf_size) {
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
	size_t i, j;

	if (ms == NULL || (buf == NULL && buf_size != 0) || buf_len == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(ms->ctx);

	for (i = 0; i < timeMapperList_length(ms->timeList); i++) {
		timeMapper *tm = NULL;
		size_t tmp_len;

		res = timeMapperList_elementAt(ms->timeList, i, &tm);
		if (res != KSI_OK) goto cleanup;

		if (tm->calendarAuthRec != NULL) {

			/* Write the bytes to the end of the buffer. */
			res = KSI_CalendarAuthRec_writeBytes(tm->calendarAuthRec, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len, KSI_TLV_OPT_NO_MOVE);
			if (res != KSI_OK) {
				KSI_pushError(ms->ctx, res, NULL);
				goto cleanup;
			}

			len += tmp_len;
			/* Just to be sure - should never happen. */
			if (buf != NULL & len >= buf_size) {
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
			if (buf != NULL && len >= buf_size) {
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
			if (buf != NULL && len >= buf_size) {
				KSI_pushError(ms->ctx, res = KSI_BUFFER_OVERFLOW, NULL);
				goto cleanup;
			}
		}

		res = chainIndexMapper_writeBytes(tm->chainIndexeList, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}

		len += tmp_len;
		/* Just to be sure - should never happen. */
		if (buf != NULL && len >= buf_size) {
			KSI_pushError(ms->ctx, res = KSI_BUFFER_OVERFLOW, NULL);
			goto cleanup;
		}
	}

	if ((opt & KSI_TLV_OPT_NO_HEADER) == 0) {
		size_t hdr_len = strlen(KSI_MULTI_SIGNATURE_HDR);
		len += hdr_len;

		if (buf != NULL) {
			if (len + hdr_len >= buf_size) {
				KSI_pushError(ms->ctx, res = KSI_BUFFER_OVERFLOW, NULL);
				goto cleanup;
			}

			memcpy(buf + buf_size - len, KSI_MULTI_SIGNATURE_HDR, hdr_len);
		}
	}

	if ((opt & KSI_TLV_OPT_NO_MOVE) == 0 && buf != NULL) {
		for (i = 0; i < len; i++) {
			buf[i] = buf[buf_size - len + i];
		}

		if (len < 0xffff) {
			KSI_LOG_logBlob(ms->ctx, KSI_LOG_DEBUG, "Serialized multi signature container", buf, len);
		}
	}

	*buf_len = len;

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

	if (hlpr->ptr_len > 0) {
		size_t tlv_len;
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

	*tlv = hlpr->tlv;
	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MultiSignature_parse(KSI_CTX *ctx, const unsigned char *raw, size_t raw_len, KSI_MultiSignature **ms) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MultiSignature *tmp = NULL;
	ParserHelper hlpr;
	size_t len;
	size_t hdr_len;

	hlpr = (ParserHelper) {ctx, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
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

	if (strncmp(raw, KSI_MULTI_SIGNATURE_HDR, hdr_len)) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Multi signature container magic number mismatch.");
		goto cleanup;
	}

	hlpr.ptr = raw + hdr_len;
	hlpr.ptr_len = raw_len - hdr_len;

	res = KSI_TlvTemplate_extractGenerator(ctx, &hlpr, &hlpr, KSI_TLV_TEMPLATE(ParserHelper), parserGenerator);
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
	res = KSI_AggregationHashChainList_foldl(hlpr.aggregationChainList, tmp, addAggregationHashChain);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add all the publications to the container. */
	res = KSI_PublicationRecordList_foldl(hlpr.publicationRecordList, tmp->timeList, addPublication);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add all the calendar auth records to the container. */
	res = KSI_CalendarAuthRecList_foldl(hlpr.calendarAuthRecordList, tmp->timeList, addCalendarAuthRec);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add all the calendar hash chains to the container.
	 * NB! It is essential that the publications and calendar auth records are processed by now. */
	res = KSI_CalendarHashChainList_foldl(hlpr.calendarChainList, tmp->timeList, addCalendarChain);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add all the aggregation auth records to the container. */
	res = KSI_AggregationAuthRecList_foldl(hlpr.aggregationAuthRecordList, tmp->timeList, addAggregationAuthRec);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Add all the rfc3161 elements to the container. */
	res = KSI_RFC3161List_foldl(hlpr.rfc3161List, tmp->timeList, addRfc3161);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*ms = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_MultiSignature_free(tmp);
	KSI_AggregationHashChainList_free(hlpr.aggregationChainList);
	KSI_CalendarHashChainList_free(hlpr.calendarChainList);
	KSI_PublicationRecordList_free(hlpr.publicationRecordList);
	KSI_AggregationAuthRecList_free(hlpr.aggregationAuthRecordList);
	KSI_CalendarAuthRecList_free(hlpr.calendarAuthRecordList);
	KSI_RFC3161List_free(hlpr.rfc3161List);
	KSI_TLV_free(hlpr.tlv);

	return res;
}


