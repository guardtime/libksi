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

#define KSI_MULTI_SIGNATURE_HDR "MULTISIG"

KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationHashChain);
KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarHashChain);
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationAuthRec);
KSI_IMPORT_TLV_TEMPLATE(KSI_CalendarAuthRec);
KSI_IMPORT_TLV_TEMPLATE(KSI_RFC3161);

typedef struct ParserHelper_st {
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

KSI_DEFINE_TLV_TEMPLATE(KSI_MultiSignature)
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
		KSI_CalendarHashChainList_free(tm->calendarChainList);
		KSI_CalendarAuthRec_free(tm->calendarAuthRec);
		KSI_PublicationRecord_free(tm->pubRec);
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
	tmp->calendarChainList = NULL;
	tmp->calendarAuthRec = NULL;
	tmp->pubRec = NULL;

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

static int addCalendarChain(KSI_LIST(KSI_CalendarHashChain) **list, KSI_CalendarHashChain *chn) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_LIST(KSI_CalendarHashChain) *tmp = NULL;
	KSI_LIST(KSI_CalendarHashChain) *ptr = NULL;
	size_t i;

	if (list == NULL || chn == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ptr = *list;

	/* Check if the entry exists in the list. */
	for (i = 0; i < KSI_CalendarHashChainList_length(ptr); i++) {
		KSI_CalendarHashChain *c = NULL;
		res = KSI_CalendarHashChainList_elementAt(ptr, i, &c);
		if (res != KSI_OK) goto cleanup;

		if (KSI_Integer_equals(chn->aggregationTime, c->aggregationTime) && KSI_Integer_equals(chn->publicationTime, c->publicationTime)) {
			res = KSI_OK;
			goto cleanup;
		}
	}

	if (ptr == NULL) {
		res = KSI_CalendarHashChainList_new(&tmp);
		if (res != KSI_OK) goto cleanup;

		ptr = tmp;
	}

	res = KSI_CalendarHashChain_ref(chn);
	if (res != KSI_OK) goto cleanup;

	res = KSI_CalendarHashChainList_append(ptr, chn);
	if (res != KSI_OK) goto cleanup;

	if (tmp != NULL) {
		*list = tmp;
		tmp = NULL;
	}

	res = KSI_OK;

cleanup:

	KSI_CalendarHashChainList_free(tmp);

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
	for (i = 0; i < KSI_AggregationHashChainList_length(sig->aggregationChainList); i++) {
		KSI_AggregationHashChain *tmp = NULL;
		chainIndexMapper *last = NULL;

		/* Get a pointer to the current aggregation hash chain. */
		res = KSI_AggregationHashChainList_elementAt(sig->aggregationChainList, i, &tmp);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}

		/* Select the appropriate time element. */
		res = timeMapperList_select(&ms->timeList, tmp->aggregationTime, &mpr, 1);
		if (res != KSI_OK) goto cleanup;

		/* Add the element to the container. */
		res = chainIndexMapperList_select(&mpr->chainIndexeList, tmp->chainIndex, NULL, &last);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}

		if (last->aggrChain == NULL) {
			res = KSI_AggregationHashChain_ref(tmp);
			if (res != KSI_OK) {
				KSI_pushError(ms->ctx, res, NULL);
				goto cleanup;
			}
			last->aggrChain = tmp;
		} else {
			KSI_LOG_debug(ms->ctx, "Discarding aggregation hash chain, as it is already present.");
		}
	}

	/* Add the rfc3161 element. */
	if (sig->rfc3161 != NULL) {
		chainIndexMapper *last = NULL;

		res = timeMapperList_select(&ms->timeList, sig->rfc3161->aggregationTime, &mpr, 1);
		if (res != KSI_OK) goto cleanup;

		res = chainIndexMapperList_select(&mpr->chainIndexeList, sig->rfc3161->chainIndex, NULL, &last);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_RFC3161_ref(sig->rfc3161);
		if (res != KSI_OK) goto cleanup;

		last->rfc3161 = sig->rfc3161;
	}

	/* Add the calendar chain. */
	if (sig->calendarChain != NULL) {
		res = timeMapperList_select(&ms->timeList, sig->calendarChain->aggregationTime, &mpr, 1);
		if (res != KSI_OK) goto cleanup;

		res = addCalendarChain(&mpr->calendarChainList, sig->calendarChain);
		if (res != KSI_OK) goto cleanup;
	}

	/* Add the calendar auth record. */
	if (sig->calendarAuthRec != NULL) {
		res = timeMapperList_select(&ms->timeList, sig->calendarAuthRec->pubData->time, &mpr, 1);
		if (res != KSI_OK) goto cleanup;

		if (mpr->calendarAuthRec == NULL) {
			res = KSI_CalendarAuthRec_ref(sig->calendarAuthRec);
			if (res != KSI_OK) goto cleanup;

			mpr->calendarAuthRec = sig->calendarAuthRec;
		} else {
			KSI_LOG_debug(sig->ctx, "Discarding calendar authentication record, as it is already present.");
		}
	}

	/* Add the publication. */
	if (sig->publication != NULL) {
		res = timeMapperList_select(&ms->timeList, sig->publication->publishedData->time, &mpr, 1);
		if (res != KSI_OK) goto cleanup;

		if (mpr->pubRec == NULL) {
			res = KSI_PublicationRecord_ref(sig->publication);
			if (res != KSI_OK) goto cleanup;

			mpr->pubRec = sig->publication;
		} else {
			char buf[256];
			/* TODO! We could try merging the publication records instead. */
			KSI_LOG_debug(sig->ctx, "Discarding publication as a value already present: %s", KSI_PublicationRecord_toString(sig->publication, buf, sizeof(buf)));
		}
	}

	/* Add the aggregation auth record. */
	if (sig->aggregationAuthRec != NULL) {
		chainIndexMapper *last = NULL;

		/* Select the appropriate time element. */
		res = timeMapperList_select(&ms->timeList, sig->aggregationAuthRec->aggregationTime, &mpr, 1);
		if (res != KSI_OK) goto cleanup;

		/* Add the element to the container. */
		res = chainIndexMapperList_select(&mpr->chainIndexeList, sig->aggregationAuthRec->chainIndexesList, NULL, &last);
		if (res != KSI_OK) {
			KSI_pushError(ms->ctx, res, NULL);
			goto cleanup;
		}

		if (last->aggrAuthRec == NULL) {
			last->aggrAuthRec = sig->aggregationAuthRec;
		} else {
			KSI_LOG_debug(sig->ctx, "Discarding aggregation auth record, as it already is present.");
		}
	}

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

	for (i = 0; i < KSI_CalendarHashChainList_length(tm->calendarChainList); i++) {
		KSI_CalendarHashChain *cal = NULL;
		timeMapper *proof = NULL;

		res = KSI_CalendarHashChainList_elementAt(tm->calendarChainList, i, &cal);
		if (res != KSI_OK) goto cleanup;

		if (tmp->calendarChain == NULL) {
			res = KSI_CalendarHashChain_ref(cal);
			if (res != KSI_OK) goto cleanup;

			tmp->calendarChain = cal;
		}

		/* Find proof. */
		res = timeMapperList_select(&ms->timeList, cal->publicationTime, &proof, 0);
		if (res != KSI_OK) goto cleanup;

		if (proof == NULL) continue;

		if (tmp->publication == NULL && proof->pubRec != NULL) {
			/* Update calendar chain, if different. */
			if (!KSI_Integer_equals(proof->pubRec->publishedData->time, tmp->calendarChain->publicationTime)) {
				res = KSI_CalendarHashChain_ref(cal);
				if (res != KSI_OK) goto cleanup;

				KSI_CalendarHashChain_free(tmp->calendarChain);
				tmp->calendarChain = cal;
			}
			/* We've found an actual publication. */
			res = KSI_PublicationRecord_ref(proof->pubRec);
			if (res != KSI_OK) goto cleanup;
			tmp->publication = proof->pubRec;

			/* Remove the calendar auth record, if any. */
			KSI_CalendarAuthRec_free(tmp->calendarAuthRec);
			tmp->calendarAuthRec = NULL;

			/* Stop searching. */
			break;
		} else if (tmp->publication == NULL && tmp->calendarAuthRec == NULL && proof->calendarAuthRec != NULL) {
			/* Update calendar chain, if different. */
			if (!KSI_Integer_equals(proof->calendarAuthRec->pubData->time, tmp->calendarChain->publicationTime)) {
				res = KSI_CalendarHashChain_ref(cal);
				if (res != KSI_OK) goto cleanup;

				KSI_CalendarHashChain_free(tmp->calendarChain);
				tmp->calendarChain = cal;
			}

			res = KSI_CalendarAuthRec_ref(proof->calendarAuthRec);
			if  (res != KSI_OK) goto cleanup;

			tmp->calendarAuthRec = proof->calendarAuthRec;
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

	for (i = 0; i < KSI_CalendarHashChainList_length(tm->calendarChainList); i++) {
		KSI_CalendarHashChain *cal = NULL;
		timeMapper *pubTm = NULL;
		res = KSI_CalendarHashChainList_elementAt(tm->calendarChainList, i, &cal);
		if (res != KSI_OK) goto cleanup;

		res = timeMapperList_select(&tmList, cal->publicationTime, &pubTm, 0);
		if (res != KSI_OK) goto cleanup;

		if (pubTm == NULL) {
			res = KSI_MULTISIG_INVALID_STATE;
			goto cleanup;
		}

		if (pubTm->calendarAuthRec != NULL || pubTm->pubRec != NULL) {
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

int KSI_MultiSignature_extend(KSI_MultiSignature *ms) {
	int res = KSI_UNKNOWN_ERROR;

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

		if (tm->pubRec != NULL) {
			/* Write the bytes to the end of the buffer. */
			res = KSI_PublicationRecord_writeBytes(tm->pubRec, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len, KSI_TLV_OPT_NO_MOVE);
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

		for (j = KSI_CalendarHashChainList_length(tm->calendarChainList); j > 0; j--) {
			KSI_CalendarHashChain *ch = NULL;
			res = KSI_CalendarHashChainList_elementAt(tm->calendarChainList, j - 1, &ch);
			if (res != KSI_OK) {
				KSI_pushError(ms->ctx, res, NULL);
				goto cleanup;
			}

			res = KSI_CalendarHashChain_writeBytes(ch, buf, (buf == NULL ? 0 : buf_size - len), &tmp_len, KSI_TLV_OPT_NO_MOVE);
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
	}

	*buf_len = len;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MultiSignature_parse(KSI_CTX *ctx, unsigned char *raw, size_t raw_len, KSI_MultiSignature **ms) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || raw == NULL || raw_len == 0 || ms == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}


