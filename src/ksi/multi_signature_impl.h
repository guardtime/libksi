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

#ifndef MULTI_SIGNATURE_IMPL_H_
#define MULTI_SIGNATURE_IMPL_H_

#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef struct ChainIndexMapper_st ChainIndexMapper;
	typedef struct TimeMapper_st TimeMapper;

	KSI_DEFINE_LIST(ChainIndexMapper);
#define ChainIndexMapperList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->append((lst), (o)))
#define ChainIndexMapperList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->removeElement((lst), (pos), (o)))
#define ChainIndexMapperList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), (lst)->indexOf((lst), (o), (i)))
#define ChainIndexMapperList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->insertAt((lst), (pos), (o)))
#define ChainIndexMapperList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->replaceAt((lst), (pos), (o)))
#define ChainIndexMapperList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->elementAt((lst), (pos), (o)))
#define ChainIndexMapperList_length(lst) (((lst) != NULL) ? (lst)->length((lst)) : 0)
#define ChainIndexMapperList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), (lst)->sort((lst), (cmp)))
#define ChainIndexMapperList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (lst)->foldl((lst), (foldCtx), (foldFn)) : KSI_OK)

	KSI_DEFINE_LIST(TimeMapper);
#define TimeMapperList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->append((lst), (o)))
#define TimeMapperList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->removeElement((lst), (pos), (o)))
#define TimeMapperList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), (lst)->indexOf((lst), (o), (i)))
#define TimeMapperList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->insertAt((lst), (pos), (o)))
#define TimeMapperList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->replaceAt((lst), (pos), (o)))
#define TimeMapperList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), (lst)->elementAt((lst), (pos), (o)))
#define TimeMapperList_length(lst) (((lst) != NULL) ? (lst)->length((lst)) : 0)
#define TimeMapperList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), (lst)->sort((lst), (cmp)))
#define TimeMapperList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (lst)->foldl((lst), (foldCtx), (foldFn)) : KSI_OK)

	struct ChainIndexMapper_st {
		/** Part of the chain index. */
		KSI_Integer *key_index;

		/** Aggregation hash chain. */
		KSI_AggregationHashChain *aggrChain;

		/** Child elements (with a longer chain index). */
		KSI_LIST(ChainIndexMapper) *children;

		/** Aggregation authentication record for this chain index. */
		KSI_AggregationAuthRec *aggrAuthRec;

		KSI_RFC3161 *rfc3161;
	};

	struct TimeMapper_st {
		/** Time value. */
		KSI_Integer *key_time;

		/** Chain index container for this concrete round. */
		KSI_LIST(ChainIndexMapper) *chainIndexeList;

		/** Calendar hash chain starting at this round, */
		KSI_CalendarHashChain *calendarChain;

		/** Calendar auth record for calendar chain ending on this round. */
		KSI_CalendarAuthRec *calendarAuthRec;

		/** Publication record for this round. */
		KSI_PublicationRecord *publication;

		/** A flag for "painting" the instance for cleanup purpuses. */
		bool paint;

	};

	struct KSI_MultiSignature_st {
		KSI_CTX *ctx;
		bool timeList_ordered;
		KSI_LIST(TimeMapper) *timeList;
	};

#ifdef __cplusplus
}
#endif

#endif /* MULTI_SIGNATURE_IMPL_H_ */
