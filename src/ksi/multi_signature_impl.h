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

	typedef struct chainIndexMapper_st chainIndexMapper;
	typedef struct timeMapper_st timeMapper;

	KSI_DEFINE_LIST(chainIndexMapper);
	KSI_DEFINE_LIST(timeMapper);

	struct chainIndexMapper_st {
		/** Part of the chain index. */
		KSI_Integer *key_index;

		/** Aggregation hash chain. */
		KSI_AggregationHashChain *aggrChain;

		/** Child elements (with a longer chain index). */
		KSI_LIST(chainIndexMapper) *children;

		/** Aggregation authentication record for this chain index. */
		KSI_AggregationAuthRec *aggrAuthRec;

		KSI_RFC3161 *rfc3161;
	};

	struct timeMapper_st {
		/** Time value. */
		KSI_Integer *key_time;

		/** Chain index container for this concrete round. */
		KSI_LIST(chainIndexMapper) *chainIndexeList;

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
		KSI_LIST(timeMapper) *timeList;
	};

#ifdef __cplusplus
}
#endif

#endif /* MULTI_SIGNATURE_IMPL_H_ */
