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

#ifndef SIGNATURE_IMPL_H_
#define SIGNATURE_IMPL_H_

#include "verification.h"
#include "verification_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_CalendarAuthRec_st {
		KSI_CTX *ctx;
		size_t ref;

		KSI_PublicationData *pubData;
		KSI_PKISignedData *signatureData;
	};

	struct KSI_AggregationAuthRec_st {
		KSI_CTX *ctx;
		size_t ref;

		KSI_Integer *aggregationTime;
		KSI_LIST(KSI_Integer) *chainIndexesList;
		KSI_DataHash *inputHash;

		KSI_PKISignedData *signatureData;
	};

	struct KSI_AggregationHashChain_st {
		KSI_CTX *ctx;
		size_t ref;

		KSI_Integer *aggregationTime;
		KSI_LIST(KSI_Integer) *chainIndex;
		KSI_OctetString *inputData;
		KSI_DataHash *inputHash;
		KSI_Integer *aggrHashId;
		KSI_LIST(KSI_HashChainLink) *chain;
	};

	struct KSI_RFC3161_st {
		KSI_CTX *ctx;
		size_t ref;

		KSI_Integer *aggregationTime;
		KSI_LIST(KSI_Integer) *chainIndex;
		KSI_DataHash *inputHash;

		KSI_OctetString *tstInfoPrefix;
		KSI_OctetString *tstInfoSuffix;
		KSI_Integer *tstInfoAlgo;

		KSI_OctetString *sigAttrPrefix;
		KSI_OctetString *sigAttrSuffix;
		KSI_Integer *sigAttrAlgo;
	};

	/**
	 * KSI Signature object
	 */
	struct KSI_Signature_st {
		/** KSI context. */
		KSI_CTX *ctx;
		/** Base TLV - when serialized, this value will be used. */
		KSI_TLV *baseTlv;
		/** Calendar hash chain. */
		KSI_CalendarHashChain *calendarChain;
		/** List of aggregation hash chains. */
		KSI_LIST(KSI_AggregationHashChain) *aggregationChainList;
		/** Legacy RFC3161 signature first aggregation hash chain. */
		KSI_RFC3161 *rfc3161;
		/** Calendar auth record. */
		KSI_CalendarAuthRec *calendarAuthRec;
		/** Aggregation auth record. */
		KSI_AggregationAuthRec *aggregationAuthRec;
		/** Publication record. */
		KSI_PublicationRecord *publication;
		/** Verification info for the signature. */
		KSI_VerificationResult verificationResult;
		/** This function replaces the calendar chain of the signature.
		 * \note The function does not check the internal consistency! */
		int (*replaceCalendarChain)(KSI_Signature *sig, KSI_CalendarHashChain *calendarHashChain);
	};


#ifdef __cplusplus
}
#endif

#endif /* SIGNATURE_IMPL_H_ */
