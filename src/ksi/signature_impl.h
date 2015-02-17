/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#ifndef SIGNATURE_IMPL_H_
#define SIGNATURE_IMPL_H_

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_CalendarAuthRec_st {
		KSI_CTX *ctx;

		KSI_TLV *pubDataTlv;
		KSI_PublicationData *pubData;
		KSI_PKISignedData *signatureData;
	};

	struct KSI_AggregationAuthRec_st {
		KSI_CTX *ctx;
		KSI_Integer *aggregationTime;
		KSI_LIST(KSI_Integer) *chainIndexesList;
		KSI_DataHash *inputHash;

		KSI_PKISignedData *signatureData;
	};

	struct KSI_AggregationHashChain_st {
		KSI_CTX *ctx;
		KSI_Integer *aggregationTime;
		KSI_LIST(KSI_Integer) *chainIndex;
		KSI_OctetString *inputData;
		KSI_DataHash *inputHash;
		KSI_Integer *aggrHashId;
		KSI_LIST(KSI_HashChainLink) *chain;
	};

	/**
	 * KSI Signature object
	 */
	struct KSI_Signature_st {
		KSI_CTX *ctx;

		/* Base TLV - when serialized, this value will be used. */
		KSI_TLV *baseTlv;

		KSI_CalendarHashChain *calendarChain;

		KSI_LIST(KSI_AggregationHashChain) *aggregationChainList;

		KSI_CalendarAuthRec *calendarAuthRec;
		KSI_AggregationAuthRec *aggregationAuthRec;
		KSI_PublicationRecord *publication;

		/* Verification info for the signature. */
		KSI_VerificationResult verificationResult;

	};


#ifdef __cplusplus
}
#endif

#endif /* SIGNATURE_IMPL_H_ */
