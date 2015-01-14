/*
 * signature_impl.h
 *
 *  Created on: 29.08.2014
 *      Author: henri
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
