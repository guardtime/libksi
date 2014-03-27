#include "ksi_internal.h"
#include "ksi_tlv.h"

void KSI_Signature_free(KSI_Signature *sig) {
	if (sig != NULL) {
		KSI_free(sig->errorMessage);
		KSI_Header_free(sig->responseHeader);
		KSI_CalendarChain_free(sig->calendarChain);
		KSI_free(sig);
	}
}

void KSI_CalendarChain_free(KSI_CalendarChain *cal) {
	if (cal != NULL) {
		KSI_HashNode_free(cal->chain);
		KSI_free(cal);
	}
}

void KSI_Header_free(KSI_Header *hdr) {
	if (hdr != NULL) {
		KSI_free(hdr->clientId);
		KSI_free(hdr);
	}
}

#define TLV_NESTED_BEGIN 															\
			{																		\
				KSI_TLV *__parent = __tlv; 											\
				if (__parent != NULL) {												\
					__res = KSI_TLV_cast(__parent, KSI_TLV_PAYLOAD_TLV);			\
				} 																	\
				if (__res == KSI_OK) {												\
					if (__parent != NULL) {											\
						while(1) {													\
							KSI_TLV *__tlv = NULL;									\
							res = KSI_TLV_getNextNestedTLV(__parent, &__tlv);		\
							if (res == KSI_OK && __tlv != NULL) {					\
								switch(KSI_TLV_getTag(__tlv)) {						\

#define TLV_NESTED_END 																\
								} 													\
							} 														\
							if (__tlv == NULL) break;								\
							if (__res != KSI_OK) break;								\
						}															\
					}																\
				} 																	\
			}																		\

#define TLV_PDU_BEGIN(ctx, raw, raw_len) 											\
		{																			\
			KSI_CTX *__ctx = (ctx);													\
			int __res;																\
			KSI_TLV *__tlv = NULL;													\
			/* Parse PDU */															\
			__res = KSI_TLV_parseBlob(ctx, (raw), (raw_len), &__tlv);				\
			if (__res == KSI_OK) {													\
				/* Parse PDU nested components. */									\
				TLV_NESTED_BEGIN													\


#define TLV_PDU_END(res) 																\
				TLV_NESTED_END															\
			}																			\
			KSI_TLV_free(__tlv);														\
			(res) = __res;																\
		}																				\

#define TLV_ELEMENT_BEGIN(tag, opt)														\
		case (tag): {																	\
			{opt}																		\
			if (__res == KSI_OK) {														\

#define TLV_ELEMENT_END																	\
			}																			\
			break;																		\
		}																				\

#define TLV_NESTED_ELEMENT_BEGIN(tag) 													\
	TLV_ELEMENT_BEGIN((tag), TLV_OPT_NONE)												\
	TLV_NESTED_BEGIN																	\

#define TLV_NESTED_ELEMENT_END															\
	TLV_NESTED_END																		\
	TLV_ELEMENT_END																		\

#define TLV_ELEMENT_UINT64(tag, val) 													\
	TLV_ELEMENT_BEGIN(tag, TLV_OPT_SINGLE)												\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_INT); 								\
		if (__res == KSI_OK) { 															\
			__res = KSI_TLV_getUInt64Value(__tlv, (val)); 								\
		} 																				\
	TLV_ELEMENT_END																		\

#define TLV_ELEMENT_UTF8STR(tag, str) 													\
	TLV_ELEMENT_BEGIN(tag, TLV_OPT_SINGLE)												\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_STR); 								\
		if (__res == KSI_OK) { 															\
			__res = KSI_TLV_getStringValue(__tlv, (str), 1);							\
		} 																				\
	TLV_ELEMENT_END																		\

#define TLV_ELEMENT_RAW(tag, raw, len)													\
	TLV_ELEMENT_BEGIN(tag, TLV_OPT_SINGLE)												\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_STR); 								\
		if (__res == KSI_OK) { 															\
			__res = KSI_TLV_getRawValue(__tlv, (raw), (len), 1);						\
		} 																				\
	TLV_ELEMENT_END																		\

#define TLV_ELEMENT_UINT_(tag, val, maxVal, type) \
	TLV_ELEMENT_BEGIN(tag, TLV_OPT_SINGLE)												\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_INT); 								\
		if (__res == KSI_OK) { 															\
			uint64_t __val;																\
			__res = KSI_TLV_getUInt64Value(__tlv, &__val); 								\
			if (__res == KSI_OK) {														\
				if (__val > (maxVal))													\
					__res = KSI_INVALID_FORMAT;											\
			}																			\
			if (__res == KSI_OK)														\
				*(val) = (type) __val;													\
		} 																				\
	TLV_ELEMENT_END																		\

#define TLV_ELEMENT_UINT32(tag, val) TLV_ELEMENT_UINT_(tag, val, 0xffffffff, uint32_t)
#define TLV_ELEMENT_UINT16(tag, val) TLV_ELEMENT_UINT_(tag, val, 0xffff, uint16_t)
#define TLV_ELEMENT_UINT8(tag, val) TLV_ELEMENT_UINT_(tag, val, 0xff, uint8_t)


#define TLV_ELEMENT_IMPRINT(tag, hsh) 													\
	TLV_ELEMENT_BEGIN(tag, TLV_OPT_SINGLE)												\
		unsigned char *__raw = NULL; \
		int __raw_len = 0; \
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_RAW); 								\
		if (__res == KSI_OK) { 															\
			__res = KSI_TLV_getRawValue(__tlv, &__raw, &__raw_len, 0); 					\
			if (__res == KSI_OK) { 														\
				__res = KSI_DataHash_fromImprint(__tlv->ctx, __raw, __raw_len, (hsh));	\
			} 																			\
		}																				\
		KSI_nofree(__raw);																\
	TLV_ELEMENT_END																		\

#define TLV_ELEMENT_CB(tag, fn, dat)													\
	TLV_ELEMENT_BEGIN(tag, TLV_OPT_NONE)												\
		__res = (fn)(__ctx, __tlv, (dat));												\
	TLV_ELEMENT_END																		\

#define TLV_OPT_SINGLE {static int __count = 0; ++__count; if (__count > 1) __res = KSI_INVALID_FORMAT;}
#define TLV_OPT_SINGLE2 																	\
		{ 																				\
			static int __count = 0;														\
			if (++__count > 1) __res == KSI_INVALID_FORMAT;								\
		}																				\

#define TLV_OPT_NONE

static int calendarChain_add(KSI_CTX *ctx, KSI_TLV *tlv, KSI_HashNode **chainRoot) {
	int res;
	KSI_DataHash *hsh = NULL;
	unsigned char *imprint = NULL;
	int imprint_len = 0;
	int tlvTag;

	/* Validate arguments. */
	tlvTag = KSI_TLV_getTag(tlv);
	switch (tlvTag) {
		case 0x05:
			if (*chainRoot != NULL) {
				res = KSI_INVALID_FORMAT;
				goto cleanup;
			}
			break;
		case 0x07:
		case 0x08:
			if (*chainRoot == NULL) {
				res = KSI_INVALID_FORMAT;
				goto cleanup;
			}
			break;
		default:
			res = KSI_INVALID_ARGUMENT;
			goto cleanup;
	}

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_RAW);
	if (res != KSI_OK) goto cleanup;

	/* Extract the raw value from the tlv */
	res = KSI_TLV_getRawValue(tlv, &imprint, &imprint_len, 0);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHash_fromImprint(tlv->ctx, imprint, imprint_len, &hsh);
	if (res != KSI_OK) goto cleanup;

	res = KSI_HashNode_buildCalendar(ctx, hsh, KSI_TLV_getTag(tlv) == 0x08, chainRoot);
	if (res != KSI_OK) goto cleanup;

cleanup:

	KSI_nofree(imprint);
	KSI_DataHash_free(hsh);

	return res;
}

int KSI_parseSignature(KSI_CTX *ctx, unsigned char *rawPdu, int rawPdu_len, KSI_Signature **signature) {
	KSI_ERR err;
	int res;

	uint32_t utc_time;

	KSI_Signature *sig = NULL;
	KSI_CalendarChain *cal = NULL;
	KSI_AggregationChain *aggr = NULL;
	KSI_Header *hdr = NULL;


	KSI_BEGIN(ctx, &err);

	sig = KSI_new(KSI_Signature);
	if (sig == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	sig->requestId = 0;
	sig->status = 0;
	sig->errorMessage = NULL;

	sig->calendarChain = NULL;

	cal = KSI_new(KSI_CalendarChain);
	if (cal == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	cal->aggregationTime = 0;
	cal->publicationTime = 0;
	cal->chain = NULL;
	cal->inputHash = NULL;

	hdr = KSI_new(KSI_Header);
	if (cal == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	hdr->clientId = NULL;
	hdr->clientId_length = 0;
	hdr->instanceId = 0;
	hdr->messageId = 0;

	aggr = KSI_new(KSI_AggregationChain);
	if (aggr == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	aggr->inputData = NULL;
	aggr->inputHash = NULL;

	KSI_LOG_debug(ctx, "Starting to parse aggregation response.");

	TLV_PDU_BEGIN(ctx, rawPdu, rawPdu_len)
		TLV_NESTED_ELEMENT_BEGIN(0x202)
			TLV_NESTED_ELEMENT_BEGIN(0x01)
				TLV_ELEMENT_UINT32(0x05, &hdr->instanceId)
				TLV_ELEMENT_UINT32(0x06, &hdr->messageId)
				TLV_ELEMENT_RAW(0x07, &hdr->clientId, &hdr->clientId_length);
			TLV_NESTED_ELEMENT_END

			TLV_ELEMENT_UINT32(0x02, &sig->requestId);
			TLV_ELEMENT_UINT32(0x05, &sig->status);
			TLV_ELEMENT_UTF8STR(0x06, &sig->errorMessage);

			TLV_NESTED_ELEMENT_BEGIN(0x801)
				TLV_ELEMENT_UINT32(0x02, &aggr->aggregationTime)
				TLV_ELEMENT_UINT32(0x03, &aggr->chainIndex)
				TLV_ELEMENT_RAW(0x04, &aggr->inputData, &aggr->inputData_len)
				TLV_ELEMENT_IMPRINT(0x05, &aggr->inputHash)
				TLV_ELEMENT_UINT8(0x06, &aggr->aggrHashId)


			TLV_NESTED_ELEMENT_END

			TLV_NESTED_ELEMENT_BEGIN(0x802)
				TLV_ELEMENT_UINT32(0x02, &cal->aggregationTime)
				TLV_ELEMENT_UINT32(0x01, &cal->publicationTime)
				TLV_ELEMENT_CB(0x05, calendarChain_add, &cal->chain)
				TLV_ELEMENT_CB(0x07, calendarChain_add, &cal->chain)
				TLV_ELEMENT_CB(0x08, calendarChain_add, &cal->chain)
			TLV_NESTED_ELEMENT_END

		TLV_NESTED_ELEMENT_END
	TLV_PDU_END(res);

	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashNode_getCalendarAggregationTime(cal->chain, cal->publicationTime, &utc_time);
	KSI_CATCH(&err, res) goto cleanup;

	if (utc_time != cal->aggregationTime) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Aggregation time mismatch.");
		goto cleanup;
	}

	sig->calendarChain = cal;
	cal = NULL;

	sig->responseHeader = hdr;
	hdr = NULL;
	KSI_LOG_debug(ctx, "status = %d, aggr_time = %lld, pub_time = %lld", sig->status, sig->calendarChain->aggregationTime, sig->calendarChain->publicationTime);


	KSI_LOG_debug(ctx, "Finished parsing successfully.");

	KSI_SUCCESS(&err);


	*signature = sig;
	sig = NULL;

cleanup:

	KSI_Header_free(hdr);
	KSI_CalendarChain_free(cal);
	KSI_Signature_free(sig);

	return KSI_RETURN(&err);
}
