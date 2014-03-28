#ifndef KSI_TLV_EASY_H_
#define KSI_TLV_EASY_H_

#include "ksi_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KSI_TLV_BEGIN(ctx, tag, isLenient, isForward) 														\
			{																								\
				KSI_CTX *__ctx = (ctx);																		\
				KSI_TLV *__tlv = NULL; 																		\
				int __res; 																					\
				__res = KSI_TLV_new(__ctx, KSI_TLV_PAYLOAD_TLV, (tag), (isLenient), (isForward), NULL, 0, 0, &__tlv); 			\
				if (__res == KSI_OK) {																		\

#define KSI_TLV_END(outRes, outTlv) 		\
				} 							\
				if (__res == KSI_OK) {		\
					(outTlv) = __tlv; 		\
					__tlv = NULL; 			\
				} 							\
				(outRes) = __res; 			\
				KSI_TLV_free(__tlv); 		\
			}								\

#define KSI_TLV_NESTED_HEADER \
		if (__res == KSI_OK) 																				\
		{ 																									\
			KSI_TLV *__master = __tlv; 																		\
			KSI_TLV *__tlv = NULL; 																			\


#define KSI_TLV_NESTED_RAW_BEGIN(tag, isLenient, isForward, data, data_len) 								\
			KSI_TLV_NESTED_HEADER																			\
			__res = KSI_TLV_new(__ctx, KSI_TLV_PAYLOAD_RAW, (tag), (isLenient), (isForward), (data), (data_len), 0, &__tlv);	\

#define KSI_TLV_NESTED_END \
				if (__res == KSI_OK) __res = KSI_TLV_appendNestedTLV(__master, NULL, __tlv); 	\
				if (__res == KSI_OK) __tlv = NULL; 												\
				KSI_TLV_free(__tlv); 															\
			}																					\

#define KSI_TLV_NESTED_BEGIN(tag, isLenient, isForward) 																	\
		KSI_TLV_NESTED_HEADER																								\
		__res = KSI_TLV_new(__ctx, KSI_TLV_PAYLOAD_TLV, (tag), (isLenient), (isForward), NULL, 0, 0, &__tlv);	\

#define KSI_TLV_NESTED_RAW(tag, isLenient, isForward, data, data_len) 									\
	KSI_TLV_NESTED_HEADER																				\
		__res = KSI_TLV_new(__ctx, KSI_TLV_PAYLOAD_RAW, (tag), (isLenient), (isForward), (data), (data_len), 0, &__tlv);	\
	KSI_TLV_NESTED_END																					\

#define KSI_TLV_NESTED_UINT(tag, isLenient, isForward, val) 							\
	KSI_TLV_NESTED_HEADER																\
		__res = KSI_TLV_fromUint(__ctx, (tag), (isLenient), (isForward),  (val));		\
	KSI_TLV_NESTED_END \


/************
 *
 * PARSER
 *
 ************/

#define KSI_PARSE_TLV_NESTED_BEGIN 														\
			{																			\
				KSI_TLV *__parent = __tlv; 												\
				if (__parent != NULL) {													\
					__res = KSI_TLV_cast(__parent, KSI_TLV_PAYLOAD_TLV);				\
				} 																		\
				if (__res == KSI_OK) {													\
					if (__parent != NULL) {												\
						while(1) {														\
							KSI_TLV *__tlv = NULL;										\
							res = KSI_TLV_getNextNestedTLV(__parent, &__tlv);			\
							if (res == KSI_OK && __tlv != NULL) {						\
								switch(KSI_TLV_getTag(__tlv)) {							\

#define KSI_PARSE_TLV_NESTED_END 														\
								} 														\
							} 															\
							if (__tlv == NULL) break;									\
							if (__res != KSI_OK) break;									\
						}																\
					}																	\
				} 																		\
			}																			\

#define TLV_PDU_BEGIN(ctx, raw, raw_len) 												\
		{																				\
			KSI_CTX *__ctx = (ctx);														\
			int __res;																	\
			KSI_TLV *__tlv = NULL;														\
			/* Parse PDU */																\
			__res = KSI_TLV_parseBlob(ctx, (raw), (raw_len), &__tlv);					\
			if (__res == KSI_OK) {														\
				/* Parse PDU nested components. */										\
				KSI_PARSE_TLV_NESTED_BEGIN												\


#define TLV_PDU_END(res) 																\
				KSI_PARSE_TLV_NESTED_END												\
			}																			\
			KSI_TLV_free(__tlv);														\
			(res) = __res;																\
		}																				\

#define KSI_PARSE_TLV_ELEMENT_BEGIN(tag, opt)											\
		case (tag): {																	\
			{opt}																		\
			if (__res == KSI_OK) {														\

#define KSI_PARSE_TLV_ELEMENT_END														\
			}																			\
			break;																		\
		}																				\

#define KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(tag) 										\
	KSI_PARSE_TLV_ELEMENT_BEGIN((tag), KSI_PARSE_TLV_OPT_NONE)									\
	KSI_PARSE_TLV_NESTED_BEGIN															\

#define KSI_PARSE_TLV_NESTED_ELEMENT_END												\
	KSI_PARSE_TLV_NESTED_END															\
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_ELEMENT_UINT64(tag, val) 											\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_SINGLE)									\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_INT); 								\
		if (__res == KSI_OK) { 															\
			__res = KSI_TLV_getUInt64Value(__tlv, (val)); 								\
		} 																				\
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_ELEMENT_UTF8STR(tag, str) 										\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_SINGLE)									\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_STR); 								\
		if (__res == KSI_OK) { 															\
			__res = KSI_TLV_getStringValue(__tlv, (str), 1);							\
		} 																				\
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_ELEMENT_RAW(tag, raw, len)										\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_SINGLE)									\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_STR); 								\
		if (__res == KSI_OK) { 															\
			__res = KSI_TLV_getRawValue(__tlv, (raw), (len), 1);						\
		} 																				\
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_ELEMENT_UINT_(tag, val, maxVal, type) 							\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_SINGLE)									\
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
	KSI_PARSE_TLV_ELEMENT_END																		\

#define KSI_PARSE_TLV_ELEMENT_UINT32(tag, val) KSI_PARSE_TLV_ELEMENT_UINT_(tag, val, 0xffffffff, uint32_t)
#define KSI_PARSE_TLV_ELEMENT_UINT16(tag, val) KSI_PARSE_TLV_ELEMENT_UINT_(tag, val, 0xffff, uint16_t)
#define KSI_PARSE_TLV_ELEMENT_UINT8(tag, val) KSI_PARSE_TLV_ELEMENT_UINT_(tag, val, 0xff, uint8_t)


#define TLV_ELEMENT_IMPRINT(tag, hsh) 													\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_SINGLE)												\
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
	KSI_PARSE_TLV_ELEMENT_END																		\

#define TLV_ELEMENT_CB(tag, fn, dat)													\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_NONE)												\
		__res = (fn)(__ctx, __tlv, (dat));												\
	KSI_PARSE_TLV_ELEMENT_END																		\

#define KSI_PARSE_TLV_OPT_SINGLE { /* TODO! Find a proper way to check for unique value */ }

#define KSI_PARSE_TLV_OPT_NONE {}

#ifdef __cplusplus
}
#endif

#endif /* KSI_TLV_EASY_H_ */
