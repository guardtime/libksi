#ifndef KSI_TLV_EASY_H_
#define KSI_TLV_EASY_H_

#include "ksi_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/************
 *
 * PARSER
 *
 ************/

#define KSI_PARSE_TLV_NESTED_BEGIN 														\
			{																			\
				KSI_LIST(KSI_TLV) *nestedList = NULL;									\
				KSI_TLV *__parent = __tlv; 												\
				int __itr;																\
				if (__parent != NULL) {													\
					__res = KSI_TLV_cast(__parent, KSI_TLV_PAYLOAD_TLV);				\
				} 																		\
				if (__res == KSI_OK && __parent != NULL) {								\
						__res = KSI_TLV_getNestedList(__parent, &nestedList);			\
				}																		\
				if (__res == KSI_OK) {													\
					if (__parent != NULL) {												\
						for(__itr = 0; __itr < KSI_TLVList_length(nestedList); __itr++) {	\
							KSI_TLV *__tlv = NULL;										\
							res = KSI_TLVList_elementAt(nestedList, __itr, &__tlv); 	\
							if (res == KSI_OK && __tlv != NULL) {						\
								int __tagChecked = 0;									\
								switch(KSI_TLV_getTag(__tlv)) {							\

#define KSI_PARSE_TLV_NESTED_END 														\
								} 														\
								if (!__tagChecked)										\
									KSI_LOG_warn(__ctx, "Tag 0x%x not handeled", 		\
											KSI_TLV_getTag(__tlv)); 					\
							}															\
							if (__tlv == NULL) break;									\
							if (__res != KSI_OK) break;									\
						}																\
					}																	\
				} 																		\
			}																			\

#define KSI_TLV_PARSE_BEGIN(ctx, tlv)		 											\
		{																				\
			KSI_CTX *__ctx = (ctx);														\
			int __res = KSI_UNKNOWN_ERROR;												\
			KSI_TLV *__tlv = (tlv);														\
			KSI_PARSE_TLV_NESTED_BEGIN													\

#define KSI_TLV_PARSE_END(res)				 											\
			KSI_PARSE_TLV_NESTED_END													\
			(res) = __res;																\
		}																				\

#define KSI_TLV_PARSE_RAW_BEGIN(ctx, raw, raw_len) 										\
		{																				\
			KSI_CTX *__ctx = (ctx);														\
			int __res;																	\
			KSI_TLV *__tlv = NULL;														\
			/* Parse PDU */																\
			__res = KSI_TLV_parseBlob(ctx, (raw), (raw_len), &__tlv);					\
			if (__tlv == NULL) __res = KSI_INVALID_FORMAT;								\
			if (__res == KSI_OK) {														\
				int __tagChecked = 0;													\
				/* Parse PDU nested components. */										\
				switch(KSI_TLV_getTag(__tlv)) {											\


#define KSI_TLV_PARSE_RAW_END(res, tlv)													\
				}																		\
				if (!__tagChecked)														\
						KSI_LOG_warn(__ctx, "Tag 0x%x not handeled",					\
								KSI_TLV_getTag(__tlv));									\
			}																			\
			if (__res == KSI_OK && (KSI_TLV **)(tlv) != NULL) {							\
				*((KSI_TLV **)(tlv)) = __tlv;															\
				__tlv = NULL;															\
			}																			\
			KSI_TLV_free(__tlv);														\
			(res) = __res;																\
		}																				\

#define KSI_PARSE_TLV_ELEMENT_BEGIN(tag, opt)											\
		case (tag): {																	\
			{opt}																		\
			__tagChecked = 1;															\
			if (__res == KSI_OK) {														\

#define KSI_PARSE_TLV_ELEMENT_END														\
			}																			\
			break;																		\
		}																				\

#define KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(tag) 										\
	KSI_PARSE_TLV_ELEMENT_BEGIN((tag), KSI_PARSE_TLV_OPT_NONE)							\
	KSI_PARSE_TLV_NESTED_BEGIN															\

#define KSI_PARSE_TLV_NESTED_ELEMENT_END												\
	KSI_PARSE_TLV_NESTED_END															\
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_ELEMENT_INTEGER(tag, val)											\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_SINGLE)							\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_INT); 								\
		if (__res == KSI_OK) {															\
			__res = KSI_TLV_getInteger(__tlv, (val));									\
		} 																				\
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_ELEMENT_UINT64(tag, val) 											\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_SINGLE)							\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_INT); 								\
		if (__res == KSI_OK) { 															\
			__res = KSI_TLV_getUInt64Value(__tlv, (val)); 								\
		} 																				\
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_ELEMENT_UTF8STR(tag, str) 										\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_SINGLE)							\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_STR); 								\
		if (__res == KSI_OK) { 															\
			const char *$tmpStr = NULL;													\
			__res = KSI_TLV_getStringValue(__tlv, &$tmpStr);							\
			if (__res == KSI_OK) {														\
				*str = KSI_calloc(strlen($tmpStr) + 1, 1);								\
				if (*str == NULL) {														\
					__res = KSI_OUT_OF_MEMORY;											\
				} else {																\
					strncpy(*str, $tmpStr, strlen($tmpStr) + 1);						\
				}																		\
			}																			\
		} 																				\
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_ELEMENT_RAW(tag, raw, len)										\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_SINGLE)							\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_RAW); 								\
		if (__res == KSI_OK) { 															\
			const unsigned char *$tmpRaw = NULL;										\
			int $tmpRaw_len = 0;														\
			__res = KSI_TLV_getRawValue(__tlv, &$tmpRaw, &$tmpRaw_len);					\
			if (__res == KSI_OK) {														\
				*raw = KSI_calloc($tmpRaw_len, 1);										\
				if (*raw == NULL) {														\
					__res = KSI_OUT_OF_MEMORY;											\
				} else {																\
					*(len) = $tmpRaw_len;												\
					memcpy(*(raw), $tmpRaw, $tmpRaw_len);								\
				}																		\
			}																			\
		} 																				\
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_ELEMENT_UINT_(tag, val, maxVal, type) 							\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_SINGLE)							\
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
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_ELEMENT_UNKNONW_NON_CRITICAL_IGNORE								\
	default: {																			\
		__tagChecked = 1;																\
		if (!KSI_TLV_isLenient(__tlv)) {												\
			KSI_LOG_error(__ctx, "Unknown tag 0x%x", KSI_TLV_getTag(__tlv));			\
			__res = KSI_OK;																\
			__res = KSI_INVALID_FORMAT;													\
		} else {																		\
			KSI_LOG_debug(__ctx, "Ignoring unknown tag 0x%x", KSI_TLV_getTag(__tlv));	\
			__res = KSI_OK;																\
		}																				\
	}																					\

#define KSI_PARSE_TLV_ELEMENT_UNKNONW_NON_CRITICAL_REMOVE								\
	default: __tagChecked = 1;															\
		if (!KSI_TLV_isLenient(__tlv)) {												\
			KSI_LOG_error(__ctx, "Unknown tag 0x%x", KSI_TLV_getTag(__tlv));			\
			__res = KSI_OK;																\
			__res = KSI_INVALID_FORMAT;													\
			} else	{																	\
				__res = KSI_TLV_removeNestedTlv(__parent, __tlv);						\
				if (__res == KSI_OK) {													\
					KSI_TLV_free(__tlv);												\
				}																		\
			}																			\


#define KSI_PARSE_TLV_ELEMENT_UNKNOWN_FWD(fwdTlv)										\
	default: {																			\
		__tagChecked = 1;																\
		__res = KSI_TLV_appendNestedTlv(fwdTlv, NULL, __tlv);							\
		if (__res == KSI_OK) {															\
			__res = KSI_TLV_removeNestedTlv(__parent, __tlv);							\
			__itr--;																	\
		}																				\
	}																					\

#define KSI_PARSE_TLV_ELEMENT_UINT32(tag, val) KSI_PARSE_TLV_ELEMENT_UINT_(tag, val, 0xffffffff, uint32_t)
#define KSI_PARSE_TLV_ELEMENT_UINT16(tag, val) KSI_PARSE_TLV_ELEMENT_UINT_(tag, val, 0xffff, uint16_t)
#define KSI_PARSE_TLV_ELEMENT_UINT8(tag, val) KSI_PARSE_TLV_ELEMENT_UINT_(tag, val, 0xff, uint8_t)


#define KSI_PARSE_TLV_ELEMENT_IMPRINT(tag, hsh) 										\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_SINGLE)							\
		const unsigned char *__raw = NULL; 												\
		int __raw_len = 0; 																\
		__res = KSI_TLV_cast(__tlv, KSI_TLV_PAYLOAD_RAW); 								\
		if (__res == KSI_OK) { 															\
			__res = KSI_TLV_getRawValue(__tlv, &__raw, &__raw_len); 					\
			if (__res == KSI_OK) { 														\
				__res = KSI_DataHash_fromImprint(ctx, __raw, __raw_len, (hsh));			\
			} 																			\
		}																				\
		KSI_nofree(__raw);																\
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_ELEMENT_CB(tag, fn, dat)											\
	KSI_PARSE_TLV_ELEMENT_BEGIN(tag, KSI_PARSE_TLV_OPT_NONE)							\
		__res = (fn)(__ctx, __tlv, (dat));												\
	KSI_PARSE_TLV_ELEMENT_END															\

#define KSI_PARSE_TLV_OPT_SINGLE { /* TODO! Find a proper way to check for unique value */ }

#define KSI_PARSE_TLV_OPT_NONE {}

#ifdef __cplusplus
}
#endif

#endif /* KSI_TLV_EASY_H_ */
