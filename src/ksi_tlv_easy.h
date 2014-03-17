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

#ifdef __cplusplus
}
#endif

#endif /* KSI_TLV_EASY_H_ */
