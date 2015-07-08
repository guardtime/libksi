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

#ifndef _KSI_INTERNAL_H_
#define _KSI_INTERNAL_H_

#include <stdint.h>
#include <limits.h>

#include "ksi.h"
#include "err.h"
#include "compatibility.h"

#define KSI_TLV_MASK_TLV16 0x80u
#define KSI_TLV_MASK_LENIENT 0x40u
#define KSI_TLV_MASK_FORWARD 0x20u

#define KSI_TLV_MASK_TLV8_TYPE 0x1fu

/**
 * HTTP network client implementations.
 */
#define KSI_IMPL_CURL			1
#define KSI_IMPL_WININET		2
#define KSI_IMPL_WINHTTP		3
 /**
  * Crypto implementations.
  */
#define KSI_IMPL_OPENSSL		4
#define KSI_IMPL_CRYPTOAPI			5

/**
 * Default implementation for HTTP network client.
 */
#ifndef KSI_NET_HTTP_IMPL
#define KSI_NET_HTTP_IMPL KSI_IMPL_CURL
#endif

/**
 * Default implementation for data hashing.
 */
#ifndef KSI_HASH_IMPL
#define KSI_HASH_IMPL KSI_IMPL_OPENSSL
#endif

/**
 * Default implementation for the PKI truststore.
 */
#ifndef KSI_PKI_TRUSTSTORE_IMPL
#define KSI_PKI_TRUSTSTORE_IMPL KSI_IMPL_OPENSSL
#endif

#ifndef _WIN32
#  include <stdbool.h>
#  ifdef HAVE_CONFIG_H
#    include "config.h"
#  endif
#endif

#ifdef _WIN32
	typedef enum { false = 0, true = !false } bool;
#  ifndef gmtime_r
#    define gmtime_r(time, resultp) gmtime_s(resultp, time)
#  endif
#endif

#define KSI_pushError(ctx, statusCode, message) KSI_ERR_push((ctx), (statusCode), 0, __FILE__, __LINE__, (message))

#define KSI_UINT16_MINSIZE(val) (((val) > 0xff) ? 2 : ((val) == 0 ? 0 : 1))
#define KSI_UINT32_MINSIZE(val) (((val) > 0xffff) ? (2 + KSI_UINT16_MINSIZE((val) >> 16)) : KSI_UINT16_MINSIZE((val)))
#define KSI_UINT64_MINSIZE(val) (((val) > 0xffffffff) ? (4 + KSI_UINT32_MINSIZE((val) >> 32)) : KSI_UINT32_MINSIZE((val)))

/* Create a new object of type. */
#define KSI_new(typeVar) (typeVar *)(KSI_malloc(sizeof(typeVar)))

/* Returns Empty string if #str==NULL otherwise returns #str itself */
#define KSI_strnvl(str) ((str) == NULL)?"":(str)

/** Dummy macro for indicating that the programmer knows and did not forget to free up some pointer. */
#define KSI_nofree(ptr) (ptr) = NULL

#define KSI_IMPLEMENT_GET_CTX(type)							\
KSI_CTX *type##_getCtx(const type *o) {			 			\
	return o != NULL ? o->ctx : NULL;						\
} 															\

#define KSI_DEFINE_SETTER(baseType, valueType, valueName, alias) int baseType##_set##alias(baseType *o, valueType valueName)
#define KSI_DEFINE_GETTER(baseType, valueType, valueName, alias) int baseType##_get##alias(const baseType *o, valueType* valueName)

#define KSI_IMPLEMENT_SETTER(baseType, valueType, valueName, alias)			\
KSI_DEFINE_SETTER(baseType, valueType, valueName, alias) {					\
	int res = KSI_UNKNOWN_ERROR;											\
	if (o == NULL) {														\
		res = KSI_INVALID_ARGUMENT;											\
		goto cleanup;														\
	}																		\
	KSI_ERR_clearErrors(o->ctx);											\
	o->valueName = valueName;												\
	res = KSI_OK;															\
cleanup:																	\
	return res;																\
}																			\

#define KSI_IMPLEMENT_GETTER(baseType, valueType, valueName, alias)			\
KSI_DEFINE_GETTER(baseType, valueType, valueName, alias) {					\
	int res = KSI_UNKNOWN_ERROR;											\
	if (o == NULL || valueName == NULL) {									\
		res = KSI_INVALID_ARGUMENT;											\
		goto cleanup;														\
	}																		\
	KSI_ERR_clearErrors(o->ctx);											\
	*valueName = o->valueName;												\
	res = KSI_OK;															\
cleanup:																	\
	return res;																\
}																			\

#define KSI_IMPLEMENT_TOTLV(type) \
int type##_toTlv(KSI_CTX *ctx, const type *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) { \
	int res; \
	KSI_TLV *tmp = NULL; \
	\
	KSI_ERR_clearErrors(ctx);\
	\
	if (ctx == NULL || data == NULL || tlv == NULL) { \
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL); \
		goto cleanup; \
	} \
	\
	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, tag, isNonCritical, isForward, &tmp); \
	if (res != KSI_OK) { \
		KSI_pushError(ctx, res, NULL); \
		goto cleanup; \
	} \
	\
	res = KSI_TlvTemplate_construct(ctx, tmp, data, KSI_TLV_TEMPLATE(type)); \
	if (res != KSI_OK) { \
		KSI_pushError(ctx, res, NULL); \
		goto cleanup; \
	} \
	\
	*tlv = tmp; \
	tmp = NULL; \
	\
	res = KSI_OK; \
	\
cleanup: \
	\
	KSI_TLV_free(tmp); \
	\
	return res; \
}

#define KSI_IMPLEMENT_FROMTLV(type, tag, addon) \
int type##_fromTlv(KSI_TLV *tlv, type **data) { \
	int res; \
	type *tmp = NULL; \
	int isLeft = 0; \
	unsigned char *tlvData = NULL; \
	KSI_OctetString *raw = NULL; \
	KSI_CTX *ctx = KSI_TLV_getCtx(tlv); \
	\
	if (tlv == NULL) { \
		res = KSI_INVALID_ARGUMENT;\
		goto cleanup;\
	} \
	\
	KSI_ERR_clearErrors(ctx);\
	\
	if (data == NULL) { \
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL); \
		goto cleanup; \
	} \
	\
	if (KSI_TLV_getTag(tlv) != tag){ \
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, NULL); \
		goto cleanup; \
	} \
	\
	res = type##_new(KSI_TLV_getCtx(tlv), &tmp); \
	if (res != KSI_OK) { \
		KSI_pushError(ctx, res, NULL); \
		goto cleanup; \
	} \
	\
	res = KSI_TlvTemplate_extract(KSI_TLV_getCtx(tlv), tmp, tlv, KSI_TLV_TEMPLATE(type)); \
	if (res != KSI_OK) { \
		KSI_pushError(ctx, res, NULL); \
		goto cleanup; \
	} \
	addon \
	*data = tmp; \
	tmp = NULL; \
	\
	res = KSI_OK; \
	\
cleanup: \
	\
	type##_free(tmp); \
	KSI_free(tlvData); \
	KSI_OctetString_free(raw); \
	return res; \
}

#define FROMTLV_ADD_RAW(name, offset) \
	do{ \
		size_t len; \
		res = KSI_TLV_serialize(tlv, &tlvData, &len); \
		if (res != KSI_OK) { \
			KSI_pushError(ctx, res, NULL); \
			goto cleanup; \
		} \
		\
		if (len-offset <= 0){ \
			KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL); \
			goto cleanup; \
		} \
		res = KSI_OctetString_new(ctx, tlvData+offset, len-offset, &raw); \
		if (res != KSI_OK) { \
			KSI_pushError(ctx, res, NULL); \
			goto cleanup; \
		} \
		\
		tmp->name = raw; \
		raw = NULL; \
	}while(0);

/*TODO: Is it safe to not free baseTlv, as on error baseTlv is still NULL and after setting "name", objects tmp free handles the memory.*/
#define FROMTLV_ADD_BASETLV(name) \
	do{ \
		KSI_TLV *baseTlv = NULL; \
		res = KSI_TLV_clone(tlv, &baseTlv); \
		if (res != KSI_OK) { \
			KSI_pushError(ctx, res, NULL); \
			goto cleanup; \
		} \
		tmp->name = baseTlv; \
	}while(0);

struct KSI_Object_st {
	KSI_CTX *ctx;
	unsigned refCount;
};

/* Error structure.*/
struct KSI_ERR_st {
	/* Free text error message to be displayed. */
	char message[1024];

	/* Filename of the error. */
	char fileName[1024];

	/* Line number where the error was logd. */
	unsigned int lineNr;

	/* Status code. */
	int statusCode;

	/* Error code */
	long extErrorCode;

	/* Pointer to parent context. */
	KSI_CTX *ctx;
};

#endif
