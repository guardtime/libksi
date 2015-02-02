#ifndef _KSI_INTERNAL_H_
#define _KSI_INTERNAL_H_

#include <stdint.h>
#include <limits.h>

#include "ksi.h"

/**
 * HTTP network client implementations.
 */
#define KSI_IMPL_CURL			1
#define KSI_IMPL_WININET		2
#define KSI_IMPL_WINHTTP		3
 /**
  * Crypo implementations.
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
#  ifndef snprintf
#    define snprintf _snprintf
#  endif
#  ifndef gmtime_r
#    define gmtime_r(time, resultp) gmtime_s(resultp, time)
#  endif
#endif

#define KSI_BEGIN(ctx, err) KSI_ERR_init((ctx), (err))
#define KSI_PRE(err, cond) if (KSI_ERR_pre(err, cond, __FILE__, __LINE__) || !(cond))
#define KSI_RETURN(err) KSI_ERR_apply((err))
#define KSI_FAIL_EXT(err, statusCode, extErrCode, message) (KSI_ERR_fail((err), (statusCode), (extErrCode), __FILE__, __LINE__, (message)))
#define KSI_FAIL(err, statusCode, message) (KSI_ERR_fail((err), (statusCode), 0, __FILE__, __LINE__, (message)))
#define KSI_CATCH(err, res) if ((res) != KSI_OK && KSI_FAIL((err), res, NULL) == KSI_OK)
#define KSI_SUCCESS(err) KSI_ERR_success((err))

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
	return o->ctx; 											\
} 															\

#define KSI_DEFINE_SETTER(baseType, valueType, valueName, alias) int baseType##_set##alias(baseType *o, valueType valueName)
#define KSI_DEFINE_GETTER(baseType, valueType, valueName, alias) int baseType##_get##alias(const baseType *o, valueType* valueName)

#define KSI_IMPLEMENT_SETTER(baseType, valueType, valueName, alias)			\
KSI_DEFINE_SETTER(baseType, valueType, valueName, alias) {					\
	KSI_ERR err;															\
	KSI_PRE(&err, o != NULL) goto cleanup;									\
	KSI_BEGIN(o->ctx, &err);												\
	o->valueName = valueName;												\
	KSI_SUCCESS(&err);														\
cleanup:																	\
	return KSI_RETURN(&err);												\
}																			\

#define KSI_IMPLEMENT_GETTER(baseType, valueType, valueName, alias)			\
KSI_DEFINE_GETTER(baseType, valueType, valueName, alias) {					\
	KSI_ERR err;															\
	KSI_PRE(&err, o != NULL) goto cleanup;									\
	KSI_PRE(&err, valueName != NULL) goto cleanup;							\
	KSI_BEGIN(o->ctx, &err);												\
	*valueName = o->valueName;												\
	KSI_SUCCESS(&err);														\
cleanup:																	\
	return KSI_RETURN(&err);												\
}																			\

#define KSI_IMPLEMENT_TOTLV(type) \
int type##_toTlv(KSI_CTX *ctx, const type *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) { \
	KSI_ERR err; \
	int res; \
	KSI_TLV *tmp = NULL; \
	\
	KSI_PRE(&err, data != NULL) goto cleanup; \
	KSI_PRE(&err, tlv != NULL) goto cleanup; \
	KSI_BEGIN(ctx, &err); \
	\
	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, tag, isNonCritical, isForward, &tmp); \
	KSI_CATCH(&err, res) goto cleanup; \
	\
	res = KSI_TlvTemplate_construct(ctx, tmp, data, KSI_TLV_TEMPLATE(type)); \
	KSI_CATCH(&err, res) goto cleanup; \
	\
	*tlv = tmp; \
	tmp = NULL; \
	\
	KSI_SUCCESS(&err); \
	\
cleanup: \
	\
	KSI_TLV_free(tmp); \
	\
	return KSI_RETURN(&err); \
}

#define KSI_IMPLEMENT_FROMTLV(type, tag, addon) \
int type##_fromTlv(KSI_TLV *tlv, type **data) { \
	KSI_ERR err; \
	int res; \
	type *tmp = NULL; \
	int isLeft = 0; \
	unsigned char *tlvData = NULL; \
	unsigned len; \
	KSI_OctetString *raw = NULL; \
	KSI_TLV *baseTlv = NULL; \
	KSI_CTX *ctx = KSI_TLV_getCtx(tlv); \
	\
	KSI_PRE(&err, tlv != NULL) goto cleanup; \
	KSI_PRE(&err, data != NULL) goto cleanup; \
	KSI_BEGIN(ctx, &err); \
	\
	if (KSI_TLV_getTag(tlv) != tag){ \
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL); \
		goto cleanup; \
	} \
	\
	res = type##_new(KSI_TLV_getCtx(tlv), &tmp); \
	KSI_CATCH(&err, res) goto cleanup; \
	\
	res = KSI_TlvTemplate_extract(KSI_TLV_getCtx(tlv), tmp, tlv, KSI_TLV_TEMPLATE(type)); \
	KSI_CATCH(&err, res) goto cleanup; \
	addon \
	*data = tmp; \
	tmp = NULL; \
	\
	KSI_SUCCESS(&err); \
	\
cleanup: \
	\
	type##_free(tmp); \
	KSI_free(tlvData); \
	KSI_OctetString_free(raw); \
	KSI_TLV_free(baseTlv); \
	return KSI_RETURN(&err); \
}
	
#define FROMTLV_ADD_RAW(name, offset) \
	res = KSI_TLV_serialize(tlv, &tlvData, &len); \
	KSI_CATCH(&err, res) goto cleanup; \
	\
	if (len-offset <= 0){ \
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL); \
		goto cleanup; \
	} \
	res = KSI_OctetString_new(ctx, tlvData+offset, len-offset, &raw); \
	KSI_CATCH(&err, res) goto cleanup; \
	\
	tmp->name = raw; \
	raw = NULL; \

#define FROMTLV_ADD_BASETLV(name) \
	res = KSI_TLV_clone(tlv, &baseTlv); \
	KSI_CATCH(&err, res) goto cleanup; \
	tmp->name = baseTlv; \
	baseTlv = NULL;
	
struct KSI_Object_st {
	KSI_CTX *ctx;
	unsigned refCount;
};

#endif
