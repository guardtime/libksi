#ifndef _KSI_INTERNAL_H_
#define _KSI_INTERNAL_H_

#include <stdint.h>
#include <limits.h>

#include "ksi.h"
#include "tlv_tags.h"

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
#endif

#define KSI_BEGIN(ctx, err) KSI_ERR_init((ctx), (err))
#define KSI_PRE(err, cond) if (KSI_ERR_pre(err, cond, __FILE__, __LINE__) || !(cond))
#define KSI_RETURN(err) KSI_ERR_apply((err))
#define KSI_FAIL_EXT(err, statusCode, extErrCode, message) (KSI_ERR_fail((err), (statusCode), (extErrCode), __FILE__, __LINE__, (message)))
#define KSI_FAIL(err, statusCode, message) (KSI_ERR_fail((err), (statusCode), 0, __FILE__, __LINE__, (message)))
#define KSI_CATCH(err, res) if ((res) != KSI_OK && KSI_FAIL((err), res, NULL) == KSI_OK)
#define KSI_SUCCESS(err) KSI_ERR_success((err))

#define KSI_UINT16_MINSIZE(val) ((val > 0xff) ? 2 : 1)
#define KSI_UINT32_MINSIZE(val) ((val > 0xffff) ? (2 + KSI_UINT16_MINSIZE((val) >> 16)) : KSI_UINT16_MINSIZE((val)))
#define KSI_UINT64_MINSIZE(val) (((val) > 0xffffffff) ? (4 + KSI_UINT32_MINSIZE((val) >> 32)) : KSI_UINT32_MINSIZE((val)))

/* Create a new object of type. */
#define KSI_new(typeVar) (typeVar *)(KSI_calloc(sizeof(typeVar), 1))

/* Returns Empty string if #str==NULL otherwise returns #str itself */
#define KSI_strnvl(str) ((str) == NULL)?"":(str)

/** Dummy macro for indicating that the programmer knows and did not forget to free up some pointer. */
#define KSI_nofree(ptr) (void *)(ptr)

#define KSI_IMPLEMENT_GET_CTX(type)							\
KSI_CTX *type##_getCtx(const type *o) {			 			\
	return o->ctx; 											\
} 															\

#define KSI_IMPLEMENT_LIST(type, free_fn)											\
struct type##_list_st { 															\
	KSI_CTX *ctx;																	\
	KSI_List *list;																	\
};																					\
int KSI_LIST_FN_NAME(type, new)(KSI_CTX *ctx, KSI_LIST(type) **list) {				\
	int res = KSI_UNKNOWN_ERROR;													\
	KSI_LIST(type) *l = NULL;														\
	l = KSI_new(KSI_LIST(type));													\
	if (l == NULL) {																\
		res = KSI_OUT_OF_MEMORY;													\
		goto cleanup;																\
	}																				\
	res = KSI_List_new((void (*)(void *))free_fn, &l->list);						\
	if (res != KSI_OK) goto cleanup;												\
	l->ctx = ctx;																	\
	*list = l;																		\
	l = NULL;																		\
	res = KSI_OK;																	\
cleanup:																			\
	KSI_LIST_FN_NAME(type, free)(l);												\
	return res;																		\
}																					\
void KSI_LIST_FN_NAME(type, free)(KSI_LIST(type) *list) {							\
	if (list != NULL) {																\
		KSI_List_free(list->list);													\
		KSI_free(list);																\
	}																				\
} 																					\
void KSI_LIST_FN_NAME(type, freeAll)(KSI_LIST(type) *list) {						\
	if (list != NULL) {																\
		KSI_List_freeAll(list->list);												\
		KSI_free(list);																\
	}																				\
} 																					\
int KSI_LIST_FN_NAME(type, append)(KSI_LIST(type) *list, type *o) {					\
	return KSI_List_append(list->list, o);											\
}																					\
int KSI_LIST_FN_NAME(type, iter)(KSI_LIST(type) *list) {							\
	return KSI_List_iter(list->list);												\
}																					\
int KSI_LIST_FN_NAME(type, next)(KSI_LIST(type) *list, type **o) {					\
	return KSI_List_next(list->list, (void **)o);									\
}																					\
int KSI_LIST_FN_NAME(type, indexOf)(const KSI_LIST(type) *list, const type *o, size_t **pos) {	\
	return KSI_List_indexOf(list->list, o, pos);									\
}																					\
int KSI_LIST_FN_NAME(type, insertAt)(KSI_LIST(type) *list, size_t pos, type *o) {	\
	return KSI_List_insertAt(list->list, pos, o);									\
}																					\
int KSI_LIST_FN_NAME(type, replaceAt)(KSI_LIST(type) *list, size_t pos, type *o) {	\
	return KSI_List_replaceAt(list->list, pos, o);									\
}																					\
size_t KSI_LIST_FN_NAME(type, length)(const KSI_LIST(type) *list) {					\
	return list != NULL ? KSI_List_length(list->list): 0;							\
}																					\
int KSI_LIST_FN_NAME(type, remove)(KSI_LIST(type) *list, size_t pos) {				\
	return KSI_List_remove(list->list, pos);										\
}																					\
int KSI_LIST_FN_NAME(type, elementAt)(const KSI_LIST(type) *list, size_t pos, type **o) {	\
	return KSI_List_elementAt(list->list, pos, (void **) o);						\
}																					\
int KSI_LIST_FN_NAME(type, sort)(KSI_LIST(type) *list, int (*cmp)(const type **a, const type **b)) {	\
	return KSI_List_sort(list->list, (int (*)(const void *, const void *)) cmp);	\
}																					\
KSI_CTX *type##List_getCtx(const KSI_LIST(type) *o) {	 							\
	return o->ctx; 																	\
} 																					\

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

#endif
