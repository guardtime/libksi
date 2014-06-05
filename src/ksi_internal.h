#ifndef _KSI_INTERNAL_H_
#define _KSI_INTERNAL_H_

#include <stdint.h>

#include "include/ksi/ksi.h"
#include "ksi_tlv_tags.h"

#define KSI_BEGIN(ctx, err) KSI_ERR_init((ctx), (err))
#define KSI_PRE(err, cond) if (!(cond) && (KSI_ERR_init(NULL, (err)) == KSI_OK) && (KSI_FAIL((err), KSI_INVALID_ARGUMENT, NULL) == KSI_OK))
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

/* Dummy macro for indicating that the programmer knows and did not forget to free up some pointer. */
#define KSI_nofree(ptr)

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
int KSI_LIST_FN_NAME(type, append)(KSI_LIST(type) *list, type *o) {					\
	return KSI_List_append(list->list, o);											\
}																					\
int KSI_LIST_FN_NAME(type, iter)(KSI_LIST(type) *list) {							\
	return KSI_List_iter(list->list);												\
}																					\
int KSI_LIST_FN_NAME(type, next)(KSI_LIST(type) *list, type **o) {					\
	return KSI_List_next(list->list, (void **)o);									\
}																					\
int KSI_LIST_FN_NAME(type, indexOf)(const KSI_LIST(type) *list, const type *o) {	\
	return KSI_List_indexOf(list->list, o);											\
}																					\
int KSI_LIST_FN_NAME(type, insertAt)(KSI_LIST(type) *list, int pos, type *o) {		\
	return KSI_List_insertAt(list->list, pos, o);									\
}																					\
int KSI_LIST_FN_NAME(type, replaceAt)(KSI_LIST(type) *list, int pos, type *o) {		\
	return KSI_List_replaceAt(list->list, pos, o);									\
}																					\
int KSI_LIST_FN_NAME(type, length)(const KSI_LIST(type) *list) {					\
	return list != NULL ? KSI_List_length(list->list): 0;							\
}																					\
int KSI_LIST_FN_NAME(type, remove)(KSI_LIST(type) *list, int pos) {					\
	return KSI_List_remove(list->list, pos);										\
}																					\
int KSI_LIST_FN_NAME(type, elementAt)(const KSI_LIST(type) *list, int pos, type **o) {	\
	return KSI_List_elementAt(list->list, pos, (void **) o);						\
}																					\
KSI_CTX *type##List_getCtx(const KSI_LIST(type) *o) {	 							\
	return o->ctx; 																	\
} 																					\

#endif
