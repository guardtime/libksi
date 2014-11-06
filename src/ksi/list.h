#ifndef KSI_LIST_H_
#define KSI_LIST_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KSI_List_st KSI_List;

#define KSI_LIST(type) type##List

#define KSI_NEW_LIST(type, list) KSI_List_new(type##_free, (list))
#define KSI_NEW_REFLIST(type, list) KSI_RefList_new(type##_free, type##_ref, (list))

#define KSI_LIST_FN_NAME(type, name) type##List_##name
#define KSI_DEFINE_LIST(type) 													\
typedef struct type##_list_st KSI_LIST(type);									\
void KSI_LIST_FN_NAME(type, free)(KSI_LIST(type) *);							\
int KSI_LIST_FN_NAME(type, new)(KSI_CTX *, KSI_LIST(type) **);					\
int KSI_LIST_FN_NAME(type, append)(KSI_LIST(type) *, type *);					\
int KSI_LIST_FN_NAME(type, indexOf)(KSI_LIST(type) *, type *, size_t **);		\
int KSI_LIST_FN_NAME(type, insertAt)(KSI_LIST(type) *, size_t, type *);			\
int KSI_LIST_FN_NAME(type, replaceAt)(KSI_LIST(type) *, size_t, type *);		\
int KSI_LIST_FN_NAME(type, remove)(KSI_LIST(type) *, size_t, type **);			\
size_t KSI_LIST_FN_NAME(type, length)(KSI_LIST(type) *);						\
int KSI_LIST_FN_NAME(type, elementAt)(KSI_LIST(type) *, size_t pos, type **);	\
int KSI_LIST_FN_NAME(type, sort)(KSI_LIST(type) *, int (*)(const type **, const type **));	\

void KSI_List_free(KSI_List *list);
int KSI_List_new(void (*obj_free)(void *), KSI_List **list);
int KSI_List_append(KSI_List *list, void *o);
int KSI_List_remove(KSI_List *list, size_t pos, void **o);
int KSI_List_indexOf(KSI_List *list, void *o, size_t **i);
int KSI_List_insertAt(KSI_List *list, size_t pos, void *o);
int KSI_List_replaceAt(KSI_List *list, size_t pos, void *o);
int KSI_List_elementAt(KSI_List *list, size_t pos, void **o);
size_t KSI_List_length(KSI_List *list);
int KSI_List_sort(KSI_List *list, int (*)(const void *, const void *));

#define KSI_IMPLEMENT_LIST(type, free_fn)											\
struct type##_list_st { 															\
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
int KSI_LIST_FN_NAME(type, indexOf)(KSI_LIST(type) *list, type *o, size_t **pos) {	\
	return KSI_List_indexOf(list->list, o, pos);									\
}																					\
int KSI_LIST_FN_NAME(type, insertAt)(KSI_LIST(type) *list, size_t pos, type *o) {	\
	return KSI_List_insertAt(list->list, pos, o);									\
}																					\
int KSI_LIST_FN_NAME(type, replaceAt)(KSI_LIST(type) *list, size_t pos, type *o) {	\
	return KSI_List_replaceAt(list->list, pos, o);									\
}																					\
size_t KSI_LIST_FN_NAME(type, length)(KSI_LIST(type) *list) {					\
	return list != NULL ? KSI_List_length(list->list): 0;							\
}																					\
int KSI_LIST_FN_NAME(type, remove)(KSI_LIST(type) *list, size_t pos, type **o) {	\
	return KSI_List_remove(list->list, pos, (void **)o);							\
}																					\
int KSI_LIST_FN_NAME(type, elementAt)(KSI_LIST(type) *list, size_t pos, type **o) {	\
	return KSI_List_elementAt(list->list, pos, (void **) o);						\
}																					\
int KSI_LIST_FN_NAME(type, sort)(KSI_LIST(type) *list, int (*cmp)(const type **a, const type **b)) {	\
	return KSI_List_sort(list->list, (int (*)(const void *, const void *)) cmp);	\
}																					\

#ifdef __cplusplus
}
#endif

#endif /* KSI_LIST_H_ */
