/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#ifndef KSI_LIST_H_
#define KSI_LIST_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup lists Lists
 * @{
 */

/**
 * Generic list type for storing void* pointers.
 */
typedef struct KSI_List_st KSI_List;

/**
 * Macro to get the list type name for a given type.
 * \param[in]	type	Type of the list.
 */
#define KSI_LIST(type) type##List

/**
 * Experimental macro for creating lists.
 * \param[in]	type		Type of the list.
 * \param[out]	list		Pointer to the receiving pointer.
 */
#define KSI_NEW_LIST(type, list) KSI_List_new(type##_free, (list))

/**
 * Experimental macro for creating lists.
 * \param[in]	type		Type of the list.
 * \param[out]	list		Pointer to the receiving pointer.
 */
#define KSI_NEW_REFLIST(type, list) KSI_RefList_new(type##_free, type##_ref, (list))

/**
 * Generates the function name for a list with a given type.
 * \param[in]	type	Type of the list.
 * \param[in]	name	Name of the function.
 */
#define KSI_LIST_FN_NAME(type, name) type##List_##name

/**
 * This macro defines a new list of given type.
 * \param[in]	type	Type of the elements stored in the list.
 */
#define KSI_DEFINE_LIST(type) 													\
/*!
 List of \ref type.
*/ 														\
typedef struct type##_list_st KSI_LIST(type);									\
/*! Frees the memory allocated by the list and frees the elements individually.
	\param[in]	list		Pointer to the list.
 */																				\
void KSI_LIST_FN_NAME(type, free)(KSI_LIST(type) *list);						\
/*! Creates a new list of \ref type.
	\param[out]	list	Pointer to the receiving pointer.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */																				\
int KSI_LIST_FN_NAME(type, new)(KSI_LIST(type) **list);					\
/*! Appends the element to the list.
	\param[in]	list	Pointer to the list.
	\param[in]	el		Pointer to the element being added.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	\note After appending the element to the list, the element belongs to the list
		and it will be freed if the list is freed.
 */																				\
int KSI_LIST_FN_NAME(type, append)(KSI_LIST(type) *list, type *el);				\
/*! This function finds the index of a given element.
	\param[in]	list	Pointer to the list.
	\param[in]	el		Pointer to the element.
	\param[out]	pos		Pointer to the receiving pointer.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */																				\
int KSI_LIST_FN_NAME(type, indexOf)(KSI_LIST(type) *list, type *el, size_t **pos);		\
/*! Add the element to the given position in the list. All elements with
	equal or greater indices are shifted.
	\param[in]	list	Pointer to the list.
	\param[in]	pos		Position where to insert the element.
	\param[in]	el		Pointer to the element being added.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	\note After add the element to the list, the element belongs to the list
		and it will be freed if the list is freed.
 */																				\
int KSI_LIST_FN_NAME(type, insertAt)(KSI_LIST(type) *list, size_t pos, type *el);			\
/*! Replace the element at the given position in the list. The old element
	will be freed.
	\param[in]	list	Pointer to the list.
	\param[in]	pos		Position where to insert the element.
	\param[in]	el		Pointer to the element being added.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	\note After add the element to the list, the element belongs to the list
		and it will be freed if the list is freed.
 */																				\
int KSI_LIST_FN_NAME(type, replaceAt)(KSI_LIST(type) *list, size_t pos, type *el);		\
/*! Removes an element at the given position. If the out parameter is set to
	NULL, the removed element is freed implicitly with type##_free.
	\param[in]	list	Pointer to the list.
	\param[in]	pos		Position of the element to be removed.
	\param[out]	el		Pointer to the receiving pointer.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	\note If the element is removed from the list and returned via output parameter
		to the caller, the caller is responsible for freeing the element.
*/ \
int KSI_LIST_FN_NAME(type, remove)(KSI_LIST(type) *list, size_t pos, type **el);			\
/*! Returns the list of the element.
	\param[in]	list	Pointer to the list.
	\return Returns the length of the list or 0 if the list is \c NULL.
*/ \
size_t KSI_LIST_FN_NAME(type, length)(KSI_LIST(type) *list);						\
/*! Method for accessing an element at any given position.
	\param[in]	list	Pointer to the list.
	\param[in]	pos		Position of the element.
	\param[out]	el		Pointer to the receiving pointer.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	\note The returned element still belongs to the list and may not be freed
		by the caller.
*/ \
int KSI_LIST_FN_NAME(type, elementAt)(KSI_LIST(type) *list, size_t pos, type **el);	\
/*! Function to sort the elements in the list.
	\param[in]	list	Pointer to the list.
	\param[in]	fn		Sort function.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
*/ \
int KSI_LIST_FN_NAME(type, sort)(KSI_LIST(type) *list, int (*fn)(const type **, const type **));	\

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

/**
 * This macro implements all the functions of a list for a given type.
 * \param[in]	type	The type of the elements stored in the list.
 * \param[in]	free_fn	Function pointer to the free method of stored elements. May be \c NULL
 */
#define KSI_IMPLEMENT_LIST(type, free_fn)											\
struct type##_list_st { 															\
	KSI_List *list;																	\
};																					\
int KSI_LIST_FN_NAME(type, new)(KSI_LIST(type) **list) {							\
	return KSI_List_new((void (*)(void *))free_fn, (KSI_List **)list);				\
}																					\
void KSI_LIST_FN_NAME(type, free)(KSI_LIST(type) *list) {							\
	KSI_List_free((KSI_List *)list);												\
} 																					\
int KSI_LIST_FN_NAME(type, append)(KSI_LIST(type) *list, type *o) {					\
	return KSI_List_append((KSI_List *)list, o);									\
}																					\
int KSI_LIST_FN_NAME(type, indexOf)(KSI_LIST(type) *list, type *o, size_t **pos) {	\
	return KSI_List_indexOf((KSI_List *)list, o, pos);								\
}																					\
int KSI_LIST_FN_NAME(type, insertAt)(KSI_LIST(type) *list, size_t pos, type *o) {	\
	return KSI_List_insertAt((KSI_List *)list, pos, o);								\
}																					\
int KSI_LIST_FN_NAME(type, replaceAt)(KSI_LIST(type) *list, size_t pos, type *o) {	\
	return KSI_List_replaceAt((KSI_List *)list, pos, o);							\
}																					\
size_t KSI_LIST_FN_NAME(type, length)(KSI_LIST(type) *list) {						\
	return KSI_List_length((KSI_List *)list);										\
}																					\
int KSI_LIST_FN_NAME(type, remove)(KSI_LIST(type) *list, size_t pos, type **o) {	\
	return KSI_List_remove((KSI_List *)list, pos, (void **)o);						\
}																					\
int KSI_LIST_FN_NAME(type, elementAt)(KSI_LIST(type) *list, size_t pos, type **o) {	\
	return KSI_List_elementAt((KSI_List *)list, pos, (void **) o);					\
}																					\
int KSI_LIST_FN_NAME(type, sort)(													\
		KSI_LIST(type) *list, int (*cmp)(const type **a, const type **b)) {			\
	return KSI_List_sort(															\
		(KSI_List *)list, (int (*)(const void *, const void *)) cmp);				\
}																					\

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_LIST_H_ */
