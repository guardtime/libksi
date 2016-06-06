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

#ifndef KSI_LIST_H_
#define KSI_LIST_H_

#include <stddef.h>

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

#define KSI_DEFINE_LIST_STRUCT(ltype, rtype) 			\
	/*! Appends the element to the list.
	\param[in]	list	Pointer to the list.
	\param[in]	el		Pointer to the element being added.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	\note After appending the element to the list, the element belongs to the list
		and it will be freed if the list is freed.
	*/																				\
	int (*append)(ltype *, rtype *); 					\
	/*! Removes an element at the given position. If the out parameter is set to
	NULL, the removed element is freed implicitly with type##_free.
	\param[in]	list	Pointer to the list.
	\param[in]	pos		Position of the element to be removed.
	\param[out]	el		Pointer to the receiving pointer.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	\note If the element is removed from the list and returned via output parameter
		to the caller, the caller is responsible for freeing the element.
	*/ \
	int (*removeElement)(ltype *, size_t, rtype **);	\
	/*! This function finds the index of a given element.
	\param[in]	list	Pointer to the list.
	\param[in]	el		Pointer to the element.
	\param[out]	pos		Pointer to the receiving pointer.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	*/																				\
	int (*indexOf)(ltype *, rtype *, size_t **);		\
	/*! Add the element to the given position in the list. All elements with
	equal or greater indices are shifted.
	\param[in]	list	Pointer to the list.
	\param[in]	pos		Position where to insert the element.
	\param[in]	el		Pointer to the element being added.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	\note After add the element to the list, the element belongs to the list
		and it will be freed if the list is freed.
	*/																				\
	int (*insertAt)(ltype *, size_t, rtype *);			\
	/*! Replace the element at the given position in the list. The old element
	will be freed.
	\param[in]	list	Pointer to the list.
	\param[in]	pos		Position where to insert the element.
	\param[in]	el		Pointer to the element being added.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	\note After add the element to the list, the element belongs to the list
		and it will be freed if the list is freed.
	*/																				\
	int (*replaceAt)(ltype *, size_t, rtype *);			\
	/*! Method for accessing an element at any given position.
	\param[in]	list	Pointer to the list.
	\param[in]	pos		Position of the element.
	\param[out]	el		Pointer to the receiving pointer.
	\return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	\note The returned element still belongs to the list and may not be freed
		by the caller.
	*/ \
	int (*elementAt)(ltype *, size_t pos, rtype **);	\
	/*! Returns the list of the element.
	\param[in]	list	Pointer to the list.
	\return Returns the length of the list or 0 if the list is \c NULL.
	*/ \
	size_t (*length)(ltype *list);						\
	void (*obj_free)(rtype *);							\
	/*! Sorts the list using the comparison function cmp.
	 * \param[in]	list	Pointer to the list.
	 * \param[in]	cmp		The comparison function.
	 */ \
	int (*sort)(ltype *list, int (*cmp)(const rtype **, const rtype **)); \
	/*!
	 * Applies each element in the list and the foldCtx to the function fn.
	 * \param[in]	list	Pointer to the list.
	 * \param[in]	foldCtx	The fold context.
	 * \param[in]	fn		Function to be applied.
	 */ \
	int (*foldl)(ltype *list, void *foldCtx, int (*fn)(rtype *el, void *foldCtx)); \
	/*! Internal implementation of the list. */ \
	void *pImpl;										\

/**
 * This macro defines a new list of given type.
 * \param[in]	type	Type of the elements stored in the list.
 */
#define KSI_DEFINE_LIST(type) 									\
	typedef struct type##_list_st KSI_LIST(type);				\
	struct type##_list_st {										\
		KSI_DEFINE_LIST_STRUCT(KSI_LIST(type), type);			\
	}; 															\
	int KSI_LIST_FN_NAME(type, new)(KSI_LIST(type) **list);		\
	void KSI_LIST_FN_NAME(type, free)(KSI_LIST(type) *list);	\


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
int KSI_List_foldl(KSI_List *list, void *foldCtx, int (*fn)(void *el, void *foldCtx));

/**
 * This macro implements all the functions of a list for a given type.
 * \param[in]	type	The type of the elements stored in the list.
 * \param[in]	free_fn	Function pointer to the free method of stored elements. May be \c NULL
 */
#define KSI_IMPLEMENT_LIST(type, free_fn)											\
int KSI_LIST_FN_NAME(type, new)(KSI_LIST(type) **list) {							\
	return KSI_List_new((void (*)(void *))free_fn, (KSI_List **)list);				\
}																					\
void KSI_LIST_FN_NAME(type, free)(KSI_LIST(type) *list) {							\
	KSI_List_free((KSI_List *)list);												\
} 																					\

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_LIST_H_ */
