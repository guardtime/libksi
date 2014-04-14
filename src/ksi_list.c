#include <stdlib.h>

#include "ksi_internal.h"

typedef struct KSI_List_st KSI_List;

#define KSI_LIST_SIZE_INCREMENT 10

#define KSI_IMPLEMENT_LIST(type) 													\
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
	res = KSI_List_new((void (*)(void *))type##_free, &l->list);					\
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
int KSI_LIST_FN_NAME(type, indexOf)(KSI_LIST(type) *list, type *o) {				\
	return KSI_List_indexOf(list->list, o);											\
}																					\
int KSI_LIST_FN_NAME(type, insertAt)(KSI_LIST(type) *list, int pos, type *o) {		\
	return KSI_List_insertAt(list->list, pos, o);									\
}																					\
KSI_CTX *type##List_getCtx(KSI_LIST(type) *o) {	 									\
	return o->ctx; 																	\
} 																					\

struct KSI_List_st {
	void **arr;
	size_t arr_size;
	size_t arr_len;
	void (*obj_free)(void *);
	int iter;

};


static void KSI_List_free(struct KSI_List_st *list) {
	if (list != NULL) {
		struct KSI_List_st *tmp = NULL;
		int i;
		for (i = 0; i < list->arr_len; i++) {
			if (list->obj_free != NULL) {
				list->obj_free(list->arr[i]);
			}
		}
		KSI_free(list->arr);
		KSI_free(list);
	}
}

static int KSI_List_new(void (*obj_free)(void *), struct KSI_List_st **list) {
	int res;
	struct KSI_List_st *tmp = NULL;

	tmp = KSI_new(struct KSI_List_st);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->arr = NULL;
	tmp->obj_free = obj_free;
	tmp->arr_len = 0;
	tmp->arr_size = 0;
	tmp->iter = 0;

	*list = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_List_free(tmp);

	return res;
}

static int appendElement(struct KSI_List_st* list, void* obj) {
	int res = KSI_UNKNOWN_ERROR;
	void **tmp_arr = NULL;

	if (list == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (list->arr_len + 1 >= list->arr_size) {
		int i;

		tmp_arr = KSI_calloc(list->arr_size + KSI_LIST_SIZE_INCREMENT,
		        sizeof(void *));
		if (tmp_arr == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}

		for (i = 0; i < list->arr_len; i++) {
			tmp_arr[i] = list->arr[i];
		}

		KSI_free(list->arr);
		list->arr = tmp_arr;
		tmp_arr = NULL;

		list->arr_size += KSI_LIST_SIZE_INCREMENT;
	}
	list->arr[list->arr_len++] = obj;

	res = KSI_OK;

cleanup:

	KSI_free(tmp_arr);

	return res;
}

static int KSI_List_append(struct KSI_List_st *list, void *obj) {
	int res = KSI_UNKNOWN_ERROR;

	if (list == NULL || obj == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = appendElement(list, obj);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

static int KSI_List_iter(struct KSI_List_st *list) {
	int res = KSI_UNKNOWN_ERROR;
	if (list == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	list->iter = 0;

	res = KSI_OK;

cleanup:

	return res;
}

static int KSI_List_next(struct KSI_List_st *list, void **o) {
	int res = KSI_UNKNOWN_ERROR;
	if (list == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (list->iter < list->arr_len) {
		*o = list->arr[list->iter++];
	} else {
		*o = NULL;
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int KSI_List_indexOf(struct KSI_List_st *list, void *o) {
	int index = -1;
	int i;
	if (list == NULL || o == NULL) goto cleanup;
	for (i = 0; i < list->arr_len; i++) {
		if (o == list->arr[i]) {
			index = i;
			break;
		}
	}

cleanup:

	return index;
}

static int KSI_List_insertAt(struct KSI_List_st *list, int pos, void *o) {
	int res = KSI_UNKNOWN_ERROR;
	int i;

	if (list == NULL || o == NULL || pos > list->arr_len + 1) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Append empty element */
	res = appendElement(list, NULL);

	/* Shift the elements */
	for (i = pos + 1; i < list->arr_len; i++) {
		list->arr[i] = list->arr[i - 1];
	}
	list->arr[pos] = o;

cleanup:

	return res;
}

KSI_IMPLEMENT_LIST(KSI_Integer);
KSI_IMPLEMENT_LIST(KSI_TLV);
//KSI_IMPLEMENT_LIST(KSI_HashChain);
