#include <stdlib.h>

#include "ksi_internal.h"

#define KSI_LIST_SIZE_INCREMENT 10

struct KSI_List_st {
	void **arr;
	size_t arr_size;
	size_t arr_len;
	void (*obj_free)(void *);
	int iter;

};

static int appendElement(KSI_List *list, void* obj) {
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

void KSI_List_free(KSI_List *list) {
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

int KSI_List_new(void (*obj_free)(void *), KSI_List **list) {
	int res;
	KSI_List *tmp = NULL;

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

int KSI_List_append(KSI_List *list, void *obj) {
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

int KSI_List_iter(KSI_List *list) {
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

int KSI_List_next(KSI_List *list, void **o) {
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

int KSI_List_indexOf(KSI_List *list, void *o) {
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

int KSI_List_insert(KSI_List *list, int pos, void *o) {
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

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_List_length(KSI_List *list) {
	return list == NULL ? 0 : list->arr_len;
}

int KSI_List_remove(KSI_List *list, int pos) {
	int res = KSI_UNKNOWN_ERROR;
	int i;

	if (list == NULL || pos < 0 || pos >= list->arr_len) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Shift the tail */
	for (i = pos + 1; i < list->arr_len; i++) {
		list->arr[i - 1] = list->arr[i];
	}

	list->arr_len--;

	if (list->iter > pos) --list->iter;

	res = KSI_OK;

cleanup:

	return res;
}

KSI_IMPLEMENT_LIST(KSI_Integer, KSI_Integer_free);
KSI_IMPLEMENT_LIST(KSI_TLV, KSI_TLV_free);
KSI_IMPLEMENT_LIST(KSI_HashChain, KSI_HashChain_free);
KSI_IMPLEMENT_LIST(KSI_String, KSI_free);
