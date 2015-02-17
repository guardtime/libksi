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

#include <stdlib.h>

#include "internal.h"

#define KSI_LIST_SIZE_INCREMENT 10

struct KSI_List_st {
	void **arr;
	size_t arr_size;
	size_t arr_len;
	int (*append)(KSI_List *, void *);
	int (*removeElement)(KSI_List *, size_t, void **);
	int (*indexOf)(KSI_List *, void *, size_t **);
	int (*insertAt)(KSI_List *, size_t, void *);
	int (*replaceAt)(KSI_List *, size_t, void *);
	int (*elementAt)(KSI_List *, size_t pos, void **);
	size_t (*length)(KSI_List *list);

	void (*obj_free)(void *);
};

struct KSI_RefList_st {
	struct KSI_List_st list;
	int (*refElement)(void *);
};

static int appendElement(KSI_List *list, void* obj) {
	int res = KSI_UNKNOWN_ERROR;
	void **tmp_arr = NULL;

	if (list == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if ((list->arr_len + 1) >= list->arr_size) {
		unsigned int i;

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

static int appendRef(KSI_List *list, void* obj) {
	int res;

	res = ((struct KSI_RefList_st *) list)->refElement(obj);
	if (res != KSI_OK) goto cleanup;

	res = appendElement(list, obj);
	if (res != KSI_OK) goto cleanup;

cleanup:

	return res;
}

static int indexOf(KSI_List *list, void *o, size_t **pos) {
	int res = KSI_UNKNOWN_ERROR;

	size_t i;
	size_t *tmp = NULL;

	if (list == NULL || o == NULL || pos == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	for (i = 0; i < list->arr_len; i++) {
		if (o == list->arr[i]) {
			tmp = KSI_calloc(sizeof(i), 1);
			if (tmp == NULL) {
				res = KSI_OUT_OF_MEMORY;
				goto cleanup;
			}
			*tmp = i;
			break;
		}
	}

	*pos = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);

	return res;
}

static int replaceElementAt(KSI_List *list, size_t pos, void *o) {
	int res = KSI_UNKNOWN_ERROR;

	if (list == NULL || o == NULL || pos > list->arr_len) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (list->obj_free != NULL) {
		list->obj_free(list->arr[pos]);
	}
	list->arr[pos] = o;

	res = KSI_OK;

cleanup:

	return res;
}

static int insertElementAt(KSI_List *list, size_t pos, void *o) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	if (list == NULL || o == NULL || pos > list->arr_len) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Append empty element */
	res = appendElement(list, NULL);
	if (res != KSI_OK) goto cleanup;

	/* Shift the elements */
	for (i = pos + 1; i < list->arr_len; i++) {
		list->arr[i] = list->arr[i - 1];
	}
	list->arr[pos] = o;

	res = KSI_OK;

cleanup:

	return res;
}

static int insertRefAt(KSI_List *list, size_t pos, void *o) {
	int res;

	res = ((struct KSI_RefList_st *) list)->refElement(o);
	if (res != KSI_OK) goto cleanup;

	res = insertElementAt(list, pos, o);
	if (res != KSI_OK) goto cleanup;

cleanup:

	return res;
}

static int elementAt(KSI_List *list, size_t pos, void **o) {
	int res = KSI_UNKNOWN_ERROR;
	if (list == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (pos >= list->arr_len) {
		res = KSI_BUFFER_OVERFLOW;
		goto cleanup;
	}
	*o = list->arr[pos];

	res = KSI_OK;

cleanup:

	return res;
}

static size_t length(KSI_List *list) {
	return list == NULL ? 0 : list->arr_len;
}

static int removeElement(KSI_List *list, size_t pos, void **o) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;

	if (list == NULL || pos >= list->arr_len) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (o != NULL) {
		*o = list->arr[pos];
	} else {
		list->obj_free(list->arr[pos]);
	}
	/* Shift the tail */
	for (i = pos + 1; i < list->arr_len; i++) {
		list->arr[i - 1] = list->arr[i];
	}

	list->arr_len--;

	res = KSI_OK;

cleanup:

	return res;
}


void KSI_List_free(KSI_List *list) {
	if (list != NULL) {
		unsigned int i;
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

	tmp->append = appendElement;
	tmp->indexOf = indexOf;
	tmp->replaceAt = replaceElementAt;
	tmp->insertAt = insertElementAt;
	tmp->elementAt = elementAt;
	tmp->length = length;
	tmp->removeElement = removeElement;

	*list = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_List_free(tmp);

	return res;
}

int KSI_RefList_new(void (*obj_free)(void *), int (*ref)(void *), KSI_List **list) {
	int res;
	struct KSI_RefList_st *tmp = NULL;
	KSI_List *tmpl = NULL;

	res = KSI_List_new(obj_free, &tmpl);
	if (res != KSI_OK) goto cleanup;

	tmp = (struct KSI_RefList_st *)tmpl;

	tmpl->obj_free = obj_free;

	tmpl->append = appendRef;
	tmpl->insertAt = insertRefAt;

	tmp->refElement = ref;

	*list = tmpl;
	tmpl = NULL;

	res = KSI_OK;

cleanup:

	KSI_List_free(tmpl);

	return res;
}

int KSI_List_append(KSI_List *list, void *obj) {
	int res = KSI_UNKNOWN_ERROR;

	if (list == NULL || obj == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (list->append == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = list->append(list, obj);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_List_indexOf(KSI_List *list, void *o, size_t **pos) {
	int res = KSI_UNKNOWN_ERROR;

	if (list == NULL || o == NULL || pos == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (list->indexOf == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = list->indexOf(list, o, pos);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_List_replaceAt(KSI_List *list, size_t pos, void *o) {
	int res = KSI_UNKNOWN_ERROR;

	if (list == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (list->replaceAt == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = list->replaceAt(list, pos, o);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_List_insertAt(KSI_List *list, size_t pos, void *o) {
	int res = KSI_UNKNOWN_ERROR;

	if (list == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (list->insertAt == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = list->insertAt(list, pos, o);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_List_elementAt(KSI_List *list, size_t pos, void **o) {
	int res = KSI_UNKNOWN_ERROR;

	if (list == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (list->elementAt == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = list->elementAt(list, pos, o);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

size_t KSI_List_length(KSI_List *list) {
	if (list == NULL) {
		return 0;
	}

	if (list->length == NULL) {
		return 0;
	}

	return list->length(list);
}

int KSI_List_remove(KSI_List *list, size_t pos, void **o) {
	int res = KSI_UNKNOWN_ERROR;

	if (list == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (list->removeElement == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = list->removeElement(list, pos, o);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_List_sort(KSI_List *list, int (*cmp)(const void *a, const void *b)) {
	int res = KSI_UNKNOWN_ERROR;

	if (list == NULL || cmp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	qsort(list->arr, list->arr_len, sizeof(void *), cmp);

	res = KSI_OK;

cleanup:

	return res;
}

KSI_IMPLEMENT_LIST(KSI_PKICertificate, KSI_PKICertificate_free);



