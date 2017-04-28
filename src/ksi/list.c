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

#include "list.h"
#include <stdlib.h>
#include "pkitruststore.h"

#include "internal.h"

#define KSI_LIST_SIZE_INCREMENT 10

struct listEl_st {
	size_t p;
	void *o;
};

struct listImpl_st {
	struct listEl_st *arr;
	size_t arr_size;
	KSI_uint64_t arr_len;
};

struct KSI_List_st {
	KSI_DEFINE_LIST_STRUCT(KSI_List, void)
};

struct KSI_RefList_st {
	struct KSI_List_st list;
	int (*refElement)(void *);
};

static int appendElement(KSI_List *list, void* obj) {
	int res = KSI_UNKNOWN_ERROR;
	struct listEl_st *tmp_arr = NULL;
	struct listImpl_st *pImpl;

	if (list == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	pImpl = list->pImpl;

	if (pImpl == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	if ((pImpl->arr_len + 1) > pImpl->arr_size) {
		unsigned int i;

		tmp_arr = KSI_calloc(pImpl->arr_size + KSI_LIST_SIZE_INCREMENT,
				sizeof(struct listEl_st));
		if (tmp_arr == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}

		for (i = 0; i < pImpl->arr_len; i++) {
			tmp_arr[i] = pImpl->arr[i];
		}

		KSI_free(pImpl->arr);
		pImpl->arr = tmp_arr;
		tmp_arr = NULL;

		pImpl->arr_size += KSI_LIST_SIZE_INCREMENT;
	}

	if (pImpl->arr == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	pImpl->arr[pImpl->arr_len++].o = obj;

	res = KSI_OK;

cleanup:

	KSI_free(tmp_arr);

	return res;
}

static int indexOf(KSI_List *list, void *o, size_t **pos) {
	int res = KSI_UNKNOWN_ERROR;
	struct listImpl_st *pImpl;

	size_t i;
	size_t *tmp = NULL;

	if (list == NULL || o == NULL || pos == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	pImpl = list->pImpl;

	if (pImpl == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	if (pImpl->arr == NULL) {
		*pos = NULL;
		res = KSI_OK;
		goto cleanup;
	}

	for (i = 0; i < pImpl->arr_len; i++) {
		if (o == pImpl->arr[i].o) {
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
	struct listImpl_st *pImpl;

	if (list == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	pImpl = list->pImpl;

	if (pImpl == NULL || pImpl->arr == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	if (pos >= pImpl->arr_len) {
		res = KSI_BUFFER_OVERFLOW;
		goto cleanup;
	}

	if (list->obj_free != NULL) {
		list->obj_free(pImpl->arr[pos].o);
	}
	pImpl->arr[pos].o = o;

	res = KSI_OK;

cleanup:

	return res;
}

static int insertElementAt(KSI_List *list, size_t pos, void *o) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	struct listImpl_st *pImpl;

	if (list == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	pImpl = list->pImpl;

	if (pImpl == NULL || pImpl->arr == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	if (pos >= pImpl->arr_len) {
		res = KSI_BUFFER_OVERFLOW;
		goto cleanup;
	}

	/* Append empty element */
	res = appendElement(list, NULL);
	if (res != KSI_OK) goto cleanup;

	/* Shift the elements */
	for (i = pImpl->arr_len - 1; i > pos; i--) {
		pImpl->arr[i] = pImpl->arr[i - 1];
	}
	pImpl->arr[pos].o = o;

	res = KSI_OK;

cleanup:

	return res;
}

static int elementAt(KSI_List *list, size_t pos, void **o) {
	int res = KSI_UNKNOWN_ERROR;
	struct listImpl_st *pImpl;

	if (list == NULL || o == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	pImpl = list->pImpl;

	if (pImpl == NULL || pImpl->arr == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	if (pos >= pImpl->arr_len) {
		res = KSI_BUFFER_OVERFLOW;
		goto cleanup;
	}
	*o = pImpl->arr[pos].o;

	res = KSI_OK;

cleanup:

	return res;
}

static size_t length(KSI_List *list) {
	return list == NULL || list->pImpl == NULL ? 0 : ((struct listImpl_st *) list->pImpl)->arr_len;
}

static int removeElement(KSI_List *list, size_t pos, void **o) {
	int res = KSI_UNKNOWN_ERROR;
	size_t i;
	struct listImpl_st *pImpl;

	if (list == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	pImpl = list->pImpl;

	if (pImpl == NULL || pImpl->arr == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	if (pos >= pImpl->arr_len) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (o != NULL) {
		*o = pImpl->arr[pos].o;
	} else {
		list->obj_free(pImpl->arr[pos].o);
	}
	/* Shift the tail */
	for (i = pos + 1; i < pImpl->arr_len; i++) {
		pImpl->arr[i - 1] = pImpl->arr[i];
	}

	pImpl->arr_len--;

	res = KSI_OK;

cleanup:

	return res;
}


void KSI_List_free(KSI_List *list) {
	if (list != NULL) {
		unsigned int i;
		struct listImpl_st *pImpl = list->pImpl;
		if (pImpl != NULL) {
			for (i = 0; i < pImpl->arr_len; i++) {
				if (list->obj_free != NULL) {
					list->obj_free(pImpl->arr[i].o);
				}
			}
			KSI_free(pImpl->arr);
			KSI_free(pImpl);
		}
		KSI_free(list);
	}
}

int KSI_List_new(void (*obj_free)(void *), KSI_List **list) {
	int res;
	KSI_List *tmp = NULL;
	struct listImpl_st *impl = NULL;

	tmp = KSI_new(struct KSI_List_st);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->pImpl = NULL;
	tmp->obj_free = obj_free;
	tmp->append = appendElement;
	tmp->indexOf = indexOf;
	tmp->replaceAt = replaceElementAt;
	tmp->insertAt = insertElementAt;
	tmp->elementAt = elementAt;
	tmp->length = length;
	tmp->removeElement = removeElement;
	tmp->sort = KSI_List_sort;
	tmp->foldl = KSI_List_foldl;

	impl = KSI_new(struct listImpl_st);
	if (impl == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	impl->arr = NULL;
	impl->arr_len = 0;
	impl->arr_size = 0;

	tmp->pImpl = impl;
	impl = NULL;

	*list = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(impl);
	KSI_List_free(tmp);

	return res;
}

int KSI_List_append(KSI_List *list, void *obj) {
	int res = KSI_UNKNOWN_ERROR;

	if (list == NULL) {
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

	if (list == NULL || pos == NULL) {
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

	if (list == NULL) {
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

	if (list == NULL) {
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

static int (*cmpCallback)(const void **, const void **) = NULL;
static int sortCmp(const struct listEl_st *l, const struct listEl_st *r) {
	int res = (cmpCallback != NULL ? cmpCallback((const void**)&l->o, (const void**)&r->o) : 0);
	if(res == 0) {
		if (l->p > r->p) res = 1;
		else res = -1;
	}
	return res;
}

static int updateListElPos(KSI_List *list) {
	int res = KSI_UNKNOWN_ERROR;
	struct listImpl_st *pImpl;
	size_t i;

	if (list == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	pImpl = list->pImpl;

	if (pImpl == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	if (pImpl->arr == NULL) {
		res = KSI_OK;
		goto cleanup;
	}

	for (i = 0; i < pImpl->arr_len; i++) {
		pImpl->arr[i].p = i;
	}
	res = KSI_OK;
cleanup:
	return res;
}

int KSI_List_sort(KSI_List *list, int (*cmp)(const void **a, const void **b)) {
	int res = KSI_UNKNOWN_ERROR;
	struct listImpl_st *pImpl;

	if (list == NULL || cmp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	pImpl = list->pImpl;

	if (pImpl == NULL || pImpl->arr == NULL) {
		res = KSI_INVALID_STATE;
		goto cleanup;
	}

	res = updateListElPos(list);
	if (res != KSI_OK) goto cleanup;

	cmpCallback = cmp;
	qsort(pImpl->arr, pImpl->arr_len, sizeof(struct listEl_st), (int(*)(const void *, const void *))sortCmp);
	cmpCallback = NULL;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_List_foldl(KSI_List *list, void *foldCtx, int (*fn)(void *, void *)) {
	int res = KSI_UNKNOWN_ERROR;
	void *el;
	size_t i;

	if (list == NULL || fn == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	for (i = 0; i < KSI_List_length(list); i++) {
		res = KSI_List_elementAt(list, i, &el);
		if (res != KSI_OK) goto cleanup;

		res = fn(el, foldCtx);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

KSI_IMPLEMENT_LIST(KSI_PKICertificate, KSI_PKICertificate_free);



