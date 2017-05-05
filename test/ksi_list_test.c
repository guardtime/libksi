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

#include <string.h>
#include "all_tests.h"
#include "../src/ksi/ksi.h"
#include "../src/ksi/list.h"
#include "../src/ksi/internal.h"


extern KSI_CTX *ctx;

typedef struct TestObject_st {
	size_t initialPos;
	size_t val;
} TestObject;

static void TestObject_free(TestObject *o) {
	if (o != NULL) {
		KSI_free(o);
	}
}

static int TestObject_new(TestObject **o) {
	TestObject *tmp = NULL;
	if (o == NULL) return KSI_INVALID_ARGUMENT;

	tmp = KSI_new(TestObject);
	if (tmp == NULL) return KSI_OUT_OF_MEMORY;

	tmp->initialPos = 0;
	tmp->val = 0;

	*o = tmp;
	return KSI_OK;
}

KSI_DEFINE_LIST(TestObject)
#define TestObjectList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define TestObjectList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define TestObjectList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define TestObjectList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define TestObjectList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define TestObjectList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define TestObjectList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define TestObjectList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define TestObjectList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

KSI_IMPLEMENT_LIST(TestObject, TestObject_free)

static int TestObject_compare(const TestObject **left, const TestObject **right) {
	const TestObject *l = *left;
	const TestObject *r = *right;

	if (l->val == r->val) return 0;
	else if (l->val > r->val) return 1;
	else return -1;
}

static void testList_sortEqualValues(CuTest *tc) {
#define TEST_LIST_LENGTH 10
#define TEST_VALUE 0xaa

	int res = KSI_UNKNOWN_ERROR;
	TestObjectList *list = NULL;
	size_t i;

	res = TestObjectList_new(&list);
	CuAssert(tc, "Unable to create new list.", res == KSI_OK);

	for (i = 0; i < TEST_LIST_LENGTH; i++) {
		TestObject *obj = NULL;

		res = TestObject_new(&obj);
		CuAssert(tc, "Unable to create new test object.", res == KSI_OK);

		obj->initialPos = i;
		obj->val = TEST_VALUE;

		res = TestObjectList_append(list, obj);
		CuAssert(tc, "Unable to object to list.", res == KSI_OK);
		obj = NULL;
	}
	CuAssert(tc, "List length mismatch.", TestObjectList_length(list) == TEST_LIST_LENGTH);

	res = TestObjectList_sort(list, TestObject_compare);
	CuAssert(tc, "Unable to sort list.", res == KSI_OK);

	for (i = 0; i < TEST_LIST_LENGTH; i++) {
		TestObject *obj = NULL;

		res = TestObjectList_elementAt(list, i, &obj);
		CuAssert(tc, "Unable to get object from list.", res == KSI_OK);

		CuAssert(tc, "Object value mismatch.", obj->val == TEST_VALUE);
		CuAssert(tc, "Object position mismatch.", obj->initialPos == i);
	}

	TestObjectList_free(list);

#undef TEST_LIST_LENGTH
#undef TEST_VALUE
}

static void testList_sortAscendingValues(CuTest *tc) {
#define TEST_LIST_LENGTH 10

	int res = KSI_UNKNOWN_ERROR;
	TestObjectList *list = NULL;
	size_t i;

	res = TestObjectList_new(&list);
	CuAssert(tc, "Unable to create new list.", res == KSI_OK);

	for (i = 0; i < TEST_LIST_LENGTH; i++) {
		TestObject *obj = NULL;

		res = TestObject_new(&obj);
		CuAssert(tc, "Unable to create new test object.", res == KSI_OK);

		obj->initialPos = i;
		obj->val = i + 1;

		res = TestObjectList_append(list, obj);
		CuAssert(tc, "Unable to object to list.", res == KSI_OK);
		obj = NULL;
	}
	CuAssert(tc, "List length mismatch.", TestObjectList_length(list) == TEST_LIST_LENGTH);

	res = TestObjectList_sort(list, TestObject_compare);
	CuAssert(tc, "Unable to sort list.", res == KSI_OK);

	for (i = 0; i < TEST_LIST_LENGTH; i++) {
		TestObject *obj = NULL;

		res = TestObjectList_elementAt(list, i, &obj);
		CuAssert(tc, "Unable to get object from list.", res == KSI_OK);

		CuAssert(tc, "Object value mismatch.", obj->val == (i + 1));
		CuAssert(tc, "Object position mismatch.", obj->initialPos == i);
	}

	TestObjectList_free(list);

#undef TEST_LIST_LENGTH
}

static void testList_sortDescendingValues(CuTest *tc) {
#define TEST_LIST_LENGTH 10

	int res = KSI_UNKNOWN_ERROR;
	TestObjectList *list = NULL;
	size_t i;

	res = TestObjectList_new(&list);
	CuAssert(tc, "Unable to create new list.", res == KSI_OK);

	for (i = 0; i < TEST_LIST_LENGTH; i++) {
		TestObject *obj = NULL;

		res = TestObject_new(&obj);
		CuAssert(tc, "Unable to create new test object.", res == KSI_OK);

		obj->initialPos = i;
		obj->val = TEST_LIST_LENGTH - i;

		res = TestObjectList_append(list, obj);
		CuAssert(tc, "Unable to object to list.", res == KSI_OK);
		obj = NULL;
	}
	CuAssert(tc, "List length mismatch.", TestObjectList_length(list) == TEST_LIST_LENGTH);

	res = TestObjectList_sort(list, TestObject_compare);
	CuAssert(tc, "Unable to sort list.", res == KSI_OK);

	for (i = 0; i < TEST_LIST_LENGTH; i++) {
		TestObject *obj = NULL;

		res = TestObjectList_elementAt(list, i, &obj);
		CuAssert(tc, "Unable to get object from list.", res == KSI_OK);

		CuAssert(tc, "Object value mismatch.", obj->val == (i + 1));
		CuAssert(tc, "Object position mismatch.", obj->initialPos == (TEST_LIST_LENGTH - i - 1));
	}

	TestObjectList_free(list);

#undef TEST_LIST_LENGTH
}

CuSuite* KSITest_List_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testList_sortEqualValues);
	SUITE_ADD_TEST(suite, testList_sortAscendingValues);
	SUITE_ADD_TEST(suite, testList_sortDescendingValues);

	return suite;
}
