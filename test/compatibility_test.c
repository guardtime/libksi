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

#include <stdio.h>
#include <string.h>

#include "cutest/CuTest.h"
#include "all_tests.h"
#include <ksi/compatibility.h>

static void test_KSI_snprintf(CuTest* tc) {
	int i = 0;
	size_t len = 0;
	char dest[8];
	char empty[8];
	char bigdest[0xFF];

	memset(dest, 0xFF, sizeof(dest));
	memset(empty, 0xFF, sizeof(empty));

	len = KSI_snprintf(dest, 8, "%s", "1234567890");
	CuAssert(tc, "KSI_snprintf failed.", len == 7 && dest[7] == 0 && !strcmp(dest, "1234567"));
	memset(dest, 0xFF, sizeof(dest));

	len = KSI_snprintf(dest, 4, "%d%c%d%d%d%d%d%d%d%d", 1, '2', 3, 4, 5, 6, 7, 8, 9, 0);
	CuAssert(tc, "KSI_snprintf failed.", len == 3 && dest[3] == 0 && !strcmp(dest, "123"));
	memset(dest, 0xFF, sizeof(dest));

	len = KSI_snprintf(dest, 8, "%s", "12345");
	CuAssert(tc, "KSI_snprintf failed.", len == 5 && dest[5] == 0 && !strcmp(dest, "12345") );
	memset(dest, 0xFF, sizeof(dest));

	len = KSI_snprintf(dest, 0, "%s", "12345");
	CuAssert(tc, "KSI_snprintf failed.", len == 0 && memcmp(dest, empty, sizeof(dest)) == 0);

	len = KSI_snprintf(NULL, 5, "%s", "12345");
	CuAssert(tc, "KSI_snprintf failed.", len == 0 && memcmp(dest, empty, sizeof(dest)) == 0);

	len = 0;
	for (i = 0 ; i < 0xff + 1; i++){
		len += KSI_snprintf(bigdest + len, sizeof(bigdest) - len, "%s", "F");
	}

	CuAssert(tc, "KSI_snprintf failed.", len == 0xFF-1);
}

static void test_KSI_strncpy(CuTest* tc) {
	char *ret;
	char dest[8];
	char empty[8];

	memset(dest, 0xFF, sizeof(dest));
	memset(empty, 0xFF, sizeof(empty));

	ret = KSI_strncpy(dest, "1234567890", 8);
	CuAssert(tc, "KSI_strncpy failed.", ret == dest && dest[7] == 0 && strcmp(dest, "1234567") == 0);
	memset(dest, 0xFF, sizeof(dest));

	ret = KSI_strncpy(dest, "1234567890", 4);
	CuAssert(tc, "KSI_strncpy failed.", ret == dest && dest[3] == 0 && strcmp(dest, "123") == 0);
	memset(dest, 0xFF, sizeof(dest));

	ret = KSI_strncpy(dest, "12345", 8);
	CuAssert(tc, "KSI_strncpy failed.", ret == dest && dest[5] == 0 && strcmp(dest, "12345") == 0);
	memset(dest, 0xFF, sizeof(dest));

	ret = KSI_strncpy(dest, "12345", 0);
	CuAssert(tc, "KSI_strncpy failed.", ret == NULL && memcmp(dest, empty, sizeof(dest)) == 0);

	ret = KSI_strncpy(NULL, "12345", 5);
	CuAssert(tc, "KSI_strncpy failed.", ret == NULL && memcmp(dest, empty, sizeof(dest)) == 0);
}

static void test_KSI_strdup(CuTest *tc) {
	int res;
	char *data = "Some random string.";
	char *dup = NULL;

	res = KSI_strdup(data, &dup);
	CuAssert(tc, "Duplicating string failed.", res == KSI_OK && dup != NULL && !strcmp(data, dup));

	KSI_free(dup);
}

static void initTimeStruct(struct tm *time, int YYYY, int MM, int DD, int hh, int mm, int ss) {
	memset(time, 0, sizeof(struct tm));
	time->tm_year = YYYY - 1900;
	time->tm_mon = MM - 1;
	time->tm_mday = DD;

	time->tm_hour = hh;
	time->tm_min = mm;
	time->tm_sec = ss;
}

static void test_CalendarTimeToUnixTime(CuTest *tc) {
	struct tm time;

	initTimeStruct(&time, 2000, 1, 1, 0, 0, 0);
	CuAssert(tc, "Unable to convert calendar time to Unix time.", KSI_CalendarTimeToUnixTime(&time) == 946684800);

	initTimeStruct(&time, 2015, 10, 13, 12, 49, 7);
	CuAssert(tc, "Unable to convert calendar time to Unix time.", KSI_CalendarTimeToUnixTime(&time) == 1444740547);

	initTimeStruct(&time, 1988, 7, 3, 3, 37, 4);
	CuAssert(tc, "Unable to convert calendar time to Unix time.", KSI_CalendarTimeToUnixTime(&time) == 583904224);

	initTimeStruct(&time, 1991, 12, 18, 9, 33, 12);
	CuAssert(tc, "Unable to convert calendar time to Unix time.", KSI_CalendarTimeToUnixTime(&time) == 693048792);

	initTimeStruct(&time, 1995, 8, 26, 17, 7, 23);
	CuAssert(tc, "Unable to convert calendar time to Unix time.", KSI_CalendarTimeToUnixTime(&time) == 809456843);

	initTimeStruct(&time, 1993, 4, 14, 3, 16, 4);
	CuAssert(tc, "Unable to convert calendar time to Unix time.", KSI_CalendarTimeToUnixTime(&time) == 734757364);

	initTimeStruct(&time, 1990, 9, 7, 12, 19, 59);
	CuAssert(tc, "Unable to convert calendar time to Unix time.", KSI_CalendarTimeToUnixTime(&time) == 652709999);

	initTimeStruct(&time, 1990, 9, 7, 12, 19, 59);
	CuAssert(tc, "Unable to convert calendar time to Unix time.", KSI_CalendarTimeToUnixTime(&time) == 652709999);

	initTimeStruct(&time, 1992, 3, 13, 3, 26, 12);
	CuAssert(tc, "Unable to convert calendar time to Unix time.", KSI_CalendarTimeToUnixTime(&time) == 700457172);

	initTimeStruct(&time, 1997, 2, 17, 11, 21, 1);
	CuAssert(tc, "Unable to convert calendar time to Unix time.", KSI_CalendarTimeToUnixTime(&time) == 856178461);
}

CuSuite* KSITest_compatibility_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, test_KSI_snprintf);
	SUITE_ADD_TEST(suite, test_KSI_strncpy);
	SUITE_ADD_TEST(suite, test_KSI_strdup);
	SUITE_ADD_TEST(suite, test_CalendarTimeToUnixTime);

	return suite;
}
