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

static void Test_KSI_snprintf(CuTest* tc) {
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

static void Test_KSI_strncpy(CuTest* tc) {
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


CuSuite* KSITest_compatibility_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, Test_KSI_snprintf);
	SUITE_ADD_TEST(suite, Test_KSI_strncpy);

	return suite;
}
