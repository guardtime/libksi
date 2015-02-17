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

#include <stdio.h>
#include <string.h>

#include "cutest/CuTest.h"
#include "all_tests.h"
#include <ksi/compatibility.h>

static void Test_KSI_snprintf(CuTest* tc) {
	int ret;
	char dest[8];
	char empty[8];
	
	memset(dest, 0xFF, sizeof(dest));
	memset(empty, 0xFF, sizeof(empty));
	
	ret = KSI_snprintf(dest, 8, "%s", "1234567890");
	CuAssert(tc, "KSI_snprintf failed.", ret == 7 && dest[7] == 0 && strcmp(dest, "1234567") == 0);
	memset(dest, 0xFF, sizeof(dest));
	
	ret = KSI_snprintf(dest, 4, "%s", "1234567890");
	CuAssert(tc, "KSI_snprintf failed.", ret == 3 && dest[3] == 0 && strcmp(dest, "123") == 0);
	memset(dest, 0xFF, sizeof(dest));
	
	ret = KSI_snprintf(dest, 8, "%s", "12345");
	CuAssert(tc, "KSI_snprintf failed.", ret == 5 && dest[5] == 0 && strcmp(dest, "12345") == 0);
	memset(dest, 0xFF, sizeof(dest));
	
	ret = KSI_snprintf(dest, 0, "%s", "12345");
	CuAssert(tc, "KSI_snprintf failed.", ret == -1 && memcmp(dest, empty, sizeof(dest)) == 0);
	
	ret = KSI_snprintf(NULL, 5, "%s", "12345");
	CuAssert(tc, "KSI_snprintf failed.", ret == -1 && memcmp(dest, empty, sizeof(dest)) == 0);
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
