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
#include <stdlib.h>

#include "all_tests.h"
#include "../src/ksi/version.h"

#define BUFF_SIZE 100
#define VERSION_FILE "VERSION"

static void testCompareVesions(CuTest* tc) {
	FILE *f = NULL;
	char verStr[BUFF_SIZE];
	char *readRes = NULL;
	unsigned int verNums[3];
	size_t i = 0;
	char *chNum = NULL;

	f = fopen(VERSION_FILE, "r");
	CuAssert(tc, "Unable to open version file", f != NULL);

	readRes = fgets(verStr, BUFF_SIZE, f);
	CuAssert(tc, "Unable to read version string", readRes != NULL);

	fclose(f);

	chNum = strtok(verStr, ".");
	while (chNum != NULL) {
		verNums[i] = atoi(chNum);

		i++;
		chNum = strtok(NULL, ".");
		CuAssert(tc, "Inconsistency in version string format. Should be: X.Y.Z", !(i >= 3 && chNum != NULL));
	}

	CuAssert(tc, "Failed to verify SDK version major number", KSI_SDK_VER_MAJOR == verNums[0]);
	CuAssert(tc, "Failed to verify SDK version minor number", KSI_SDK_VER_MINOR == verNums[1]);
	CuAssert(tc, "Failed to verify SDK version build number", KSI_SDK_VER_BUILD == verNums[2]);
}

CuSuite* KSITest_versionNumber_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, testCompareVesions);

	return suite;
}
