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
#include <ksi/hmac.h>

extern KSI_CTX *ctx;


struct testData {
	KSI_HashAlgorithm algo_id;
	
	char *key;
	
	unsigned char *message;
	unsigned int message_len;
	
	char *ref_result;
};

#define COUNT 2

#define KEY_1 "secret"
#define MSG_1 "message"
#define RES_1_SHA1 "000caf649feee4953d87bf903ac1176c45e028df16"
#define RES_1_SHA256 "018b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b"
#define RES_1_SHA512 "051bba587c730eedba31f53abb0b6ca589e09de4e894ee455e6140807399759adaafa069eec7c01647bb173dcb17f55d22af49a18071b748c5c2edd7f7a829c632"

#define KEY_2 "s"
#define MSG_2 "m"
#define RES_2_SHA1 "00f0ed6a60f66e9dfc4b967ff5c9ea9feca17e0bed"
#define RES_2_SHA256 "018e1e1cf905ed55f131230070478633764a859f8a53a59abd6be9721f5662c715"
#define RES_2_SHA512 "057cb8cf7e21394b6791205a9c14cae518131a603b8cb1f3d7449d63b98cac80202ef4f2e1474eed6d1c1edbd0a360433493fb329336e73de293c8e4a00c165940"

#define KEY_3 "secretkeyislongerthan_64secretkeyislongerthan_64secretkeyislongerthan_64secretkeyislongerthan_64"
#define MSG_3 "message"
#define RES_3_SHA1 "00456e75f2ae29cfc90b18bcc0c77ebcc8cb7beb18"
#define RES_3_SHA256 "01bf5e4d4ab708f50f5f54ba8b78941077e221dbcd28b202a07a38691d6b36e85a"
#define RES_3_SHA512 "05187818ac44ff4554148c5488d424b80be8c3b736a83969ea4088ff5f10b9e52ea1f11e1a6e9951f849d8f0c41ae94ed86ee00ccccf9ae8fae00df557513cde96"

#define STR_KEY_MSG(alg, key, msg, ref) {alg, key, (unsigned char *)msg, (sizeof(msg)-1),ref}



static void dotest(CuTest* tc, struct testData *data, int count) {
	int res;
	KSI_DataHash *hmac = NULL;
	char buf[1024];
	int i = 0;
	
	for (;i<count;i++){
		res = KSI_HMAC_create(ctx, data[i].algo_id, data[i].key, data[i].message, data[i].message_len, &hmac);
		CuAssert(tc, "Failed crete HMAC", res == KSI_OK && hmac != NULL);
		KSI_DataHash_toString(hmac,buf, sizeof(buf));
		if (strcmp(data[i].ref_result, buf)) {
			KSI_LOG_debug(ctx, "Expecting HMAC: %s", data[i].ref_result);
			KSI_LOG_debug(ctx, "Actual HMAC:    %s", buf);

			/* Just being polite. */
			KSI_DataHash_free(hmac);
			hmac = NULL;

			/* Fail and exit test. */
			CuFail(tc, "HMAC mismatch");
		}
		KSI_DataHash_free(hmac);
		hmac = NULL;
	}
	
	KSI_DataHash_free(hmac);
}


static void TestSHA1(CuTest* tc) {
	struct testData TEST_SHA1[] ={
		STR_KEY_MSG(KSI_HASHALG_SHA1, KEY_1, MSG_1, RES_1_SHA1),
		STR_KEY_MSG(KSI_HASHALG_SHA1, KEY_2, MSG_2, RES_2_SHA1),
		STR_KEY_MSG(KSI_HASHALG_SHA1, KEY_3, MSG_3, RES_3_SHA1)
	};
	
	int count = sizeof(TEST_SHA1)/sizeof(struct testData);
	
	dotest(tc, TEST_SHA1, count);
}

static void TestSHA256(CuTest* tc) {
	struct testData TEST_SHA256[] ={
		STR_KEY_MSG(KSI_HASHALG_SHA2_256, KEY_1, MSG_1, RES_1_SHA256),
		STR_KEY_MSG(KSI_HASHALG_SHA2_256, KEY_2, MSG_2, RES_2_SHA256),
		STR_KEY_MSG(KSI_HASHALG_SHA2_256, KEY_3, MSG_3, RES_3_SHA256)
	};
	
	int count = sizeof(TEST_SHA256)/sizeof(struct testData);
	
	dotest(tc, TEST_SHA256, count);
}

static void TestSHA512(CuTest* tc) {
	struct testData TEST_SHA256[] ={
		STR_KEY_MSG(KSI_HASHALG_SHA2_512, KEY_1, MSG_1, RES_1_SHA512),
		STR_KEY_MSG(KSI_HASHALG_SHA2_512, KEY_2, MSG_2, RES_2_SHA512),
		STR_KEY_MSG(KSI_HASHALG_SHA2_512, KEY_3, MSG_3, RES_3_SHA512),
	};

	int count = sizeof(TEST_SHA256)/sizeof(struct testData);

	dotest(tc, TEST_SHA256, count);
}




CuSuite* KSITest_HMAC_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestSHA1);
	SUITE_ADD_TEST(suite, TestSHA256);
	SUITE_ADD_TEST(suite, TestSHA512);

	return suite;
}
