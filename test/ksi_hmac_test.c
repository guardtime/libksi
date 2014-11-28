#include <stdio.h>
#include <string.h>

#include "cutest/CuTest.h"
#include "all_tests.h"
#include <ksi/hmac.h>

extern KSI_CTX *ctx;


struct testData {
	int hashAlg;
	
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

#define KEY_2 "s"
#define MSG_2 "m"
#define RES_2_SHA1 "00f0ed6a60f66e9dfc4b967ff5c9ea9feca17e0bed"
#define RES_2_SHA256 "018e1e1cf905ed55f131230070478633764a859f8a53a59abd6be9721f5662c715"

#define KEY_3 "secretkeyislongerthan_64secretkeyislongerthan_64secretkeyislongerthan_64secretkeyislongerthan_64"
#define MSG_3 "message"
#define RES_3_SHA1 "00456e75f2ae29cfc90b18bcc0c77ebcc8cb7beb18"
#define RES_3_SHA256 "01bf5e4d4ab708f50f5f54ba8b78941077e221dbcd28b202a07a38691d6b36e85a"

#define STR_KEY_MSG(alg, key, msg, ref) {alg, key, (unsigned char *)msg, (sizeof(msg)-1),ref}



static void dotest(CuTest* tc, struct testData *data, int count){
	int res;
	KSI_DataHash *hmac = NULL;
	char buf[1024];
	int i = 0;
	
	for(;i<count;i++){
		res = KSI_HMAC_create(ctx, data[i].hashAlg, data[i].key, data[i].message, data[i].message_len, &hmac);
		CuAssert(tc, "Failed crete HMAC", res == KSI_OK && hmac != NULL);
		KSI_DataHash_toString(hmac,buf, sizeof(buf));
		CuAssert(tc, "HMAC mismatch", strcmp(data[i].ref_result, buf)==0);
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





CuSuite* KSITest_HMAC_getSuite(void) {
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, TestSHA1);
	SUITE_ADD_TEST(suite, TestSHA256);

	return suite;
}
