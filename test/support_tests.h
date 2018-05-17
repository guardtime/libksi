#ifndef SUPPORT_TESTS_H
#define	SUPPORT_TESTS_H

#include "cutest/CuTest.h"
#include "test_conf.h"

#include <ksi/types_base.h>
#include <ksi/hash.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define KSITEST_ASYNC_SLEEP_TIME_MS 100
#define KSITEST_ASYNC_NO_RESP_TIMEOUT_MS (100 * 10 * 5)

void addSuite(CuSuite *suite, CuSuite* (*fn)(void));

void printStats(CuSuite *suite, const char *heding);

void initFullResourcePath(const char* rootDir);
const char *getFullResourcePath(const char* resource);
const char *getFullResourcePathUri(const char* resource);

void writeXmlReport(CuSuite *suite, const char *fname);

int ctx_get_base_external_error(KSI_CTX *ctx);

int KSITest_decodeHexStr(const char *hexstr, unsigned char *buf, size_t buf_size, size_t *buf_length);
int KSITest_DataHash_fromStr(KSI_CTX *ctx, const char *hexstr, KSI_DataHash **hsh);
int KSITest_memcmp(void *ptr1, void *ptr2, size_t len);

#define TEST_SCHEME_HTTP "ksi+http"
#define TEST_SCHEME_TCP "ksi+tcp"

const char *KSITest_composeUri(const char *scheme, const KSITest_ServiceConf *service);

#ifdef	__cplusplus
}
#endif

#endif	/* SUPPORT_TESTS_H */

