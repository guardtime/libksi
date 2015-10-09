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

#ifndef ALL_TESTS_H_
#define ALL_TESTS_H_

#include <ksi/ksi.h>
#include "cutest/CuTest.h"
#include "ksi_net_mock.h"
#include <ksi/compatibility.h>
#include <ksi/err.h>
#include "support_tests.h"

#ifdef __cplusplus
extern "C" {
#endif

#define lprintf //printf("%s:%d - ", __FILE__, __LINE__); printf

int KSITest_memcmp(void *ptr1, void *ptr2, size_t len);

int KSITest_DataHash_fromStr(KSI_CTX *ctx, const char *hexstr, KSI_DataHash **hsh);
int KSITest_decodeHexStr(const char *hexstr, unsigned char *buf, size_t buf_size, size_t *buf_length);
void KSITest_setFileMockResponse(CuTest *tc, const char *fileName);

int KSI_NET_MOCK_new(KSI_CTX *ctx, KSI_NetworkClient **provider);

CuSuite* KSITest_CTX_getSuite(void);
CuSuite* KSITest_RDR_getSuite(void);
CuSuite* KSITest_TLV_getSuite(void);
CuSuite* KSITest_TLV_Sample_getSuite(void);
CuSuite* KSITest_Hash_getSuite(void);
CuSuite* KSITest_NET_getSuite(void);
CuSuite* KSITest_HashChain_getSuite(void);
CuSuite* KSI_UTIL_GetSuite(void);
CuSuite* KSITest_Signature_getSuite(void);
CuSuite* KSITest_Publicationsfile_getSuite(void);
CuSuite* KSITest_Truststore_getSuite(void);
CuSuite* KSITest_HMAC_getSuite(void);
CuSuite* KSITest_compatibility_getSuite(void);
CuSuite* KSITest_uriClient_getSuite(void);
CuSuite* KSITest_multiSignature_getSuite(void);

#ifdef __cplusplus
}
#endif

#endif /* ALL_TESTS_H_ */
