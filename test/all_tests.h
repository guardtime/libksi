#ifndef ALL_TESTS_H_
#define ALL_TESTS_H_

#include "cutest/CuTest.h"
#include "ksi/ksi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define lprintf //printf("%s:%d - ", __FILE__, __LINE__); printf

int KSITest_memcmp(void *ptr1, void *ptr2, size_t len);

int KSITest_decodeHexStr(const char *hexstr, unsigned char *buf, int buf_size, unsigned *buf_length);
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

#ifdef __cplusplus
}
#endif

#endif /* ALL_TESTS_H_ */
