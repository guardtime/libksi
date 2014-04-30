#ifndef ALL_TESTS_H_
#define ALL_TESTS_H_

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define lprintf //printf("%s:%d - ", __FILE__, __LINE__); printf

int debug_memcmp(void *ptr1, void *ptr2, size_t len);

int KSI_NET_MOCK_new(KSI_CTX *ctx, KSI_NetProvider **provider);

CuSuite* KSI_CTX_GetSuite(void);
CuSuite* KSI_LOG_GetSuite(void);
CuSuite* KSI_RDR_GetSuite(void);
CuSuite* KSI_TLV_GetSuite(void);
CuSuite* KSI_TLV_Sample_GetSuite(void);
CuSuite* KSI_Hash_GetSuite(void);
CuSuite* KSI_NET_GetSuite(void);
CuSuite* KSI_HashChain_GetSuite(void);
CuSuite* KSI_UTIL_GetSuite(void);
CuSuite* KSI_Signature_getSuite(void);

#ifdef __cplusplus
}
#endif

#endif /* ALL_TESTS_H_ */
