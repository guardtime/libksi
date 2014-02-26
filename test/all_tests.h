#ifndef ALL_TESTS_H_
#define ALL_TESTS_H_

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"
#include "../src/ksi_tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

#define lprintf //printf("%s:%d - ", __FILE__, __LINE__); printf

int debug_memcmp(void *ptr1, void *ptr2, size_t len);

CuSuite* KSI_CTX_GetSuite(void);
CuSuite* KSI_LOG_GetSuite(void);
CuSuite* KSI_RDR_GetSuite(void);
CuSuite* KSI_TLV_GetSuite(void);
CuSuite* KSI_TLV_Sample_GetSuite(void);

#ifdef __cplusplus
}
#endif

#endif /* ALL_TESTS_H_ */
