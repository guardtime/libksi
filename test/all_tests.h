/*
 * all_tests.h
 *
 *  Created on: 06.02.2014
 *      Author: henri
 */

#ifndef ALL_TESTS_H_
#define ALL_TESTS_H_

#include "cutest/CuTest.h"
#include "../src/ksi_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define lprintf printf("%s:%d - ", __FILE__, __LINE__); printf

CuSuite* KSI_CTX_GetSuite(void);
CuSuite* KSI_LOG_GetSuite(void);
CuSuite* KSI_RDR_GetSuite(void);
CuSuite* KSI_TLV_GetSuite(void);
CuSuite* KSI_TLV_Sample_GetSuite(void);

#ifdef __cplusplus
}
#endif

#endif /* ALL_TESTS_H_ */
