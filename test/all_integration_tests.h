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

#ifndef ALL_INTEGRATION_TESTS_H
#define	ALL_INTEGRATION_TESTS_H

#include <ksi/ksi.h>
#include "cutest/CuTest.h"
#include <ksi/compatibility.h>
#include <ksi/err.h>


#ifdef	__cplusplus
extern "C" {
#endif

extern const char *aggreURL;
extern const char *aggreUser;
extern const char *aggrePass;
extern const char *extURL;
extern const char *extUser;
extern const char *extPass;	
	
const char *getFullResourcePath(const char* resource);

CuSuite* AggreIntegrationTests_getSuite(void);
CuSuite* ExtIntegrationTests_getSuite(void);

#ifdef	__cplusplus
}
#endif

#endif	/* ALL_INTEGRATION_TESTS_H */

