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
#include "support_tests.h"

#ifdef	__cplusplus
extern "C" {
#endif

#define CONF_FIELD_SIZE 1024
#define CONF_MAX_CONSTRAINTS 32
typedef struct CONF_st {
	char extender_url[CONF_FIELD_SIZE];
	char extender_pass[CONF_FIELD_SIZE];
	char extender_user[CONF_FIELD_SIZE];

	char aggregator_url[CONF_FIELD_SIZE];
	char aggregator_pass[CONF_FIELD_SIZE];
	char aggregator_user[CONF_FIELD_SIZE];

	char publications_file_url[CONF_FIELD_SIZE];
	char publications_file_cnstr[CONF_FIELD_SIZE];

	char tcp_url[CONF_FIELD_SIZE];
	char tcp_host[CONF_FIELD_SIZE];
	unsigned tcp_port;
	char tcp_user[CONF_FIELD_SIZE];
	char tcp_pass[CONF_FIELD_SIZE];

	unsigned int constraints;
	char oid[CONF_MAX_CONSTRAINTS][CONF_FIELD_SIZE];
	char val[CONF_MAX_CONSTRAINTS][CONF_FIELD_SIZE];
	KSI_CertConstraint testPubFileCertConstraints[CONF_MAX_CONSTRAINTS + 1];

} CONF;

extern CONF conf;

const char *getFullResourcePath(const char* resource);
const char *getFullResourcePathUri(const char* resource);

CuSuite* AggreIntegrationTests_getSuite(void);
CuSuite* ExtIntegrationTests_getSuite(void);
CuSuite* PubIntegrationTests_getSuite(void);

#ifdef	__cplusplus
}
#endif

#endif	/* ALL_INTEGRATION_TESTS_H */

