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

#ifndef TEST_CONF_H
#define	TEST_CONF_H

#include <ksi/ksi.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define CONF_FIELD_SIZE 1024
#define CONF_MAX_CONSTRAINTS 32

typedef struct KSITest_ServiceConf_st {
	char host[CONF_FIELD_SIZE];
	unsigned port;
	char pass[CONF_FIELD_SIZE];
	char user[CONF_FIELD_SIZE];
	char hmac[CONF_FIELD_SIZE];
} KSITest_ServiceConf;

typedef struct KSITest_PubfileConf_st {
	char url[CONF_FIELD_SIZE];
	char cnstr[CONF_MAX_CONSTRAINTS][CONF_FIELD_SIZE];

	/* Helper members. */
	unsigned int cnstrCount;
	KSI_CertConstraint certConstraints[CONF_MAX_CONSTRAINTS + 1];
} KSITest_PubfileConf;

typedef struct KSITest_Conf_st {
	KSITest_ServiceConf extender;
	KSITest_ServiceConf aggregator;

	KSITest_PubfileConf pubfile;
} KSITest_Conf;


/* Returns 0 if successful, 1 otherwise. */
int KSITest_Conf_load(const char *confFile, KSITest_Conf *conf);


#ifdef	__cplusplus
}
#endif

#endif	/* TEST_CONF_H */

