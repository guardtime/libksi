/*
 * Copyright 2013-2016 Guardtime, Inc.
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

#ifndef POLICY_H
#define	POLICY_H

#include "list.h"

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum VerificationResultCode_en {
	OK,
	NA,
	FAIL
} VerificationResultCode;

typedef enum VerificationErrorCode_en {
	GEN_1,
	GEN_2,
	INT_1,
	INT_2,
	INT_3,
	INT_4,
	INT_5,
	INT_6,
	INT_7,
	INT_8,
	INT_9,
	PUB_1,
	PUB_2,
	PUB_3,
	KEY_1,
	KEY_2,
	CAL_1,
	CAL_2,
	CAL_3,
	CAL_4
} VerificationErrorCode;

struct VerificationResult_st {
	VerificationResultCode resultCode;
	VerificationErrorCode errorCode;
};

typedef struct VerificationResult_st KSI_RuleVerificationResult;
typedef struct VerificationResult_st KSI_PolicyVerificationResult;

typedef struct VerificationPolicy_st KSI_Policy;

typedef struct VerificationContext_st VerificationContext;

#ifdef	__cplusplus
}
#endif

#endif	/* POLICY_H */
