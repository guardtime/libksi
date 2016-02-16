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

#ifndef POLICY_IMPL_H
#define	POLICY_IMPL_H

#include "policy.h"
#include "list.h"
#include "internal.h"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct Rule_st Rule;
KSI_DEFINE_LIST(Rule);

typedef struct VerificationResult_st PolicyVerificationResult;
KSI_DEFINE_LIST(PolicyVerificationResult);

typedef enum RuleType_en {
	RULE_TYPE_BASIC,
	RULE_TYPE_COMPOSITE
} RuleType;

typedef int (*Verifier)(KSI_Signature *, KSI_RuleVerificationResult *);

typedef struct BasicRule_st {
	KSI_RuleVerificationResult result;
	Verifier verifySignature;
} BasicRule;

typedef struct CompositeRule_st {
	KSI_RuleVerificationResult result;
	bool skipOnFirstOk;
	KSI_LIST(Rule) *rules;
} CompositeRule;

struct Rule_st {
	RuleType type;
	KSI_RuleVerificationResult result;
	union {
		BasicRule *basicRule;
		CompositeRule *compositeRule;
	} rule;
};

struct VerificationPolicy_st {
	KSI_PolicyVerificationResult result;
	KSI_Policy *fallbackPolicy;
	KSI_LIST(Rule) *rules;
};

struct VerificationContext_st {
	bool extendingAllowed;
	KSI_CTX *ctx;
	KSI_Signature *sig;
};

#ifdef	__cplusplus
}
#endif

#endif	/* POLICY_IMPL_H */
