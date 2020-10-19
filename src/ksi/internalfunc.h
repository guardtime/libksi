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

/**
 * This file may only be included internally to share functions that may not be
 * exported width libksi.
 */

#ifndef INTERNALFUNC_H_
#define INTERNALFUNC_H_

#include "ksi.h"
#include "internal.h"

#if KSI_HASH_IMPL == KSI_IMPL_OPENSSL || KSI_PKI_TRUSTSTORE_IMPL == KSI_IMPL_OPENSSL
#	include <openssl/evp.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct KSI_InternalFunctions_st {
#if KSI_HASH_IMPL == KSI_IMPL_OPENSSL || KSI_PKI_TRUSTSTORE_IMPL == KSI_IMPL_OPENSSL
	const KSI_HashAlgorithm (*const EVPTohashAlgorithm)(const EVP_MD *hash_id);
	const EVP_MD* (*const hashAlgorithmToEVP)(KSI_HashAlgorithm hash_id);
#endif

	/* Value with no effect, do not use. May be removed in future. */
	void *_reserved;
};

/**
 * Internally used data structure for sharing internal function.
 */
extern struct KSI_InternalFunctions_st InternalFunc;

#ifdef __cplusplus
}
#endif

#endif /* INTERNALFUNC_H_*/