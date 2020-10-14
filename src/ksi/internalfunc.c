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

#include "internalfunc.h"

#if KSI_HASH_IMPL == KSI_IMPL_OPENSSL || KSI_PKI_TRUSTSTORE_IMPL == KSI_IMPL_OPENSSL
static KSI_HashAlgorithm EVPTohashAlgorithm(const EVP_MD *hash_id);
static const EVP_MD *hashAlgorithmToEVP(KSI_HashAlgorithm hash_id);
#endif

struct KSI_InternalFunctions_st InternalFunc = {
#if KSI_HASH_IMPL == KSI_IMPL_OPENSSL || KSI_PKI_TRUSTSTORE_IMPL == KSI_IMPL_OPENSSL
	EVPTohashAlgorithm,
	hashAlgorithmToEVP,
#endif
	NULL
};

#if KSI_HASH_IMPL == KSI_IMPL_OPENSSL || KSI_PKI_TRUSTSTORE_IMPL == KSI_IMPL_OPENSSL
static const EVP_MD *algorithmMapper[KSI_NUMBER_OF_KNOWN_HASHALGS];
static int isRegistred = 0;

static const char* getOpenSSLName(KSI_HashAlgorithm algo_id) {
	switch(algo_id) {
		case KSI_HASHALG_SHA1: return "sha1";
		case KSI_HASHALG_SHA2_256: return "sha256";
		case KSI_HASHALG_RIPEMD160: return "ripemd160";
		case KSI_HASHALG_SHA2_384: return "sha384";
		case KSI_HASHALG_SHA2_512: return "sha512";
//		case KSI_HASHALG_SHA3_224: return "sha3-224";
		case KSI_HASHALG_SHA3_256: return "sha3-256";
		case KSI_HASHALG_SHA3_384: return "sha3-384";
		case KSI_HASHALG_SHA3_512: return "sha3-512";
		case KSI_HASHALG_SM3: return "sm3";
		default: return NULL;
	}
}

static void registerSupportedAlgorithms() {
	KSI_HashAlgorithm algo_id;

	for (algo_id = 0; algo_id < KSI_NUMBER_OF_KNOWN_HASHALGS; algo_id++) {
		const char *name = getOpenSSLName(algo_id);
		algorithmMapper[algo_id] = EVP_get_digestbyname(name);
	}
	isRegistred = 1;
}

/**
 * Converts hash function ID from hash chain to OpenSSL identifier.
 */
static const EVP_MD *hashAlgorithmToEVP(KSI_HashAlgorithm hash_id) {
	if (hash_id >= KSI_NUMBER_OF_KNOWN_HASHALGS) return NULL;
	if (!isRegistred) registerSupportedAlgorithms();
	return algorithmMapper[hash_id];
}

/**
 * Converts OpenSSL hash function ID to hash function ID from hash chain.
 */
static KSI_HashAlgorithm EVPTohashAlgorithm(const EVP_MD *hash_id) {
	KSI_HashAlgorithm algo_id;
	if (hash_id == NULL) return KSI_HASHALG_INVALID_VALUE;
	if (!isRegistred) registerSupportedAlgorithms();
	for (algo_id = 0; algo_id < KSI_NUMBER_OF_KNOWN_HASHALGS; algo_id++) {
		if (algorithmMapper[algo_id] == hash_id) return algo_id;
	}
	return KSI_HASHALG_INVALID_VALUE;
}
#endif