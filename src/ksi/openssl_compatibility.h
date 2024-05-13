/*
 * Copyright 2013-2017 Guardtime, Inc.
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


#ifndef OPENSSL_COMPATIBILITY_H_
#define OPENSSL_COMPATIBILITY_H_

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif


	struct openssl_compatibility_functions_st {
		void (*openssl_setup)(void);
		void (*openssl_cleanup)(void);

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		void* (*mac_ctx_new)(void);
		void (*mac_ctx_free)(void *ctx);
		int (*mac_ctx_reset)(void *ctx, const unsigned char *key, size_t key_len, const EVP_MD *md);
		int (*mac_ctx_update)(void *ctx, const unsigned char *data, size_t data_len);
		int (*mac_ctx_final)(void *ctx, unsigned char *out, size_t out_size, size_t *out_len);
#endif
	};

	extern struct openssl_compatibility_functions_st openssl_compatibility_functions;

	/**
	 * These macros are needed to support both OpenSSL 1.0 and 1.1.
	 *
	 * "If you think good design is expensive, you should look at the cost of bad design."
	 *                                                                     -— Ralf Speth
	 */
	#if OPENSSL_VERSION_NUMBER < 0x10100000L
	#  define KSI_EVP_MD_CTX_create() EVP_MD_CTX_create()
	#  define KSI_EVP_MD_CTX_destroy(md) EVP_MD_CTX_destroy((md))
	#  define KSI_EVP_MD_CTX_cleanup(md) EVP_MD_CTX_cleanup((md))
	#else
	#  define KSI_EVP_MD_CTX_create() EVP_MD_CTX_new()
	#  define KSI_EVP_MD_CTX_destroy(md) EVP_MD_CTX_free((md))
	#  define KSI_EVP_MD_CTX_cleanup(md) EVP_MD_CTX_reset((md))
	#endif


#ifdef __cplusplus
}
#endif

#endif /* OPENSSL_COMPATIBILITY_H_ */
