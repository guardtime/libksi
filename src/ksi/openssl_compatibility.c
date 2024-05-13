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


#include "openssl_compatibility.h"
#include "internal.h"
#include "hash.h"
#include "tlv_template.h"
#include <string.h>
#include <stddef.h>


#if (KSI_PKI_TRUSTSTORE_IMPL == KSI_IMPL_OPENSSL) || (KSI_HASH_IMPL == KSI_IMPL_OPENSSL)

#	include <openssl/evp.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#	include <openssl/provider.h>
#	include <openssl/core_names.h>
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
#	include <openssl/hmac.h>
#endif




//     0x1    01   0000        0
// [32:28][27:20][19 :4][3  :  0]
// [major][minor][patch][release]

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	static OSSL_PROVIDER *_legacy = NULL;
	static OSSL_PROVIDER *_default = NULL;
	static EVP_MAC *mac_impl = NULL;
#endif


#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	void static openssl_setup(void) {
		OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
		_default = OSSL_PROVIDER_load(NULL, "default"); // To support ripemd160.
		_legacy = OSSL_PROVIDER_load(NULL, "legacy"); // To support ripemd160.
		mac_impl = EVP_MAC_fetch(NULL, "HMAC", NULL);
	}

	void static openssl_cleanup(void) {
		EVP_MAC_free(mac_impl);
		OSSL_PROVIDER_unload(_legacy);
		OSSL_PROVIDER_unload(_default);
		OPENSSL_cleanup();
	}

	static void* openssl_mac_ctx_new(void) {
		return EVP_MAC_CTX_new(mac_impl);
	}

	static void openssl_mac_ctx_free(void *ctx) {
		return EVP_MAC_CTX_free(ctx);
	}

	static int openssl_mac_ctx_reset(void *ctx, const unsigned char *key, size_t key_len, const EVP_MD *md) {
		const char *digest = NULL;
		OSSL_PARAM params[2];
		digest = EVP_MD_name(md);
		params[0] = OSSL_PARAM_construct_utf8_string("digest", (char*)digest, 0);
		params[1] = OSSL_PARAM_construct_end();
		return EVP_MAC_init(ctx, key, key_len, params);
	}

	static int openssl_mac_ctx_update(void *ctx, const unsigned char *data, size_t data_len) {
		return EVP_MAC_update(ctx, data, data_len);
	}

	static int openssl_mac_ctx_final(void *ctx, unsigned char *out, size_t out_size, size_t *out_len) {
		return EVP_MAC_final(ctx, out, out_len, out_size);
	}
#elif OPENSSL_VERSION_NUMBER >= 0x10100000L
	void static openssl_setup(void) {
		OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
	}

	void static openssl_cleanup(void) {
		OPENSSL_cleanup();
	}

	static void* openssl_mac_ctx_new(void) {
		return HMAC_CTX_new();
	}

	static void openssl_mac_ctx_free(void *ctx) {
		return HMAC_CTX_free(ctx);
	}

	static int openssl_mac_ctx_reset(void *ctx, const unsigned char *key, size_t key_len, const EVP_MD*md) {
		if (!HMAC_CTX_reset(ctx)) return 0;
		if (!HMAC_Init_ex(ctx, key, key_len, md, NULL)) return 0;
		return 1;
	}

	static int openssl_mac_ctx_update(void *ctx, const unsigned char *data, size_t data_len) {
		return HMAC_Update(ctx, data, data_len);
	}

	static int openssl_mac_ctx_final(void *ctx, unsigned char *out, size_t out_size, size_t *out_len) {
		int ret = 0;
		unsigned int tmp_len = 0;

		ret = HMAC_Final(ctx, out, &tmp_len);
		if(!ret) return ret;
		*out_len = tmp_len;
		return 1;
	}
#else
	void static openssl_setup(void) {
		OpenSSL_add_all_digests();
	}

	void static openssl_cleanup(void) {
		EVP_cleanup();
	}
#endif

struct openssl_compatibility_functions_st openssl_compatibility_functions = {
	openssl_setup,
	openssl_cleanup,
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
	openssl_mac_ctx_new,
	openssl_mac_ctx_free,
	openssl_mac_ctx_reset,
	openssl_mac_ctx_update,
	openssl_mac_ctx_final,
#endif
};



#endif