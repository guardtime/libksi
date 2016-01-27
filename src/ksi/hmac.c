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

#include <string.h>

#include "internal.h"
#include "hmac.h"

#define MAX_BUF_LEN 128

int KSI_HMAC_create(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, const char *key, const unsigned char *data, size_t data_len, KSI_DataHash **hmac) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hashedKey = NULL;
	KSI_DataHash *innerHash = NULL;
	KSI_DataHash *outerHash = NULL;
	unsigned blockSize = 0;

	size_t key_len;
	const unsigned char *bufKey = NULL;
	size_t buf_len;
	unsigned char ipadXORkey[MAX_BUF_LEN];
	unsigned char opadXORkey[MAX_BUF_LEN];
	const unsigned char *digest = NULL;
	size_t digest_len = 0;
	size_t i;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || key == NULL || data == NULL || data_len == 0 || hmac == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	key_len = strlen(key);
	if (key_len == 0 || key_len > 0xffff) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Invalid key length.");
		goto cleanup;
	}

	blockSize = KSI_HashAlgorithm_getBlockSize(algo_id);
	if (blockSize == 0) {
		KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Unknown buffer length for hash algorithm.");
		goto cleanup;
	}

	if (KSI_getHashLength(algo_id) > MAX_BUF_LEN || blockSize > MAX_BUF_LEN) {
		KSI_pushError(ctx, res = KSI_BUFFER_OVERFLOW, "Internal buffer too short to calculate HMAC.");
		goto cleanup;
	}

	/* Open the hasher. */
	res = KSI_DataHasher_open(ctx, algo_id, &hsr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Prepare the key for hashing. */
	/* If the key is longer than 64, hash it. If the key or its hash is shorter than 64 bit, append zeros. */
	if (key_len > blockSize) {
		res = KSI_DataHasher_add(hsr, key, key_len);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_DataHasher_close(hsr, &hashedKey);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_DataHash_extract(hashedKey, NULL, &digest, &digest_len);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (digest == NULL || digest_len > blockSize) {
			KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "The hash of the key is invalid");
			goto cleanup;
		}

		bufKey = digest;
		buf_len = digest_len;
	} else {
		bufKey = (const unsigned char *) key;
		buf_len = key_len;
	}

	for (i = 0; i < buf_len; i++) {
		ipadXORkey[i] = 0x36 ^ bufKey[i];
		opadXORkey[i] = 0x5c ^ bufKey[i];
	}

	for (; i < blockSize; i++) {
		ipadXORkey[i] = 0x36;
		opadXORkey[i] = 0x5c;
	}

	/* Hash inner data. */
	res = KSI_DataHasher_reset(hsr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Adding ipad", ipadXORkey, blockSize);
	res = KSI_DataHasher_add(hsr, ipadXORkey, blockSize);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "data:", data, data_len);
	res = KSI_DataHasher_add(hsr, data, data_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_debug(ctx, "Closing inner hasher");

	res = KSI_DataHasher_close(hsr, &innerHash);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Hash outer data. */
	res = KSI_DataHasher_reset(hsr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Adding opad", opadXORkey, blockSize);
	res = KSI_DataHasher_add(hsr, opadXORkey, blockSize);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_extract(innerHash, NULL, &digest, &digest_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logBlob(ctx, KSI_LOG_DEBUG, "Adding inner hash", digest, digest_len);
	res = KSI_DataHasher_add(hsr, digest, digest_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_debug(ctx, "Closing outer hasher");

	res = KSI_DataHasher_close(hsr, &outerHash);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hmac = KSI_DataHash_ref(outerHash);

	res = KSI_OK;

cleanup:

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hashedKey);
	KSI_DataHash_free(innerHash);
	KSI_DataHash_free(outerHash);

	return res;
}
