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
#include "hmac_impl.h"

int KSI_HMAC_create(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, const char *key, const unsigned char *data, size_t data_len, KSI_DataHash **hmac) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HmacHasher *hasher = NULL;
	KSI_DataHash *tmp_hmac = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || hmac == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_HmacHasher_open(ctx, algo_id, key, &hasher);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_HmacHasher_add(hasher, data, data_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_HmacHasher_close(hasher, &tmp_hmac);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hmac = tmp_hmac;
	tmp_hmac = NULL;
	res = KSI_OK;

cleanup:

	KSI_DataHash_free(tmp_hmac);
	KSI_HmacHasher_free(hasher);

	return res;
}

int KSI_HmacHasher_open(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, const char *key, KSI_HmacHasher **hasher) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HmacHasher *tmp_hasher = NULL;
	KSI_DataHash *hashedKey = NULL;
	unsigned blockSize = 0;

	size_t key_len;
	const unsigned char *bufKey = NULL;
	size_t buf_len;
	const unsigned char *digest = NULL;
	size_t digest_len = 0;
	size_t i;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || key == NULL || hasher == NULL) {
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

	tmp_hasher = KSI_new(KSI_HmacHasher);
	if (tmp_hasher == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	memset(tmp_hasher, sizeof(KSI_HmacHasher), 1);
	tmp_hasher->blockSize = 0;
	tmp_hasher->ctx = ctx;
	tmp_hasher->dataHasher = NULL;

	/* Open the data hasher. */
	res = KSI_DataHasher_open(ctx, algo_id, &tmp_hasher->dataHasher);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp_hasher->ctx = ctx;
	tmp_hasher->blockSize = blockSize;

	/* Prepare the key for hashing. */
	/* If the key is longer than 64, hash it. If the key or its hash is shorter than 64 bit, append zeros. */
	if (key_len > blockSize) {
		res = KSI_DataHasher_add(tmp_hasher->dataHasher, key, key_len);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_DataHasher_close(tmp_hasher->dataHasher, &hashedKey);
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
		tmp_hasher->ipadXORkey[i] = 0x36 ^ bufKey[i];
		tmp_hasher->opadXORkey[i] = 0x5c ^ bufKey[i];
	}

	for (; i < blockSize; i++) {
		tmp_hasher->ipadXORkey[i] = 0x36;
		tmp_hasher->opadXORkey[i] = 0x5c;
	}

	res = KSI_HmacHasher_reset(tmp_hasher);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hasher = tmp_hasher;
	tmp_hasher = NULL;
	res = KSI_OK;

cleanup:

	KSI_DataHash_free(hashedKey);
	KSI_HmacHasher_free(tmp_hasher);

	return res;
}

int KSI_HmacHasher_reset(KSI_HmacHasher *hasher) {
	int res = KSI_UNKNOWN_ERROR;

	if (hasher == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	res = KSI_DataHasher_reset(hasher->dataHasher);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	/* Hash inner data. */
	KSI_LOG_logBlob(hasher->ctx, KSI_LOG_DEBUG, "Adding ipad", hasher->ipadXORkey, hasher->blockSize);
	res = KSI_DataHasher_add(hasher->dataHasher, hasher->ipadXORkey, hasher->blockSize);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_HmacHasher_add(KSI_HmacHasher *hasher, const void *data, size_t data_length) {
	int res = KSI_UNKNOWN_ERROR;

	if (hasher == NULL || data == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	res = KSI_DataHasher_add(hasher->dataHasher, data, data_length);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_HmacHasher_close(KSI_HmacHasher *hasher, KSI_DataHash **hmac) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *innerHash = NULL;
	KSI_DataHash *outerHash = NULL;

	const unsigned char *digest = NULL;
	size_t digest_len = 0;

	if (hasher == NULL || hmac == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	KSI_LOG_debug(hasher->ctx, "Closing inner hasher");

	res = KSI_DataHasher_close(hasher->dataHasher, &innerHash);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	/* Hash outer data. */
	res = KSI_DataHasher_reset(hasher->dataHasher);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logBlob(hasher->ctx, KSI_LOG_DEBUG, "Adding opad", hasher->opadXORkey, hasher->blockSize);
	res = KSI_DataHasher_add(hasher->dataHasher, hasher->opadXORkey, hasher->blockSize);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_extract(innerHash, NULL, &digest, &digest_len);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_logBlob(hasher->ctx, KSI_LOG_DEBUG, "Adding inner hash", digest, digest_len);
	res = KSI_DataHasher_add(hasher->dataHasher, digest, digest_len);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_debug(hasher->ctx, "Closing outer hasher");

	res = KSI_DataHasher_close(hasher->dataHasher, &outerHash);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	*hmac = KSI_DataHash_ref(outerHash);

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(innerHash);
	KSI_DataHash_free(outerHash);

	return res;
}

void KSI_HmacHasher_free(KSI_HmacHasher *hasher) {
	if (hasher != NULL) {
		KSI_DataHasher_free(hasher->dataHasher);
		KSI_free(hasher);
	}
}
