/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#include <string.h>

#include "internal.h"
#include "hmac.h"

#define MAX_KEY_LEN 64

#define ipad8 0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36
#define opad8 0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c

static const unsigned char ipad[MAX_KEY_LEN]={ipad8,ipad8,ipad8,ipad8,ipad8,ipad8,ipad8,ipad8};
static const unsigned char opad[MAX_KEY_LEN]={opad8,opad8,opad8,opad8,opad8,opad8,opad8,opad8};

int KSI_HMAC_create(KSI_CTX *ctx, int alg, const char *key, const unsigned char *data, unsigned data_len, KSI_DataHash **hmac) {
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hashedKey = NULL;
	KSI_DataHash *innerHash = NULL;
	KSI_DataHash *outerHash = NULL;
	KSI_DataHash *tmp = NULL;

	size_t key_len;
	const unsigned char *bufKey = NULL;
	unsigned buf_len = 0;
	unsigned char ipadXORkey[MAX_KEY_LEN];
	unsigned char opadXORkey[MAX_KEY_LEN];
	const unsigned char *digest = NULL;
	unsigned digest_len = 0;
	unsigned i =0;

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

	if (KSI_getHashLength(alg) > MAX_KEY_LEN) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "The hash length is greater than 64");
		goto cleanup;
	}

	/* Open the hasher. */
	res = KSI_DataHasher_open(ctx, alg, &hsr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Prepare the key for hashing. */
	/* If the key is longer than 64, hash it. If the key or its hash is shorter than 64 bit, append zeros. */
	if (key_len > MAX_KEY_LEN) {
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

		if (digest == NULL || digest_len > MAX_KEY_LEN) {
			KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "The hash of the key is invalid");
			goto cleanup;
		}

		bufKey = digest;
		buf_len = digest_len;
	} else{
		bufKey = (unsigned char *)key;
		buf_len = (unsigned)key_len;
	}

	for (i = 0; i < buf_len; i++) {
		ipadXORkey[i] = ipad[i] ^ bufKey[i];
		opadXORkey[i] = opad[i] ^ bufKey[i];
	}

	for (; i < MAX_KEY_LEN; i++) {
		ipadXORkey[i] = 0x36;
		opadXORkey[i] = 0x5c;
	}

	/* Hash inner data. */
	res = KSI_DataHasher_reset(hsr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_add(hsr, ipadXORkey, MAX_KEY_LEN);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_add(hsr, data, data_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

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

	res = KSI_DataHasher_add(hsr, opadXORkey, MAX_KEY_LEN);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_extract(innerHash, NULL, &digest, &digest_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_add(hsr, digest, digest_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_close(hsr, &outerHash);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_clone(outerHash, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hmac = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hashedKey);
	KSI_DataHash_free(innerHash);
	KSI_DataHash_free(outerHash);
	KSI_DataHash_free(tmp);

	return res;
}
