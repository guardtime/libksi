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

#include <ctype.h>
#include <string.h>

#include "hash.h"
#include "internal.h"
#include "impl/hash_impl.h"
#include "tlv.h"
#include "impl/ctx_impl.h"

#define HASH_ALGO(id, bitcount, blocksize, deprecatedFrom, obsoleteFrom) {(id), (bitcount), (blocksize), id##_names, (deprecatedFrom), (obsoleteFrom)}

/** Hash algorithm names. The last name has to be an empty string. */
static const char * const KSI_HASHALG_SHA1_names[] = {"SHA-1", "SHA1", ""};
static const char * const KSI_HASHALG_SHA2_256_names[] = {"SHA-256", "SHA2-256", "SHA-2", "SHA2", "SHA256", "DEFAULT", ""};
static const char * const KSI_HASHALG_RIPEMD160_names[] = { "RIPEMD-160", "RIPEMD160", ""};
static const char * const KSI_HASHALG_SHA2_384_names[] = { "SHA-384", "SHA384", "SHA2-384", ""};
static const char * const KSI_HASHALG_SHA2_512_names[] = { "SHA-512", "SHA512", "SHA2-512", ""};
static const char * const KSI_HASHALG_SHA3_244_names[] = { "SHA3-224", ""};
static const char * const KSI_HASHALG_SHA3_256_names[] = { "SHA3-256", ""};
static const char * const KSI_HASHALG_SHA3_384_names[] = { "SHA3-384", ""};
static const char * const KSI_HASHALG_SHA3_512_names[] = { "SHA3-512"};
static const char * const KSI_HASHALG_SM3_names[] = { "SM-3", "SM3", ""};


static const struct KSI_hashAlgorithmInfo_st {
	/** Hash algorithm id (should mirror the array index in #KSI_hashAlgorithmInfo) */
	KSI_HashAlgorithm algo_id;
    /** Output digest bit count. */
	unsigned int outputBitCount;
	/** Internal bit count */
	unsigned int blockSize;
	/** Accepted names for this hash algorithm. */
	char const * const *names;
	/* The time the function has been marked as deprecated. */
	time_t deprecatedFrom;
	/* The time the function has been marked as obsolete. */
	time_t obsoleteFrom;
} KSI_hashAlgorithmInfo[] = {
		/* SHA1 is deprecated as of  01.07.2016T00:00 UTC .*/
		HASH_ALGO(KSI_HASHALG_SHA1,			160, 512, 1467331200, 0),
		HASH_ALGO(KSI_HASHALG_SHA2_256,		256, 512, 0, 0),
		HASH_ALGO(KSI_HASHALG_RIPEMD160,	160, 512, 0, 0),
		{0x03, 0, 0, NULL, 1, 1}, /* Deprecated algorithm - do not reuse. */
		HASH_ALGO(KSI_HASHALG_SHA2_384,		384, 1024, 0, 0),
		HASH_ALGO(KSI_HASHALG_SHA2_512,		512, 1024, 0, 0),
		{0x06, 0, 0, NULL, 1, 1}, /* Deprecated algorithm - do not reuse. */
		HASH_ALGO(KSI_HASHALG_SHA3_244,		224, 1152, 0, 0),
		HASH_ALGO(KSI_HASHALG_SHA3_256,		256, 1088, 0, 0),
		HASH_ALGO(KSI_HASHALG_SHA3_384,		384, 832, 0, 0),
		HASH_ALGO(KSI_HASHALG_SHA3_512,		512, 576, 0, 0),
		HASH_ALGO(KSI_HASHALG_SM3, 			256, 512, 0, 0)
};

#undef HASH_ALGO

static int ksi_isHashAlgorithmIdValid(int algo_id) {
	return algo_id >= 0 && algo_id < KSI_NUMBER_OF_KNOWN_HASHALGS && KSI_hashAlgorithmInfo[algo_id].names != NULL;
}

/**
 *
 */
void KSI_DataHash_free(KSI_DataHash *hsh) {
	int res;
	/* Do nothing if the object is NULL. */
	if (hsh == NULL) return;

	/* If the reference count is already 0, it means the object is actually located
	 * in the object cache. In case of a user double free, this might become an issue. */
	if (hsh->ref == 0) {
		KSI_free(hsh);
	} else if (--hsh->ref == 0) {
		if (KSI_DataHashList_length(hsh->ctx->dataHashRecycle) < (size_t)hsh->ctx->options[KSI_OPT_DATAHASH_CACHE_SIZE]) {
			res = KSI_DataHashList_append(hsh->ctx->dataHashRecycle, hsh);

			/* Return if all went well. */
			if (res == KSI_OK) return;
		}

		/* Free the element if the recycle bin was full, or something happened. */
		KSI_free(hsh);
	}
}

/**
 *
 */
int KSI_isHashAlgorithmTrusted(KSI_HashAlgorithm algo_id) {
	if (ksi_isHashAlgorithmIdValid(algo_id)) {
		return KSI_hashAlgorithmInfo[algo_id].obsoleteFrom == 0 && KSI_hashAlgorithmInfo[algo_id].deprecatedFrom == 0;
	}
	return 0;
}

int KSI_checkHashAlgorithmAt(KSI_HashAlgorithm algo_id, time_t used_at) {
	if (algo_id >= KSI_NUMBER_OF_KNOWN_HASHALGS || algo_id == KSI_HASHALG_INVALID) {
		return KSI_UNKNOWN_HASH_ALGORITHM_ID;
	}

	if (KSI_hashAlgorithmInfo[algo_id].obsoleteFrom != 0 && KSI_hashAlgorithmInfo[algo_id].obsoleteFrom <= used_at) {
		return KSI_HASH_ALGORITHM_OBSOLETE;
	}

	if (KSI_hashAlgorithmInfo[algo_id].deprecatedFrom != 0 && KSI_hashAlgorithmInfo[algo_id].deprecatedFrom <= used_at) {
		return KSI_HASH_ALGORITHM_DEPRECATED;
	}

	return KSI_OK;
}



unsigned int KSI_getHashLength(KSI_HashAlgorithm algo_id) {
	if (ksi_isHashAlgorithmIdValid(algo_id)) {
		return (KSI_hashAlgorithmInfo[algo_id].outputBitCount) >> 3;
	}
	return 0;
}

unsigned int KSI_HashAlgorithm_getBlockSize(KSI_HashAlgorithm algo_id) {
	if (ksi_isHashAlgorithmIdValid(algo_id)) {
		return (KSI_hashAlgorithmInfo[algo_id].blockSize) >> 3;
	}
	return 0;
}

/**
 *
 */
int KSI_DataHash_extract(const KSI_DataHash *hash, KSI_HashAlgorithm *algo_id, const unsigned char **digest, size_t *digest_length) {
	int res = KSI_UNKNOWN_ERROR;

	if (hash == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hash->ctx);

	if (digest_length != NULL) *digest_length = hash->imprint_length - 1;
	if (algo_id != NULL) *algo_id = hash->imprint[0];
	if (digest != NULL) {
		*digest = hash->imprint + 1;
	}

	res = KSI_OK;

cleanup:

	return res;
}

static int alloc_dataHash(KSI_CTX *ctx, KSI_DataHash **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *tmp = NULL;
	size_t len;

	if (ctx == NULL || out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if ((len = KSI_DataHashList_length(ctx->dataHashRecycle)) > 0) {
		res = KSI_DataHashList_remove(ctx->dataHashRecycle, len - 1, &tmp);
		if (res != KSI_OK) goto cleanup;
	} else {
		tmp = KSI_new(KSI_DataHash);
		if (tmp == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}
	}

	*out = tmp;
	res = KSI_OK;

cleanup:

	return res;
}

/**
 *
 */
int KSI_DataHash_fromDigest(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, const unsigned char *digest, size_t digest_length, KSI_DataHash **hash) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *tmp_hash = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || digest == NULL || digest_length == 0 || hash == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* Make sure the algorithm is valid. */
	if (!ksi_isHashAlgorithmIdValid(algo_id)) {
		KSI_pushError(ctx, res = KSI_UNAVAILABLE_HASH_ALGORITHM, "Hash algorithm ID is not valid.");
		goto cleanup;
	}

	/* Verify the length of the digest with the algorithm. */
	if (KSI_getHashLength(algo_id) != digest_length) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Digest length does not match with algorithm.");
		goto cleanup;
	}

	/* Make sure it fits. */
	if (digest_length > KSI_MAX_IMPRINT_LEN) {
		KSI_pushError(ctx, res = KSI_CRYPTO_FAILURE, "Internal buffer too short to hold imprint.");
		goto cleanup;
	}

	res = alloc_dataHash(ctx, &tmp_hash);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp_hash->ref = 1;
	tmp_hash->ctx = ctx;

	tmp_hash->imprint[0] = (unsigned char)algo_id;
	memcpy(tmp_hash->imprint + 1, digest, digest_length);
	tmp_hash->imprint_length = digest_length + 1;

	*hash = tmp_hash;
	tmp_hash = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(tmp_hash);

	return res;
}

/**
 *
 */
int KSI_DataHash_getImprint(const KSI_DataHash *hash, const unsigned char **imprint, size_t *imprint_length) {
	int res = KSI_UNKNOWN_ERROR;

	if (hash == NULL || imprint == NULL || imprint_length == NULL) {
		res = KSI_SERVICE_UNKNOWN_ERROR;
		goto cleanup;
	}

	*imprint_length = hash->imprint_length;
	*imprint = hash->imprint;

	res = KSI_OK;

cleanup:

	return res;
}

/**
 *
 */
int KSI_DataHash_fromImprint(KSI_CTX *ctx, const unsigned char *imprint, size_t imprint_length, KSI_DataHash **hash) {
	return KSI_DataHash_fromDigest(ctx, *imprint, imprint + 1, imprint_length - 1, hash);
}

/**
 *
 */
const char *KSI_getHashAlgorithmName(KSI_HashAlgorithm algo_id) {
	if (ksi_isHashAlgorithmIdValid(algo_id)) {
		return KSI_hashAlgorithmInfo[algo_id].names[0];
	}
	return NULL;
}

KSI_HashAlgorithm KSI_getHashAlgorithmByName(const char *name) {
	size_t i;
	KSI_HashAlgorithm algo_id = KSI_HASHALG_INVALID;
	int alias_id;

	const char *alias = NULL;
	char *upperName = NULL;

	if (name == NULL || !*name || strchr(name, ',') != NULL) goto cleanup;

	upperName = KSI_calloc(strlen(name) + 1, 1);
	if (upperName == NULL) goto cleanup;

	/* Create upper-case name */
	for (i = 0; i < strlen(name); i++) {
		if (name[i] == '_') {
			upperName[i] = '-';
		} else {
			upperName[i] = (char) toupper(name[i]);
		}
	}
	upperName[i] = '\0';

	for (i = 0; i < KSI_NUMBER_OF_KNOWN_HASHALGS; i++) {
		/* Skip all records without a name. */
		if (KSI_hashAlgorithmInfo[i].names == NULL) continue;

		alias_id = 0;

		/* Loop until a null pointer or empty string. */
		while ((alias = KSI_hashAlgorithmInfo[i].names[alias_id++]) && *alias) {
			if (!strcmp(upperName, alias)) {
				algo_id = i;
				goto cleanup;
			}
		}
	}

cleanup:

	KSI_free(upperName);
	KSI_nofree(alias);

	return algo_id;
}

/**
 *
 */
int KSI_DataHash_create(KSI_CTX *ctx, const void *data, size_t data_length, KSI_HashAlgorithm algo_id, KSI_DataHash **hash) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;
	KSI_DataHasher *hsr = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || hash == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_open(ctx, algo_id, &hsr);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (data != NULL && data_length > 0) {
		res = KSI_DataHasher_add(hsr, data, data_length);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	res = KSI_DataHasher_close(hsr, &hsh);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hash = hsh;
	hsh = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);

	return res;
}

int KSI_DataHash_clone(KSI_DataHash *from, KSI_DataHash **to) {
	int res = KSI_UNKNOWN_ERROR;

	if (from == NULL || to == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(from->ctx);

	from->ref++;
	*to = from;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_DataHash_equals(const KSI_DataHash *left, const KSI_DataHash *right) {
	return left != NULL && right != NULL &&
			(left == right || (left->imprint_length == right->imprint_length && !memcmp(left->imprint, right->imprint, left->imprint_length)));
}

int KSI_DataHash_fromTlv(KSI_TLV *tlv, KSI_DataHash **hsh) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	const unsigned char *raw = NULL;
	size_t raw_len = 0;
	KSI_DataHash *tmp = NULL;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_ERR_clearErrors(ctx);
	if (tlv == NULL || hsh == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_fromImprint(ctx, raw, raw_len, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hsh = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(ctx);
	KSI_nofree(raw);
	KSI_DataHash_free(tmp);

	return res;
}

int KSI_DataHash_toTlv(KSI_CTX *ctx, const KSI_DataHash *hsh, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tmp = NULL;
	const unsigned char *raw = NULL;
	size_t raw_len = 0;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || hsh == NULL || tlv == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_TLV_new(ctx, tag, isNonCritical, isForward, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_getImprint(hsh, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_setRawValue(tmp, raw, raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(raw);
	KSI_TLV_free(tmp);

	return res;
}

int KSI_DataHash_getHashAlg(const KSI_DataHash *hash, KSI_HashAlgorithm *algo_id){
	if (hash == NULL) return KSI_INVALID_ARGUMENT;
	if (algo_id == NULL) return KSI_INVALID_ARGUMENT;

	*algo_id = hash->imprint[0];

	return KSI_OK;
}

char *KSI_DataHash_toString(const KSI_DataHash *hsh, char *buf, size_t buf_len) {
	char *ret = NULL;
	size_t i;
	size_t len = 0;

	if (hsh == NULL || buf == NULL) goto cleanup;

	for (i = 0; i < hsh->imprint_length && len < buf_len; i++) {
		len += KSI_snprintf(buf + len, buf_len - len, "%02x", hsh->imprint[i]);
	}

	ret = buf;

cleanup:

	return ret;
}

int KSI_DataHasher_close(KSI_DataHasher *hsr, KSI_DataHash **data_hash) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;

	if (hsr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hsr->ctx);

	if (!hsr->isOpen) {
		KSI_pushError(hsr->ctx, res = KSI_INVALID_STATE, "Hasher is already closed.");
		goto cleanup;
	}

	if (hsr->closeExisting == NULL) {
		KSI_pushError(hsr->ctx, res = KSI_INVALID_STATE, "Hasher not properly initialized.");
		goto cleanup;
	}


	res = alloc_dataHash(hsr->ctx, &hsh);
	if (res != KSI_OK) {
		KSI_pushError(hsr->ctx, res, NULL);
		goto cleanup;
	}

	hsh->ref = 1;
	hsh->ctx = hsr->ctx;

	res = hsr->closeExisting(hsr, hsh);
	if (res != KSI_OK) {
		KSI_pushError(hsr->ctx, res, NULL);
		goto cleanup;
	}

	if (data_hash != NULL) {
		*data_hash = hsh;
		hsh = NULL;
	}

	hsr->isOpen = false;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(hsh);

	return res;

}

int KSI_DataHasher_reset(KSI_DataHasher *hsr) {
	int res = KSI_UNKNOWN_ERROR;

	if (hsr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hsr->ctx);

	if (hsr->reset == NULL) {
		KSI_pushError(hsr->ctx, res = KSI_INVALID_STATE, "Hasher not properly initialized.");
		goto cleanup;
	}

	res = hsr->reset(hsr);
	if (res != KSI_OK) {
		KSI_pushError(hsr->ctx, res, NULL);
		goto cleanup;
	}

	hsr->isOpen = true;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_DataHasher_add(KSI_DataHasher *hsr, const void *data, size_t data_len) {
	int res = KSI_UNKNOWN_ERROR;

	if (hsr == NULL || data == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hsr->ctx);

	if (!hsr->isOpen) {
		KSI_pushError(hsr->ctx, res = KSI_INVALID_STATE, "Hasher is closed.");
		goto cleanup;
	}

	if (hsr->add == NULL) {
		KSI_pushError(hsr->ctx, res = KSI_INVALID_STATE, "Hasher not properly initialized.");
		goto cleanup;
	}

	if (data_len > 0) {
		res = hsr->add(hsr, data, data_len);
		if (res != KSI_OK) {
			KSI_pushError(hsr->ctx, res, NULL);
			goto cleanup;
		}
	}

	res = KSI_OK;

cleanup:

	return res;
}

void KSI_DataHasher_free(KSI_DataHasher *hsr) {
	if (hsr != NULL) {
		if (hsr->cleanup != NULL) {
			hsr->cleanup(hsr);
		}
		KSI_free(hsr);
	}
}

int KSI_DataHasher_addImprint(KSI_DataHasher *hasher, const KSI_DataHash *hsh) {
	int res = KSI_UNKNOWN_ERROR;
	const unsigned char *imprint;
	size_t imprint_len;

	if (hasher == NULL || hsh == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(hasher->ctx);

	res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_len);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_add(hasher, imprint, imprint_len);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_DataHasher_addOctetString(KSI_DataHasher *hasher, const KSI_OctetString *data) {
	int res = KSI_UNKNOWN_ERROR;
	const unsigned char *ptr = NULL;
	size_t len = 0;

	if (hasher == NULL || data == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_OctetString_extract(data, &ptr, &len);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_DataHasher_add(hasher, ptr, len);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_DataHash_createZero(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, KSI_DataHash **hsh) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *tmp = NULL;
	unsigned char buf[KSI_MAX_IMPRINT_LEN];

	if (ctx == NULL || hsh == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(buf, 0, sizeof(buf));
	buf[0] = algo_id;

	/* Make sure the hash algorithm id is valid. */
	if (!ksi_isHashAlgorithmIdValid(algo_id)) {
		KSI_pushError(ctx, res = KSI_UNAVAILABLE_HASH_ALGORITHM, "Hash algorithm ID is not valid.");
		goto cleanup;
	}

	res = KSI_DataHash_fromImprint(ctx, buf, (KSI_hashAlgorithmInfo[algo_id].outputBitCount >> 3) + 1, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hsh = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(tmp);

	return res;
}


KSI_IMPLEMENT_REF(KSI_DataHash);
KSI_IMPLEMENT_LIST(KSI_DataHash, KSI_DataHash_free);
