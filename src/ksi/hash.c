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
#include "hash_impl.h"
#include "tlv.h"

#define HASH_ALGO(id, name, bitcount, trusted) {(id), (name), (bitcount), (trusted), id##_aliases}

/** Hash algorithm aliases. The last alias has to be an empty string */
static char *KSI_HASHALG_SHA1_aliases[] = {"SHA-1", ""};
static char *KSI_HASHALG_SHA2_256_aliases[] = {"DEFAULT", "SHA-2", "SHA2", "SHA256", "SHA-256", ""};
static char *KSI_HASHALG_RIPEMD160_aliases[] = { "RIPEMD160", ""};
static char *KSI_HASHALG_SHA2_224_aliases[] = { "SHA224", "SHA-224", ""};
static char *KSI_HASHALG_SHA2_384_aliases[] = { "SHA384", "SHA-384", ""};
static char *KSI_HASHALG_SHA2_512_aliases[] = { "SHA512", "SHA-512", ""};
static char *KSI_HASHALG_SHA3_244_aliases[] = { ""};
static char *KSI_HASHALG_SHA3_256_aliases[] = { ""};
static char *KSI_HASHALG_SHA3_384_aliases[] = { ""};
static char *KSI_HASHALG_SHA3_512_aliases[] = { ""};
static char *KSI_HASHALG_SM3_aliases[] = { "SM-3", ""};

static struct KSI_hashAlgorithmInfo_st {
	/* Hash algorithm id (should mirror the array index in #KSI_hashAlgorithmInfo) */
	KSI_HashAlgorithm algo_id;
	/** Upper-case name. */
	char *name;
	/** Hash bit count. */
	unsigned int bitCount;
	/** Is the hash algorithm trusted? */
	int trusted;
	/** Accepted aliases for this hash algorithm. */
	char **aliases;
} KSI_hashAlgorithmInfo[] = {
		HASH_ALGO(KSI_HASHALG_SHA1,			"SHA1", 		160, 1),
		HASH_ALGO(KSI_HASHALG_SHA2_256,		"SHA2-256", 	256, 1),
		HASH_ALGO(KSI_HASHALG_RIPEMD160,	"RIPEMD-160", 	160, 1),
		HASH_ALGO(KSI_HASHALG_SHA2_224,		"SHA2-224", 	224, 1),
		HASH_ALGO(KSI_HASHALG_SHA2_384,		"SHA2-384", 	384, 1),
		HASH_ALGO(KSI_HASHALG_SHA2_512,		"SHA2-512", 	512, 1),
		{0x06, NULL, 0, 0, NULL}, /* Deprecated algorithm - do not reuse. */
		HASH_ALGO(KSI_HASHALG_SHA3_244,		"SHA3-224", 	224, 1),
		HASH_ALGO(KSI_HASHALG_SHA3_256,		"SHA3-256", 	256, 1),
		HASH_ALGO(KSI_HASHALG_SHA3_384,		"SHA3-384", 	384, 1),
		HASH_ALGO(KSI_HASHALG_SHA3_512,		"SHA3-512", 	512, 1),
		HASH_ALGO(KSI_HASHALG_SM3, 			"SM3", 			256, 1)
};

/**
 *
 */

void KSI_DataHash_free(KSI_DataHash *hash) {
	if (hash != NULL && --hash->ref == 0) {
		KSI_free(hash);
	}
}

/**
 *
 */
int KSI_isHashAlgorithmTrusted(KSI_HashAlgorithm algo_id) {
	if (algo_id >= 0 && algo_id < KSI_NUMBER_OF_KNOWN_HASHALGS) {
		return KSI_hashAlgorithmInfo[algo_id].trusted;
	}
	return 0;
}

unsigned int KSI_getHashLength(KSI_HashAlgorithm algo_id) {
	if (algo_id >= 0 && algo_id < KSI_NUMBER_OF_KNOWN_HASHALGS) {
		return (KSI_hashAlgorithmInfo[algo_id].bitCount) >> 3;
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

	/* Verify the length of the digest with the algorithm. */
	if (KSI_getHashLength(algo_id) != digest_length) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Digest length does not match with algorithm.");
		goto cleanup;
	}

	/* Make sure it fits. */
	if (digest_length > KSI_MAX_IMPRINT_LEN) {
		KSI_pushError(ctx, res = KSI_CRYPTO_FAILURE, "Internal buffer too short to hold imprint");
		goto cleanup;
	}

	tmp_hash = KSI_new(KSI_DataHash);
	if (tmp_hash == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
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
	if (algo_id >= 0 && algo_id < KSI_NUMBER_OF_KNOWN_HASHALGS) {
		return KSI_hashAlgorithmInfo[algo_id].name;
	}
	return NULL;
}

KSI_HashAlgorithm KSI_getHashAlgorithmByName(const char *name) {
	size_t i;
	KSI_HashAlgorithm algo_id = KSI_HASHALG_INVALID;
	int alias_id;

	char *alias = NULL;
	char *upperName = NULL;

	if (name == NULL || !*name || strchr(name, ',') != NULL) goto cleanup;

	upperName = KSI_calloc(strlen(name) + 1, 1);
	if (upperName == NULL) goto cleanup;

	/* Create upper-case name */
	for (i = 0; i < (int) strlen(name); i++) {
		if (name[i] == '_') {
			upperName[i] = '-';
		} else {
			upperName[i] = (char) toupper(name[i]);
		}
	}
	upperName[i] = '\0';

	for (i = 0; i < KSI_NUMBER_OF_KNOWN_HASHALGS; i++) {
		/* Skip all records without a name. */
		if (KSI_hashAlgorithmInfo[i].name == NULL) continue;

		/* Do we have a bingo? */
		if (!strcmp(upperName, KSI_hashAlgorithmInfo[i].name)) {
			algo_id = i;
			goto cleanup;
		}

		alias_id = 0;
		/* Loop until a null pointer or empty string. */
		while ((alias = KSI_hashAlgorithmInfo[i].aliases[alias_id++]) && *alias) {
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

int KSI_DataHash_toTlv(KSI_CTX *ctx, KSI_DataHash *hsh, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
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
	if (hash->imprint == NULL) return KSI_INVALID_ARGUMENT;
	
	*algo_id = hash->imprint[0];
	
	return KSI_OK;
}

int KSI_DataHash_MetaHash_parseMeta(const KSI_DataHash *metaHash, const unsigned char **data, size_t *data_len) {
	int res = KSI_UNKNOWN_ERROR;
	size_t len;
	size_t i;

	if (metaHash == NULL || data == NULL || data_len == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(metaHash->ctx);

	/* Just be paranoid, and check for the length (the length should be determined by the algorithm anyway) .*/
	if (metaHash->imprint_length < 3) {
		KSI_pushError(metaHash->ctx, res = KSI_INVALID_FORMAT, "Imprint too short for a metahash value.");
		goto cleanup;
	}

	len = ((metaHash->imprint[1] << 8) & 0xff) | (metaHash->imprint[2] & 0xff);

	if (len + 3 > metaHash->imprint_length) {
		KSI_pushError(metaHash->ctx, res = KSI_INVALID_FORMAT, "Metadata length greater than imprint length");
		goto cleanup;
	}

	/* Verify padding. */
	for (i = len + 3; i < metaHash->imprint_length; i++) {
		if (metaHash->imprint[i] != 0) {
			KSI_pushError(metaHash->ctx, res = KSI_INVALID_FORMAT, "Metahash not padded with zeros.");
			goto cleanup;
		}
	}

	*data = metaHash->imprint + 3;
	*data_len = len;

	res = KSI_OK;

cleanup:

	return res;

}

int KSI_DataHash_MetaHash_fromTlv(KSI_TLV *tlv, KSI_DataHash **hsh) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CTX *ctx = NULL;
	KSI_DataHash *tmp = NULL;
	const unsigned char *data = NULL;
	size_t data_len;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_ERR_clearErrors(ctx);

	if (tlv == NULL || hsh == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Parse as an imprint */
	res = KSI_DataHash_fromTlv(tlv, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Try to extract the meta value to validate format. */
	res = KSI_DataHash_MetaHash_parseMeta(tmp, &data, &data_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Make sure that the contents of this imprint is a null terminated sequence of bytes. */
	tmp->imprint[KSI_MAX_IMPRINT_LEN] = 0; /* Write extra 0 */

	*hsh = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(ctx);
	KSI_DataHash_free(tmp);

	return res;
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

int KSI_DataHasher_close(KSI_DataHasher *hasher, KSI_DataHash **data_hash) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *hsh = NULL;

	if (hasher == NULL || data_hash == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	KSI_ERR_clearErrors(hasher->ctx);

	hsh = KSI_new(KSI_DataHash);
	if (hsh == NULL) {
		KSI_pushError(hasher->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	hsh->ref = 1;
	hsh->ctx = hasher->ctx;

	res = hasher->closeExisting(hasher, hsh);
	if (res != KSI_OK) {
		KSI_pushError(hasher->ctx, res, NULL);
		goto cleanup;
	}

	*data_hash = hsh;
	hsh = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(hsh);

	return res;

}

KSI_IMPLEMENT_REF(KSI_DataHash);
