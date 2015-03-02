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

#include <ctype.h>
#include <string.h>

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
static char *KSI_HASHALG_RIPEMD_256_aliases[] = { "RIPEMD256", ""};
static char *KSI_HASHALG_SHA3_244_aliases[] = { ""};
static char *KSI_HASHALG_SHA3_256_aliases[] = { ""};
static char *KSI_HASHALG_SHA3_384_aliases[] = { ""};
static char *KSI_HASHALG_SHA3_512_aliases[] = { ""};
static char *KSI_HASHALG_SM3_aliases[] = { "SM-3", ""};

static struct KSI_hashAlgorithmInfo_st {
	/* Hash algorithm id (should mirror the array index in #KSI_hashAlgorithmInfo) */
	int algo_id;
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
		HASH_ALGO(KSI_HASHALG_RIPEMD_256,	"RIPEMD-256", 	256, 1),
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
	if (hash != NULL && --hash->refCount == 0) {
		KSI_free(hash);
	}
}

/**
 *
 */
int KSI_isHashAlgorithmTrusted(int hash_id) {
	if (hash_id >= 0 && hash_id < KSI_NUMBER_OF_KNOWN_HASHALGS) {
		return KSI_hashAlgorithmInfo[hash_id].trusted;
	}
	return 0;
}

unsigned int KSI_getHashLength(int hash_id) {
	if (hash_id >= 0 && hash_id < KSI_NUMBER_OF_KNOWN_HASHALGS) {
		return (KSI_hashAlgorithmInfo[hash_id].bitCount) >> 3;
	}
	return 0;
}

/**
 *
 */
int KSI_DataHash_extract(const KSI_DataHash *hash, int *hash_id, const unsigned char **digest, unsigned int *digest_length) {
	KSI_ERR err;

	KSI_PRE(&err, hash != NULL) goto cleanup;

	KSI_BEGIN(hash->ctx, &err);

	if (digest_length != NULL) *digest_length = hash->imprint_length - 1;
	if (hash_id != NULL) *hash_id = hash->imprint[0];
	if (digest != NULL) {
		*digest = hash->imprint + 1;
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_DataHash_fromDigest(KSI_CTX *ctx, int hash_id, const unsigned char *digest, unsigned int digest_length, KSI_DataHash **hash) {
	KSI_ERR err;
	KSI_DataHash *tmp_hash = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, digest != NULL) goto cleanup;
	KSI_PRE(&err, digest_length > 0) goto cleanup;
	KSI_PRE(&err, hash != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (KSI_getHashLength(hash_id) != digest_length) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Digest length does not match with algorithm.");
		goto cleanup;
	}

	if (digest_length > KSI_MAX_IMPRINT_LEN) {
		KSI_FAIL(&err, KSI_CRYPTO_FAILURE, "Internal buffer too short to hold imprint");
		goto cleanup;
	}

	tmp_hash = KSI_new(KSI_DataHash);
	if (tmp_hash == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp_hash->refCount = 1;
	tmp_hash->ctx = ctx;

	tmp_hash->imprint[0] = (unsigned char)hash_id;
	memcpy(tmp_hash->imprint + 1, digest, digest_length);
	tmp_hash->imprint_length = digest_length + 1;

	*hash = tmp_hash;
	tmp_hash = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(tmp_hash);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_DataHash_getImprint(const KSI_DataHash *hash, const unsigned char **imprint, unsigned int *imprint_length) {
	KSI_ERR err;

	KSI_PRE(&err, hash != NULL) goto cleanup;
	KSI_PRE(&err, imprint != NULL) goto cleanup;
	KSI_PRE(&err, imprint_length != NULL) goto cleanup;
	KSI_BEGIN(hash->ctx, &err);

	*imprint_length = hash->imprint_length;
	*imprint = hash->imprint;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_DataHash_fromImprint(KSI_CTX *ctx, const unsigned char *imprint, unsigned int imprint_length, KSI_DataHash **hash) {
	return KSI_DataHash_fromDigest(ctx, *imprint, imprint + 1, imprint_length - 1, hash);
}

/**
 *
 */
const char *KSI_getHashAlgorithmName(int hash_id) {
	if (hash_id >= 0 && hash_id < KSI_NUMBER_OF_KNOWN_HASHALGS) {
		return KSI_hashAlgorithmInfo[hash_id].name;
	}
	return NULL;
}

/**
 *
 */
int KSI_getHashAlgorithmByName(const char *name) {
	int algorithm_id;
	int hash_id = -1;
	int alias_id;

	char *alias = NULL;
	char *upperName = NULL;

	if (name == NULL || !*name || strchr(name, ',') != NULL) goto cleanup;

	upperName = KSI_calloc(strlen(name) + 1, 1);
	if (upperName == NULL) goto cleanup;

	/* Create upper-case name */
	for (algorithm_id = 0; algorithm_id < (int)strlen(name); algorithm_id++) {
		if (name[algorithm_id] == '_') {
			upperName[algorithm_id] = '-';
		} else {
			upperName[algorithm_id] = (char)toupper(name[algorithm_id]);
		}
	}
	upperName[algorithm_id] = '\0';

	for (algorithm_id = 0; algorithm_id < KSI_NUMBER_OF_KNOWN_HASHALGS; algorithm_id++) {
		/* Do we have a bingo? */
		if (!strcmp(upperName, KSI_hashAlgorithmInfo[algorithm_id].name)) {
			hash_id = algorithm_id;
			goto cleanup;
		}

		alias_id = 0;
		/* Loop until a null pointer or empty string. */
		while ((alias = KSI_hashAlgorithmInfo[algorithm_id].aliases[alias_id++]) && *alias) {
			if (!strcmp(upperName, alias)) {
				hash_id = algorithm_id;
				goto cleanup;
			}
		}
	}

cleanup:

	KSI_free(upperName);
	KSI_nofree(alias);

	return hash_id;
}

/**
 *
 */
int KSI_DataHash_create(KSI_CTX *ctx, const void *data, size_t data_length, int hash_id, KSI_DataHash **hash) {
	KSI_ERR err;
	KSI_DataHash *hsh = NULL;
	KSI_DataHasher *hsr = NULL;
	int res;

	KSI_BEGIN(ctx, &err);

	res = KSI_DataHasher_open(ctx, hash_id, &hsr);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHasher_add(hsr, data, data_length);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHasher_close(hsr, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	*hash = hsh;
	hsh = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(hsh);
	KSI_DataHasher_free(hsr);

	return KSI_RETURN(&err);
}

int KSI_DataHash_clone(KSI_DataHash *from, KSI_DataHash **to) {
	KSI_ERR err;

	KSI_PRE(&err, from != NULL) goto cleanup;
	KSI_PRE(&err, to != NULL) goto cleanup;
	KSI_BEGIN(from->ctx, &err);

	from->refCount++;
	*to = from;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_DataHash_equals(const KSI_DataHash *left, const KSI_DataHash *right) {
	return left != NULL && right != NULL &&
			(left == right || (left->imprint_length == right->imprint_length && !memcmp(left->imprint, right->imprint, left->imprint_length)));
}

int KSI_DataHash_fromTlv(KSI_TLV *tlv, KSI_DataHash **hsh) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	const unsigned char *raw = NULL;
	unsigned int raw_len = 0;
	KSI_DataHash *tmp = NULL;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, hsh != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_RAW);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHash_fromImprint(ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*hsh = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(ctx);
	KSI_nofree(raw);
	KSI_DataHash_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_DataHash_toTlv(KSI_CTX *ctx, KSI_DataHash *hsh, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;
	const unsigned char *raw = NULL;
	unsigned int raw_len = 0;

	KSI_PRE(&err, hsh != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHash_getImprint(hsh, &raw, &raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_setRawValue(tmp, raw, raw_len);
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(raw);
	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_DataHash_getHashAlg(const KSI_DataHash *hash, int *hashAlg){
	if (hash == NULL) return KSI_INVALID_ARGUMENT;
	if (hashAlg == NULL) return KSI_INVALID_ARGUMENT;
	if (hash->imprint == NULL) return KSI_INVALID_ARGUMENT;
	
	*hashAlg = hash->imprint[0];
	
return KSI_OK;
}

int KSI_DataHash_MetaHash_parseMeta(const KSI_DataHash *metaHash, const unsigned char **data, int *data_len) {
	KSI_ERR err;
	unsigned len;
	unsigned i;

	KSI_PRE(&err, metaHash != NULL) goto cleanup;
	KSI_PRE(&err, data != NULL) goto cleanup;
	KSI_PRE(&err, data_len != NULL) goto cleanup;
	KSI_BEGIN(metaHash->ctx, &err);

	/* Just be paranoid, and check for the length (the length should be determined by the algorithm anyway) .*/
	if (metaHash->imprint_length < 3) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Imprint too short for a metahash value.");
		goto cleanup;
	}

	len = ((metaHash->imprint[1] << 8) & 0xff) | (metaHash->imprint[2] & 0xff);

	if (len + 3 > metaHash->imprint_length) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Metadata length greater than imprint length");
		goto cleanup;
	}

	/* Verify padding. */
	for (i = len + (int)3; i < metaHash->imprint_length; i++) {
		if (metaHash->imprint[i] != 0) {
			KSI_FAIL(&err, KSI_INVALID_FORMAT, "Metahash not padded with zeros.");
			goto cleanup;
		}
	}

	*data = metaHash->imprint + 3;
	*data_len = len;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);

}

int KSI_DataHash_MetaHash_fromTlv(KSI_TLV *tlv, KSI_DataHash **hsh) {
	KSI_ERR err;
	int res;
	KSI_CTX *ctx = NULL;
	KSI_DataHash *tmp = NULL;
	const unsigned char *data = NULL;
	int data_len;

	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, hsh != NULL) goto cleanup;

	ctx = KSI_TLV_getCtx(tlv);
	KSI_BEGIN(ctx, &err);

	/* Parse as an imprint */
	res = KSI_DataHash_fromTlv(tlv, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	/* Try to extract the meta value to validate format. */
	res = KSI_DataHash_MetaHash_parseMeta(tmp, &data, &data_len);
	KSI_CATCH(&err, res) goto cleanup;

	/* Make sure that the contents of this imprint is a null terminated sequence of bytes. */
	tmp->imprint[KSI_MAX_IMPRINT_LEN] = 0; /* Write extra 0 */

	*hsh = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(ctx);
	KSI_DataHash_free(tmp);

	return KSI_RETURN(&err);
}
char *KSI_DataHash_toString(const KSI_DataHash *hsh, char *buf, unsigned buf_len) {
	char *ret = NULL;
	unsigned i;
	unsigned len = 0;

	if (hsh == NULL || buf == NULL) goto cleanup;

	for (i = 0; i < hsh->imprint_length && len < buf_len; i++) {
		len += KSI_snprintf(buf + len, buf_len - len, "%02x", hsh->imprint[i]);
	}

	ret = buf;

cleanup:

	return ret;
}

int KSI_DataHasher_close(KSI_DataHasher *hasher, KSI_DataHash **data_hash) {
	KSI_ERR err;
	int res;
	KSI_DataHash *hsh = NULL;

	KSI_PRE(&err, hasher != NULL) goto cleanup;
	KSI_PRE(&err, data_hash != NULL) goto cleanup;
	KSI_BEGIN(hasher->ctx, &err);

	hsh = KSI_new(KSI_DataHash);
	if (hsh == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	hsh->refCount = 1;
	hsh->ctx = hasher->ctx;

	res = hasher->closeExisting(hasher, hsh);
	KSI_CATCH(&err, res) goto cleanup;

	*data_hash = hsh;
	hsh = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(hsh);

	return KSI_RETURN(&err);

}
