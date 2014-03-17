#include <string.h>

#include "ksi_internal.h"
#include "ksi_hash.h"

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
	int bitCount;
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
void KSI_DataHasher_free(KSI_DataHasher *hasher) {
	if (hasher != NULL) {
		KSI_free(hasher->hashContext);
		KSI_free(hasher);
	}
}

void KSI_DataHash_free(KSI_DataHash *hash) {
	if (hash != NULL) {
		KSI_free(hash->digest);
		KSI_free(hash);
	}
}

/**
 *
 */
int KSI_fixHashAlgorithm(int hash_id) {
	if (hash_id == KSI_HASHALG_DEFAULT) {
		return KSI_HASHALG_SHA2_256;
	}
	return hash_id;
}

/**
 *
 */
int KSI_isTrusteddHashAlgorithm(int hash_id) {
	int id = KSI_fixHashAlgorithm(hash_id);
	if (id >= 0 && id < KSI_NUMBER_OF_KNOWN_HASHALGS) {
		return KSI_hashAlgorithmInfo[id].trusted;
	}
	return 0;
}

int KSI_getHashLength(int hash_id) {
	int id = KSI_fixHashAlgorithm(hash_id);
	if (id >= 0 && id < KSI_NUMBER_OF_KNOWN_HASHALGS) {
		return (KSI_hashAlgorithmInfo[id].bitCount) >> 3;
	}
	return -1;
}

/**
 *
 */
int KSI_DataHash_getData(KSI_DataHash *hash, int *algorithm, unsigned char **digest, int *digest_length) {
	KSI_ERR err;
	unsigned char *tmp_digest = NULL;

	KSI_PRE(&err, hash != NULL) goto cleanup;

	KSI_BEGIN(hash->ctx, &err);

	tmp_digest = KSI_calloc(hash->digest_length, 1);
	if (tmp_digest == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	memcpy(tmp_digest, hash->digest, hash->digest_length);

	if (digest_length != NULL) *digest_length = hash->digest_length;
	if (algorithm != NULL) *algorithm = hash->algorithm;
	if (digest != NULL) {
		*digest = tmp_digest;
		tmp_digest = NULL;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp_digest);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_DataHash_fromData(KSI_CTX *ctx, int algorithm, unsigned char *digest, int digest_length, KSI_DataHash **hash) {
	KSI_ERR err;
	KSI_DataHash *tmp_hash = NULL;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	tmp_hash = KSI_new(KSI_DataHash);
	if (tmp_hash == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp_hash->ctx = ctx;
	tmp_hash->digest = NULL;

	res = KSI_DataHash_fromData_ex(algorithm, digest, digest_length, tmp_hash);
	KSI_CATCH(&err, res) goto cleanup;

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
int KSI_DataHash_fromData_ex(int algorithm, unsigned char *digest, int digest_length, KSI_DataHash *hash) {
	KSI_ERR err;
	unsigned char *tmp_digest = NULL;

	KSI_PRE(&err, hash != NULL) goto cleanup;
	KSI_PRE(&err, digest != NULL) goto cleanup;

	KSI_BEGIN(hash->ctx, &err);
	if (KSI_getHashLength(algorithm) != digest_length) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Digest length does not match with algorithm.");
		goto cleanup;
	}

	tmp_digest = KSI_calloc(digest_length, 1);
	if (tmp_digest == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	memcpy(tmp_digest, digest, digest_length);

	KSI_free(hash->digest);

	hash->algorithm = algorithm;
	hash->digest = tmp_digest;
	hash->digest_length = digest_length;

	tmp_digest = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp_digest);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_DataHash_getImprint(KSI_DataHash *hash, unsigned char **imprint, int *imprint_length) {
	KSI_ERR err;
	unsigned char *tmp_imprint = NULL;

	KSI_PRE(&err, hash != NULL) goto cleanup;

	KSI_BEGIN(hash->ctx, &err);

	tmp_imprint = KSI_calloc(hash->digest_length + 1, 1);
	if (tmp_imprint == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	*tmp_imprint = (unsigned char) hash->algorithm;
	memcpy(tmp_imprint + 1, hash->digest, hash->digest_length);

	*imprint_length = hash->digest_length + 1;
	*imprint = tmp_imprint;
	tmp_imprint = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(tmp_imprint);

	return KSI_RETURN(&err);
}

/**
 *
 */
int KSI_DataHash_fromImprint(KSI_CTX *ctx, unsigned char *imprint, int imprint_length, KSI_DataHash **hash) {
	return KSI_DataHash_fromData(ctx, *imprint, imprint + 1, imprint_length - 1, hash);
}

/**
 *
 */
int KSI_DataHash_fromImprint_ex(unsigned char *imprint, int imprint_length, KSI_DataHash *hash) {
	KSI_ERR err;
	int res;
	KSI_PRE(&err, hash != NULL) goto cleanup;
	KSI_PRE(&err, imprint != NULL) goto cleanup;

	KSI_BEGIN(hash->ctx, &err);

	res = KSI_DataHash_fromData_ex(*imprint, imprint + 1, imprint_length - 1, hash);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);

}

/**
 *
 */
const char *KSI_getHashAlgorithmName(int hash_algorithm) {
	int id = KSI_fixHashAlgorithm(hash_algorithm);
	if (id >= 0 && id < KSI_NUMBER_OF_KNOWN_HASHALGS) {
		return KSI_hashAlgorithmInfo[id].name;
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
	for (algorithm_id = 0; algorithm_id < strlen(name); algorithm_id++) {
		if (name[algorithm_id] == '_') {
			upperName[algorithm_id] = '-';
		} else {
			upperName[algorithm_id] = toupper(name[algorithm_id]);
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
		while(*(alias = KSI_hashAlgorithmInfo[algorithm_id].aliases[alias_id++]) != NULL) {
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
