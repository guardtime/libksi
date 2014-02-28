/*
 * ksi_hash.h
 *
 *  Created on: 28.02.2014
 *      Author: henri
 */

#ifndef KSI_HASH_H_
#define KSI_HASH_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KSI_Hasher_st KSI_Hasher;

struct KSI_Hasher_st {
	/* KSI context */
	KSI_CTX *ctx;

	void *hashContext;
	int algorithm;
	int digest_length;
};

typedef struct KSI_DataHash_st {
	int algorithm;
	char *digest;
	int digest_length;
} KSI_DataHash;

int KSI_Hasher_open(KSI_CTX *ctx, int hash_algorithm, KSI_Hasher **hasher);

void KSI_Hasher_free(KSI_Hasher *hasher);

void KSI_DataHash_free(KSI_DataHash *hash);
/**
 * Fixes hash algorithm ID: replaces default ID with the current default
 * as necessary.
 **/
int KSI_fixHashAlgorithm(int hash_id);

/**
 * Is \p hash_id hash algorithm supported?
 */
int KSI_isSupportedHashAlgorithm(int hash_id);

#ifdef __cplusplus
}
#endif

#endif /* KSI_HASH_H_ */
