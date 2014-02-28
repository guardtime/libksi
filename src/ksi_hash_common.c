#include "ksi_internal.h"
#include "ksi_hash.h"

/**
 *
 */
void KSI_Hasher_free(KSI_Hasher *hasher) {
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
		return KSI_HASHALG_SHA256;
	}
	return hash_id;
}

/**
 *
 */
int KSI_isSupportedHashAlgorithm(int hash_id)
{
	return
#ifndef OPENSSL_NO_SHA
		(hash_id == KSI_HASHALG_SHA1) ||
#endif
		(hash_id == KSI_HASHALG_SHA224) ||
		(hash_id == KSI_HASHALG_SHA256) ||
#ifndef OPENSSL_NO_SHA512
		(hash_id == KSI_HASHALG_SHA384) ||
		(hash_id == KSI_HASHALG_SHA512) ||
#endif
#ifndef OPENSSL_NO_RIPEMD
		(hash_id == KSI_HASHALG_RIPEMD160) ||
#endif
		(hash_id == KSI_HASHALG_DEFAULT);
}
