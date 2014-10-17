/* 
 * File:   hmac.h
 * Author: Taavi
 *
 * Created on October 16, 2014, 12:16 PM
 */

#ifndef HMAC_H
#define	HMAC_H

#include "types_base.h"

#ifdef	__cplusplus
extern "C" {
#endif

int KSI_HMAC_free(KSI_HMAC *hmac);	
int KSI_HMAC_new(KSI_CTX *ctx, int alg, const char *key, size_t key_len, const char *data, size_t data_len, KSI_HMAC **hmac);
int KSI_HMAC_toString(const KSI_HMAC *hmac, char *buf, unsigned buf_len);
int KSI_HMAC_getDigest(const KSI_HMAC *hmac, int *hash_id, const unsigned char **digest, unsigned int *digest_length);
int KSI_HMAC_clone(KSI_HMAC *from, KSI_HMAC **to);

#ifdef	__cplusplus
}
#endif

#endif	/* HMAC_H */

