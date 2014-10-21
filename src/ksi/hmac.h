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

int KSI_HMAC_create(KSI_CTX *ctx, int alg, const char *key, size_t key_len, const char *data, size_t data_len, KSI_DataHash **hmac);
int KSI_HMAC_toString(const KSI_DataHash *hmac, char *buf, unsigned buf_len);

#ifdef	__cplusplus
}
#endif

#endif	/* HMAC_H */

