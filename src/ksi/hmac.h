#ifndef HMAC_H
#define	HMAC_H

#include "types_base.h"

#ifdef	__cplusplus
extern "C" {
#endif

int KSI_HMAC_create(KSI_CTX *ctx, int alg, const char *key, const unsigned char *data, unsigned data_len, KSI_DataHash **hmac);

#ifdef	__cplusplus
}
#endif

#endif	/* HMAC_H */

