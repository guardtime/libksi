#ifndef HASH_IMPL_H_
#define HASH_IMPL_H_

#include "hash.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_DataHash_st {
		/* KSI context */
		KSI_CTX *ctx;

		unsigned char imprint[KSI_MAX_IMPRINT_LEN + 1]; /* For an extra '0' for meta hash. */
		unsigned int imprint_length;
	};

	struct KSI_DataHasher_st {
		/* KSI context */
		KSI_CTX *ctx;
		void *hashContext;
		int algorithm;
	};

#ifdef __cplusplus
}
#endif

#endif /* HASH_IMPL_H_ */
