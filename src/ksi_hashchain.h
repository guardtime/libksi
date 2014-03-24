#ifndef KSI_HASHCHAIN_H_
#define KSI_HASHCHAIN_H_

#include "ksi_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

struct KSI_HashNode_st {
	KSI_CTX *ctx;
	KSI_DataHash *hash;
	int level;

	KSI_HashNode *parent;
	KSI_HashNode *leftChild;
	KSI_HashNode *rightChild;
};

struct KSI_HashTree_st {
	KSI_HashNode *root;
};




#ifdef __cplusplus
}
#endif

#endif /* KSI_HASHCHAIN_H_ */
