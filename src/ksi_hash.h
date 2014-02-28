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


struct KSI_DataHasher_st {
	/* KSI context */
	KSI_CTX *ctx;

	void *hashContext;
	int algorithm;
	int digest_length;
};

#ifdef __cplusplus
}
#endif

#endif /* KSI_HASH_H_ */
