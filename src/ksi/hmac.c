#include <string.h>

#include "internal.h"
#include "hmac.h"

#define MAX_KEY_LEN 64

#define ipad8 0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36
#define opad8 0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c

static const unsigned char ipad[MAX_KEY_LEN]={ipad8,ipad8,ipad8,ipad8,ipad8,ipad8,ipad8,ipad8};
static const unsigned char opad[MAX_KEY_LEN]={opad8,opad8,opad8,opad8,opad8,opad8,opad8,opad8};

struct KSI_HMAC_st{
	KSI_CTX *ctx;
	unsigned refCount;
	KSI_DataHash *HMAC;
};

int KSI_HMAC_free(KSI_HMAC *hmac){
	if (hmac != NULL && --hmac->refCount == 0) {
		KSI_DataHash_free(hmac->HMAC);
		KSI_free(hmac);
	}	
}


int KSI_HMAC_new(KSI_CTX *ctx, int alg, const char *key, size_t key_len, const char *data, size_t data_len, KSI_HMAC **hmac){
	KSI_ERR err;
	int res = 0;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hashedKey = NULL;
	KSI_DataHash *innerHash = NULL;
	KSI_DataHash *outerHash = NULL;
	
	KSI_HMAC *tmp = NULL;
	
	unsigned char key_for_hashing[MAX_KEY_LEN];
	unsigned char ipadXORkey[MAX_KEY_LEN];
	unsigned char opadXORkey[MAX_KEY_LEN];
	unsigned char *digest = NULL;
	unsigned int digest_len = 0;
	int i =0;
	

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, key != NULL) goto cleanup;
	KSI_PRE(&err, key_len > 0) goto cleanup;
	KSI_PRE(&err, data != NULL) goto cleanup;
	KSI_PRE(&err, data_len > 0) goto cleanup;
	KSI_PRE(&err, hmac != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);
	
	if(KSI_getHashLength(alg) > MAX_KEY_LEN){
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "The hash length is greater than 64");
		goto cleanup;
	}

	tmp = KSI_new(KSI_HMAC);
	if(hmac == NULL){
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}	
	
	tmp->ctx = ctx;
	tmp->refCount = 1;
	tmp->HMAC = NULL;
	
	
	/*Open the hasher*/
	res = KSI_DataHasher_open(ctx, alg, &hsr);
	KSI_CATCH(&err, res);
	
	/*Prepare the key for hashing */
	/*If the key is longer than 64, hash it. If the key or its hash is shorter than 64 bit, append zeros*/
	if(key_len > MAX_KEY_LEN){
		res = KSI_DataHasher_add(hsr, key, key_len);
		KSI_CATCH(&err, res);

		res = KSI_DataHasher_close(hsr, &hashedKey);
		KSI_CATCH(&err, res);
		
		res = KSI_DataHash_extract(hashedKey, NULL, &digest, &digest_len);
		KSI_CATCH(&err, res);
		
		if(digest == NULL || digest_len < 0 || digest_len > MAX_KEY_LEN){
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "The hash of the key is invalid");
			goto cleanup;
		}
		
		memcpy(key_for_hashing, digest, digest_len);
		memset(key_for_hashing+digest_len, 0, MAX_KEY_LEN-digest_len);
		
		digest = NULL;
		digest_len = 0;
	}
	else{
		memcpy(key_for_hashing, key, key_len);
		memset(key_for_hashing+key_len, 0, MAX_KEY_LEN-key_len);
	}
	
	/*XOR the key*/
	for(; i<MAX_KEY_LEN;i++){
		ipadXORkey[i] = ipad[i]^key_for_hashing[i];
		opadXORkey[i] = opad[i]^key_for_hashing[i];
	}
	
	/*Hash inner data*/
	res = KSI_DataHasher_reset(hsr);
	KSI_CATCH(&err, res);
	res = KSI_DataHasher_add(hsr, ipadXORkey, MAX_KEY_LEN);
	KSI_CATCH(&err, res);
	res = KSI_DataHasher_add(hsr, data, data_len);
	KSI_CATCH(&err, res);
	res = KSI_DataHasher_close(hsr, &innerHash);
	KSI_CATCH(&err, res);

	/*Hash outer data*/
	res = KSI_DataHasher_reset(hsr);
	KSI_CATCH(&err, res);
	res = KSI_DataHasher_add(hsr, opadXORkey, MAX_KEY_LEN);
	KSI_CATCH(&err, res);
	res = KSI_DataHash_extract(innerHash, NULL, &digest, &digest_len);
	KSI_CATCH(&err, res);
	res = KSI_DataHasher_add(hsr, digest, digest_len);
	KSI_CATCH(&err, res);
	res = KSI_DataHasher_close(hsr, &outerHash);
	KSI_CATCH(&err, res);
	
	
	res = KSI_DataHash_clone(outerHash, &tmp->HMAC);
	KSI_CATCH(&err, res);
	
	*hmac = tmp;
	tmp = NULL;
	
	KSI_SUCCESS(&err);
	
cleanup:	
	
	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hashedKey);
	KSI_DataHash_free(innerHash);
	KSI_DataHash_free(outerHash);
	KSI_HMAC_free(tmp);
	
	return KSI_RETURN(&err);
}

int KSI_HMAC_clone(KSI_HMAC *from, KSI_HMAC **to) {
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


int KSI_HMAC_getDigest(const KSI_HMAC *hmac, int *hash_id, const unsigned char **digest, unsigned int *digest_length){
	KSI_ERR err;
	int res;
	
	KSI_PRE(&err, hmac != NULL) goto cleanup;

	KSI_BEGIN(hmac->ctx, &err);

	res = KSI_DataHash_extract(hmac->HMAC, hash_id, digest, digest_length);
	KSI_CATCH(&err, res);

	KSI_SUCCESS(&err);
		
cleanup:

	return KSI_RETURN(&err);
}

int KSI_HMAC_toString(const KSI_HMAC *hmac, char *buf, unsigned buf_len){
	char *ret = NULL;
	unsigned i;
	unsigned len = 0;

	int res = 0;
	unsigned char *digest = NULL;
	unsigned digest_len = 0;
	
	if (hmac == NULL || buf == NULL) goto cleanup;

	res = KSI_DataHash_extract(hmac->HMAC, NULL, &digest, &digest_len);
	if(res != KSI_OK) goto cleanup;
	
	for (i = 0; i < digest_len && len < buf_len; i++) {
		len += snprintf(buf + len, buf_len - len, "%02x", digest[i]);
	}

	ret = buf;

cleanup:

	return ret;

}

