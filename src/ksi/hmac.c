#include <string.h>

#include "internal.h"
#include "hmac.h"

#define MAX_KEY_LEN 64

#define ipad8 0x36,0x36,0x36,0x36,0x36,0x36,0x36,0x36
#define opad8 0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c,0x5c

static const unsigned char ipad[MAX_KEY_LEN]={ipad8,ipad8,ipad8,ipad8,ipad8,ipad8,ipad8,ipad8};
static const unsigned char opad[MAX_KEY_LEN]={opad8,opad8,opad8,opad8,opad8,opad8,opad8,opad8};

int KSI_HMAC_create(KSI_CTX *ctx, int alg, const char *key, const unsigned char *data, unsigned data_len, KSI_DataHash **hmac){
	KSI_ERR err;
	int res;
	KSI_DataHasher *hsr = NULL;
	KSI_DataHash *hashedKey = NULL;
	KSI_DataHash *innerHash = NULL;
	KSI_DataHash *outerHash = NULL;
	KSI_DataHash *tmp = NULL;
	
	int key_len = -1;
	const unsigned char *bufKey = NULL;
	unsigned int buf_len = 0;
	unsigned char ipadXORkey[MAX_KEY_LEN];
	unsigned char opadXORkey[MAX_KEY_LEN];
	const unsigned char *digest = NULL;
	unsigned int digest_len = 0;
	unsigned int i =0;
	

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, key != NULL) goto cleanup;
	KSI_PRE(&err, (key_len = strlen(key)) > 0) goto cleanup;
	KSI_PRE(&err, data != NULL) goto cleanup;
	KSI_PRE(&err, data_len > 0) goto cleanup;
	KSI_PRE(&err, hmac != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);
	
	if(KSI_getHashLength(alg) > MAX_KEY_LEN){
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, "The hash length is greater than 64");
		goto cleanup;
	}
	
	/* Open the hasher. */
	res = KSI_DataHasher_open(ctx, alg, &hsr);
	KSI_CATCH(&err, res);
	
	/* Prepare the key for hashing. */
	/* If the key is longer than 64, hash it. If the key or its hash is shorter than 64 bit, append zeros. */
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
		
		bufKey = digest;
		buf_len = digest_len;
	} else{
		bufKey = key;
		buf_len = key_len;
	}
	
	for(i = 0; i < buf_len; i++) {
		ipadXORkey[i] = ipad[i]^bufKey[i];
		opadXORkey[i] = opad[i]^bufKey[i];
	}

	for(; i< MAX_KEY_LEN; i++){
		ipadXORkey[i] = 0x36;
		opadXORkey[i] = 0x5c;
	}
	
	/* Hash inner data. */
	res = KSI_DataHasher_reset(hsr);
	KSI_CATCH(&err, res);
	res = KSI_DataHasher_add(hsr, ipadXORkey, MAX_KEY_LEN);
	KSI_CATCH(&err, res);
	res = KSI_DataHasher_add(hsr, data, data_len);
	KSI_CATCH(&err, res);
	res = KSI_DataHasher_close(hsr, &innerHash);
	KSI_CATCH(&err, res);

	/* Hash outer data. */
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
	
	res = KSI_DataHash_clone(outerHash, &tmp);
	KSI_CATCH(&err, res);
	
	*hmac = tmp;
	tmp = NULL;
	
	KSI_SUCCESS(&err);
	
cleanup:	
	
	KSI_DataHasher_free(hsr);
	KSI_DataHash_free(hashedKey);
	KSI_DataHash_free(innerHash);
	KSI_DataHash_free(outerHash);
	KSI_DataHash_free(tmp);
	
	return KSI_RETURN(&err);
}
