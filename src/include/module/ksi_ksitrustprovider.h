#ifndef KSI_KSITRUSTPROVIDER_H_
#define KSI_KSITRUSTPROVIDER_H_

#ifdef __cplusplus
extern "C" {
#endif

	int KSI_PublicationsFile_new(KSI_CTX *ctx, KSI_PublicationsFile **t);
	int KSI_PublicationsFile_fromFile(KSI_CTX *ctx, const char *fileName, KSI_PublicationsFile **store);
	int KSI_PublicationsFile_parse(KSI_CTX *ctx, const void *raw, int raw_len, KSI_PublicationsFile **ksiTrustProvider);

	void KSI_PublicationsFile_free(KSI_PublicationsFile *t);


#ifdef __cplusplus
}
#endif

#endif /* KSI_KSITRUSTPROVIDER_H_ */
