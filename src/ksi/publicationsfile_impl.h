#ifndef PUBLICATIONSFILE_IMPL_H_
#define PUBLICATIONSFILE_IMPL_H_

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_PublicationsFile_st {
		KSI_CTX *ctx;
		unsigned char *raw;
		int raw_len;
		KSI_PublicationsHeader *header;
		KSI_LIST(KSI_CertificateRecord) *certificates;
		KSI_LIST(KSI_PublicationRecord) *publications;
		size_t signatureOffset;
		KSI_PKISignature *signature;
	};

	struct KSI_PublicationData_st {
		KSI_CTX *ctx;
		KSI_Integer *time;
		KSI_DataHash *imprint;
	};

	struct KSI_PublicationRecord_st {
		KSI_CTX *ctx;
		KSI_PublicationData *publishedData;
		KSI_LIST(KSI_Utf8String) *publicationRef;
	};


#ifdef __cplusplus
}
#endif

#endif /* PUBLICATIONSFILE_IMPL_H_ */
