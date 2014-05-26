#include "module/ksi_ksitrustprovider.h"

#ifndef KSI_PUBLICATIONSFILE_H_
#define KSI_PUBLICATIONSFILE_H_

#ifdef __cplusplus
extern "C" {
#endif
	int KSI_PublicationsFile_fromFile(KSI_CTX *ctx, const char *fileName, KSI_PublicationsFile **store);
	int KSI_PublicationsFile_getHeader(const KSI_PublicationsFile *t, KSI_PublicationsHeader **header);
	int KSI_PublicationsFile_getCertificates(const KSI_PublicationsFile *t, KSI_LIST(KSI_CertificateRecord) **certificates);
	int KSI_PublicationsFile_getPublications(const KSI_PublicationsFile *t, KSI_LIST(KSI_PublicationRecord) **publications);
	int KSI_PublicationsFile_getSignature(const KSI_PublicationsFile *t, KSI_PKISignature **signature);

#ifdef __cplusplus
}
#endif

#endif /* KSI_PUBLICATIONSFILE_H_ */
