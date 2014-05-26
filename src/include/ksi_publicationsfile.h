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

	int KSI_PublicationsFile_getPKICertificateById(const KSI_PublicationsFile *trust, const KSI_OctetString *id, KSI_PKICertificate **cert);

	int KSI_PublicationsFile_getPublicationDataByTime(const KSI_PublicationsFile *trust, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);
	int KSI_PublicationsFile_getNearestPublication(const KSI_PublicationsFile *trust, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);
	int KSI_PublicationsFile_getLatestPublication(const KSI_PublicationsFile *trust, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);



#ifdef __cplusplus
}
#endif

#endif /* KSI_PUBLICATIONSFILE_H_ */
