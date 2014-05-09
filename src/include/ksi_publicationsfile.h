#include "module/ksi_ksitrustprovider.h"

#ifndef KSI_PUBLICATIONSFILE_H_
#define KSI_PUBLICATIONSFILE_H_

#ifdef __cplusplus
extern "C" {
#endif
	int KSI_KSITrustProvider_fromFile(KSI_CTX *ctx, const char *fileName, KSI_KSITrustProvider **store);
	int KSI_KSITrustProvider_getHeader(const KSI_KSITrustProvider *t, KSI_PublicationsHeader **header);
	int KSI_KSITrustProvider_getCertificates(const KSI_KSITrustProvider *t, KSI_LIST(KSI_CertificateRecord) **certificates);
	int KSI_KSITrustProvider_getPublications(const KSI_KSITrustProvider *t, KSI_LIST(KSI_PublicationRecord) **publications);
	int KSI_KSITrustProvider_getSignature(const KSI_KSITrustProvider *t, KSI_OctetString **signature);

#ifdef __cplusplus
}
#endif

#endif /* KSI_PUBLICATIONSFILE_H_ */
