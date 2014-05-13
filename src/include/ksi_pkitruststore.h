#ifndef KSI_TRUSTSTORE_H_
#define KSI_TRUSTSTORE_H_

#include "ksi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

	int KSI_PKITruststore_new(KSI_CTX *ctx, int setDefaults, KSI_PKITruststore **trust);
	void KSI_PKITruststore_free(KSI_PKITruststore *trust);

	void KSI_PKICertificate_free(KSI_PKICertificate *cert);
	int KSI_PKICertificate_new(KSI_CTX *ctx, const void *der, int der_len, KSI_PKICertificate **cert);
	int KSI_PKICertificate_find(KSI_CTX *ctx, const unsigned char *certId, int certId_len, const KSI_PKICertificate **cert);

	int KSI_PKITruststore_validateSignatureWithCert(KSI_CTX *ctx, unsigned char *data, unsigned int data_len, const char *algoOid, unsigned char *signature, unsigned int signature_len, const KSI_PKICertificate *cert);
	int KSI_PKITruststore_global_init();

#ifdef __cplusplus
}
#endif

#endif /* KSI_TRUSTSTORE_H_ */
