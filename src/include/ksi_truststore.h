#ifndef KSI_TRUSTSTORE_H_
#define KSI_TRUSTSTORE_H_

#include "ksi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

	void KSI_Certificate_free(KSI_Certificate *cert);
	int KSI_Certificate_new(KSI_CTX *ctx, const void *der, int der_len, KSI_Certificate **cert);
	int KSI_Certificate_find(KSI_CTX *ctx, const unsigned char *certId, int certId_len, const KSI_Certificate **cert);

	int KSI_Truststore_validatePKISignature(unsigned char *data, unsigned int data_len, const char *algoOid, unsigned char *signature, unsigned int signature_len, const KSI_Certificate *cert);
	int KSI_Truststore_global_init();

#ifdef __cplusplus
}
#endif

#endif /* KSI_TRUSTSTORE_H_ */
