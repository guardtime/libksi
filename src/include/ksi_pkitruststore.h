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
	int KSI_PKICertificate_fromTlv(KSI_TLV *tlv, KSI_PKICertificate **cert);
	int KSI_PKICertificate_toTlv(KSI_PKICertificate *cert, int tag, int isNonCritical, int isForward, KSI_TLV **tlv);
	int KSI_PKICertificate_serialize(KSI_PKICertificate *cert, unsigned char **raw, int *raw_len);

	int KSI_PKISignature_new(KSI_CTX *ctx, const void *raw, int raw_len, KSI_PKISignature **signature);
	void KSI_PKISignature_free(KSI_PKISignature *sig);
	int KSI_PKISignature_fromTlv(KSI_TLV *tlv, KSI_PKISignature **sig);
	int KSI_PKISignature_toTlv(KSI_PKISignature *sig, int tag, int isNonCritical, int isForward, KSI_TLV **tlv);


	int KSI_PKITruststore_validateSignatureWithCert(KSI_CTX *ctx, unsigned char *data, unsigned int data_len, const char *algoOid, const unsigned char *signature, unsigned int signature_len, const KSI_PKICertificate *cert);
	int KSI_PKITruststore_global_init();

	int KSI_PKITruststore_addLookupFile(KSI_PKITruststore *trust, const char *path);
	int GTTruststore_addLookupDir(KSI_PKITruststore *trust, const char *path);

	int KSI_PKITruststore_validateSignature(KSI_CTX *ctx, const unsigned char *data, unsigned int data_len, const KSI_PKISignature *signature);

#ifdef __cplusplus
}
#endif

#endif /* KSI_TRUSTSTORE_H_ */
