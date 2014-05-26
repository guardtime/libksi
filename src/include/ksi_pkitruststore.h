#ifndef KSI_TRUSTSTORE_H_
#define KSI_TRUSTSTORE_H_

#include "ksi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \ingroup pkitruststore
	 * Global initialization of the PKI truststore.
	 */
	int KSI_PKITruststore_global_init(void);

	/**
	 * \ingroup pkitruststore
	 * Global finalize of the PKI truststore.
	 */
	void KSI_PKITruststore_global_cleanup(void);

	/**
	 * \ingroup pkitruststore
	 * PKI Truststore constructor. If #setDefaults == 1, the truststore is initiated
	 * with default settings, otherwise a blank truststore is created.
	 * \param[in]	ctx				KSI context.
	 * \param[in]	setDefaults		With or without default system settings.
	 * \param[out]	store			Pointer to the receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKITruststore_new(KSI_CTX *ctx, int setDefaults, KSI_PKITruststore **store);

	/**
	 * \ingroup pkitruststore
	 * Destructor for the PKI Truststore object.
	 * \param[in]	store			PKI Truststore object.
	 */
	void KSI_PKITruststore_free(KSI_PKITruststore *store);

	/**
	 * \ingroup pkitruststore
	 * PKI Certificate constructor.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	der			Pointer to DER encoded certificate.
	 * \param[in]	der_len		Length of the certificate.
	 * \param[out]	cert		Pointer to the receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKICertificate_new(KSI_CTX *ctx, const void *der, int der_len, KSI_PKICertificate **cert);

	/**
	 * \ingroup pkitruststore
	 * Destructor for the PKI Certificate object.
	 * \param[in]	cert		PKI Certificate object.
	 */
	void KSI_PKICertificate_free(KSI_PKICertificate *cert);

	/**
	 * \ingroup pkitruststore
	 * Function for converting a #TLV structure into a #KSI_PKICertificate object.
	 * \param[in]	tlv			TLV object containing the DER encoded certificate.
	 * \param[out]	cert		Pointer to the receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKICertificate_fromTlv(KSI_TLV *tlv, KSI_PKICertificate **cert);

	/**
	 * \ingroup pkitruststore
	 * Function for converting a #KSI_PKICertificate object into a #TLV structure.
	 * \param[in]	cert			PKI Certificate object.
	 * \param[in]	tag				Tag of the TLV.
	 * \param[in]	isNonCritical	TLV non-critical-flag value {0,1}.
	 * \param[in]	isForward		TLV forward-flag value {0,1}.
	 * \param[out]	tlv				Pointer to the receiving pointer.

	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKICertificate_toTlv(KSI_PKICertificate *cert, int tag, int isNonCritical, int isForward, KSI_TLV **tlv);

	/**
	 * \ingroup pkitruststore
	 * Function to serialise the KSI Certificate object as DER.
	 * \param[in]	cert		PKI Certificate object.
	 * \param[out]	raw			Pointer to the receiving pointer.
	 * \param[out]	raw_len		Serialized length.
	 */
	int KSI_PKICertificate_serialize(KSI_PKICertificate *cert, unsigned char **raw, int *raw_len);

	/**
	 * \ingroup pkitruststore
	 * Constructor for PKI Signature object.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	raw			PKCS7 encoded signature.
	 * \param[in]	raw_len		Signature len.
	 * \param[out]	signature	Pointer to the receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKISignature_new(KSI_CTX *ctx, const void *raw, int raw_len, KSI_PKISignature **signature);

	/**
	 * \ingroup pkitruststore
	 * Destructor for the PKI Signature object.
	 * \param[in]	sig			PKI Signature object.
	 */
	void KSI_PKISignature_free(KSI_PKISignature *sig);

	/**
	 * \ingroup pkitruststore
	 * Function for converting a #TLV structure into a #KSI_PKISignature object.
	 * \param[in]	tlv		TLV structure.
	 * \param[out]	sig		Pointer to the receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKISignature_fromTlv(KSI_TLV *tlv, KSI_PKISignature **sig);

	/**
	 * \ingroup pkitruststore
	 * Function for converting #KSI_PKISignature object into a #TLV structure.
	 * \param[in]	sig				PKI Signature object.
	 * \param[in]	tag				Tag value of the TLV.
	 * \param[in]	isNonCritical	TLV non-critical-flag value {0,1}.
	 * \param[in]	isForward		TLV forward-flag value {0,1}.
	 * \param[out]	tlv				Ponter to the receiving pointer.
	 */
	int KSI_PKISignature_toTlv(KSI_PKISignature *sig, int tag, int isNonCritical, int isForward, KSI_TLV **tlv);

	/**
	 * \ingroup pkitruststore
	 * Function for validating a raw signature. TODO! - explain in detail!
	 * \param[in]	ctx				KSI contetx.
	 * \param[in]	data			Pointer to input data.
	 * \param[in]	data_len		Input data len.
	 * \param[in]	algoOid			Algorithm used to sign the input data.
	 * \param[in]	signature		Pointer to the raw signature.
	 * \param[in]	signature_len	Signature length.
	 * \param[in]	cert			PKI Certificate object.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKITruststore_validateRawSignature(KSI_CTX *ctx, unsigned char *data, unsigned int data_len, const char *algoOid, const unsigned char *signature, unsigned int signature_len, const KSI_PKICertificate *cert);

	/**
	 * \ingroup pkitruststore
	 * Function for validating PKI Signature.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	data		Pointer to signed data.
	 * \param[in]	data_len	Length of the signed data.
	 * \param[in]	signature	PKI signature object.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKITruststore_validateSignature(KSI_CTX *ctx, const unsigned char *data, unsigned int data_len, const KSI_PKISignature *signature);

	/**
	 * \ingroup pkitruststore
	 * Add trusted certificate lookup file.
	 * \param[in]	store		PKI truststore.
	 * \param[in]	path		Null-terminated sting path to the file containing trusted certificates.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKITruststore_addLookupFile(KSI_PKITruststore *store, const char *path);

	/**
	 * \ingroup pkitruststore
	 * Add trusted certificate lookup directory.
	 * \param[in]	store		PKI truststore.
	 * \param[in]	path		Null-terminated sting path to the directory containing trusted certificates..
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int GTTruststore_addLookupDir(KSI_PKITruststore *store, const char *path);


#ifdef __cplusplus
}
#endif

#endif /* KSI_TRUSTSTORE_H_ */
