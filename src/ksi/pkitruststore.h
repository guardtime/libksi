#ifndef KSI_TRUSTSTORE_H_
#define KSI_TRUSTSTORE_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \addtogroup pkitruststore PKI Truststore
	 * TODO!
	 * @{
	 */

	/**
	 * Global initialization of the PKI truststore.
	 */
	int KSI_PKITruststore_global_init(void);

	/**
	 * Global finalize of the PKI truststore.
	 */
	void KSI_PKITruststore_global_cleanup(void);

	/**
	 * PKI Truststore constructor. If <tt>\c setDefaults == 1</tt>, the truststore is initiated
	 * with default settings, otherwise a blank truststore is created.
	 * \param[in]	ctx				KSI context.
	 * \param[in]	setDefaults		With or without default system settings.
	 * \param[out]	store			Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKITruststore_new(KSI_CTX *ctx, int setDefaults, KSI_PKITruststore **store);

	/**
	 * Destructor for the PKI Truststore object.
	 * \param[in]	store			PKI Truststore object.
	 */
	void KSI_PKITruststore_free(KSI_PKITruststore *store);

	/**
	 * PKI Certificate constructor.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	der			Pointer to DER encoded certificate.
	 * \param[in]	der_len		Length of the certificate.
	 * \param[out]	cert		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKICertificate_new(KSI_CTX *ctx, const void *der, size_t der_len, KSI_PKICertificate **cert);

	/**
	 * Destructor for the PKI Certificate object.
	 * \param[in]	cert		PKI Certificate object.
	 */
	void KSI_PKICertificate_free(KSI_PKICertificate *cert);

	/**
	 * Function for converting a #KSI_TLV structure into a #KSI_PKICertificate object.
	 * \param[in]	tlv			TLV object containing the DER encoded certificate.
	 * \param[out]	cert		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKICertificate_fromTlv(KSI_TLV *tlv, KSI_PKICertificate **cert);

	/**
	 * Function for converting a #KSI_PKICertificate object into a #KSI_TLV structure.
	 * \param[in]	cert			PKI Certificate object.
	 * \param[in]	tag				Tag of the TLV.
	 * \param[in]	isNonCritical	TLV non-critical-flag value {0,1}.
	 * \param[in]	isForward		TLV forward-flag value {0,1}.
	 * \param[out]	tlv				Pointer to the receiving pointer.

	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKICertificate_toTlv(KSI_PKICertificate *cert, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

	/**
	 * Function to serialise the KSI Certificate object as DER.
	 * \param[in]	cert		PKI Certificate object.
	 * \param[out]	raw			Pointer to the receiving pointer.
	 * \param[out]	raw_len		Serialized length.
	 */
	int KSI_PKICertificate_serialize(KSI_PKICertificate *cert, unsigned char **raw, unsigned *raw_len);

	/**
	 * Constructor for PKI Signature object.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	raw			PKCS7 encoded signature.
	 * \param[in]	raw_len		Signature len.
	 * \param[out]	signature	Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKISignature_new(KSI_CTX *ctx, const void *raw, unsigned raw_len, KSI_PKISignature **signature);

	/**
	 * Destructor for the PKI Signature object.
	 * \param[in]	sig			PKI Signature object.
	 */
	void KSI_PKISignature_free(KSI_PKISignature *sig);

	/**
	 * TODO!
	 */
	int KSI_PKISignature_serialize(KSI_PKISignature *sig, unsigned char **raw, unsigned *raw_len);

	/**
	 * Function for converting a #KSI_TLV structure into a #KSI_PKISignature object.
	 * \param[in]	tlv		TLV structure.
	 * \param[out]	sig		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKISignature_fromTlv(KSI_TLV *tlv, KSI_PKISignature **sig);

	/**
	 * Function for converting #KSI_PKISignature object into a #KSI_TLV structure.
	 * \param[in]	sig				PKI Signature object.
	 * \param[in]	tag				Tag value of the TLV.
	 * \param[in]	isNonCritical	TLV non-critical-flag value {0,1}.
	 * \param[in]	isForward		TLV forward-flag value {0,1}.
	 * \param[out]	tlv				Ponter to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKISignature_toTlv(KSI_PKISignature *sig, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

	/**
	 * Function for verifying a raw signature. TODO! - explain in detail!
	 * \param[in]	ctx				KSI contetx.
	 * \param[in]	data			Pointer to input data.
	 * \param[in]	data_len		Input data len.
	 * \param[in]	algoOid			Algorithm used to sign the input data.
	 * \param[in]	signature		Pointer to the raw signature.
	 * \param[in]	signature_len	Signature length.
	 * \param[in]	cert			PKI Certificate object.
	 *
	 * \return status code (\c #KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKITruststore_verifyRawSignature(KSI_CTX *ctx, const unsigned char *data, unsigned data_len, const char *algoOid, const unsigned char *signature, unsigned signature_len, const KSI_PKICertificate *cert);

	/**
	 * Function for verifying the data with PKI Signature.
	 * \param[in]	pki			PKI Truststore.
	 * \param[in]	data		Pointer to signed data.
	 * \param[in]	data_len	Length of the signed data.
	 * \param[in]	signature	PKI signature object.
	 *
	 * \return status code (\c #KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKITruststore_verifySignature(KSI_PKITruststore *pki, const unsigned char *data, size_t data_len, const KSI_PKISignature *signature);

	/**
	 * Add trusted certificate lookup file.
	 * \param[in]	store		PKI truststore.
	 * \param[in]	path		Null-terminated sting path to the file containing trusted certificates.
	 *
	 * \return status code (\c #KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKITruststore_addLookupFile(KSI_PKITruststore *store, const char *path);

	/**
	 * Add trusted certificate lookup directory.
	 * \param[in]	store		PKI truststore.
	 * \param[in]	path		Null-terminated sting path to the directory containing trusted certificates..
	 *
	 * \return status code (\c #KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PKITruststore_addLookupDir(KSI_PKITruststore *store, const char *path);


#ifdef __cplusplus
}
#endif

#endif /* KSI_TRUSTSTORE_H_ */
