#ifndef KSI_SIGNATURE_H_
#define KSI_SIGNATURE_H_

#include "ksi_common.h"

#ifdef __cplusplus
extern "C" {
#endif
	/**
	 * \addtogroup signature KSI Signature
	 * At the highest level of abstraction, a keyless signature consists of a hash chain linking the
	 * signed document to the root hash value of the aggregation tree, followed by another hash chain
	 * linking the root hash value of the aggregation tree to the published trust anchor.
	 * @{
	 */

	/**
	 * Free the signature object.
	 * \param[in]	signature		Signature object.
	 */
	void KSI_Signature_free(KSI_Signature *signature);

	/**
	 * This function verifies the signature using online resources. If the
	 * signature has a publication attached to it, the publication is verified
	 * using the publications file. Otherwise, the signature is verified by
	 * an attempt to extend it.
	 * \param[in]		sig			Signature to be verified.
	 * \param[in]		ctx			KSI context to be used.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_Signature_verify(KSI_Signature *sig, KSI_CTX *ctx);
	/**
	 * Creates a clone of the signature object.
	 * \param[in]		sig			Signature to be cloned.
	 * \param[out]		clone		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_Signature_clone(const KSI_Signature *sig, KSI_Signature **clone);

	/**
	 * Parses a KSI signature from raw buffer. The raw buffer may be freed after
	 * this function finishes. To reserialize the signature use #KSI_Signature_serialize.
	 *
	 * \param[in]		ctx			KSI context.
	 * \param[in]		raw			Pointer to the raw signature.
	 * \param[in]		raw_len		Length of the raw signature.
	 * \param[out]		sig			Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_parse(KSI_CTX *ctx, unsigned char *raw, int raw_len, KSI_Signature **sig);

	/**
	 * A convenience function for reading a signature from a file.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		fileName	Name of the signature file.
	 * \param[out]		sig			Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_fromFile(KSI_CTX *ctx, const char *fileName, KSI_Signature **sig);

	/**
	 * This function serializes the signature object into raw data. To deserialize it again
	 * use #KSI_Signature_parse.
	 * \param[in]		sig			Signature object.
	 * \param[out]		raw			Pointer to the pointer to output buffer.
	 * \param[out]		raw_len		Pointer to the length of the buffer variable.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_free.
	 */
	int KSI_Signature_serialize(KSI_Signature *sig, unsigned char **raw, int *raw_len);

	/**
	 * This function signs the given data hash \c hsh. This function requires a access to
	 * a working aggregator and fails if it is not accessible.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		hsh			Document hash.
	 * \param[out]		signature	Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note For signing hash values, the use of #KSI_createSignature is strongly
	 * recomended.
	 * \see #KSI_createSignature
	 */
	int KSI_Signature_create(KSI_CTX *ctx, const KSI_DataHash *hsh, KSI_Signature **signature);

	/**
	 * This function extends the signature to the given publication \c pubRec. If \c pubRec is \c NULL the signature is
	 * extended to the head of the calendar database. This function requires access to a working KSI extender or it will
	 * fail with an error.
	 * \param[in]		signature	KSI signature to be extended.
	 * \param[in]		pubRec		Publication record.
	 * \param[out]		extended	Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note The output signature is independent of the input signature and needs to be freed using #KSI_Signature_free.
	 */
	int KSI_Signature_extend(const KSI_Signature *signature, const KSI_PublicationRecord *pubRec, KSI_Signature **extended);

	/**
	 * Access method for the signed document hash as a #KSI_DataHash object.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		hsh			Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note The output hash \c hsh may not be freed by the caller.
	 */
	int KSI_Signature_getDocumentHash(KSI_Signature *sig, const KSI_DataHash ** hsh);

	/**
	 * Access method for the hash algorithm used to hash the signed document.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		hash_id		Pointer to the receiving hash id variable.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHash_open, #KSI_DataHash_create, #KSI_DataHash_close,
	 * #KSI_Signature_createDataHasher.
	 */
	int KSI_Signature_getHashAlgorithm(KSI_Signature *sig, int *hash_id);

	/**
	 * This method creates a data hasher object to be used on the signed data.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		hsr			Data hasher.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHasher_free, #KSI_DataHasher_close, #KSI_DataHasher_open,
	 * #KSI_Signature_getHashAlgorithm.
	 */
	int KSI_Signature_createDataHasher(KSI_Signature *sig, KSI_DataHasher **hsr);
	/**
	 * Access method for the signing time. The \c signTime is expressed as
	 * the number of seconds since 1970-01-01 00:00:00 UTC.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		signTime	Pointer to the receiving variable.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_getSigningTime(const KSI_Signature *sig, KSI_Integer **signTime);

	/**
	 * Function to get signer identity.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		identity	Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note The output memory buffer belongs to the caller and needs to be freed
	 * by the caller using #KSI_free.
	 */
	int KSI_Signature_getSignerIdentity(KSI_Signature *sig, char **identity);

	/**
	 * Accessor method for the published data. If the signature does not have a publication
	 * record the \c pubData will be set to \c NULL.
	 * \param[in]		sig			KSI signature.
	 * \param[out]		pubData		Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_getPublicatioinRecord(KSI_Signature *sig, KSI_PublicationRecord **pubRec);

	/**
	 * This function verifies given hash value \c hsh using the signature \c sig. If
	 * the hash value does not match the input hash value of the signeture, a
	 * #KSI_WRONG_DOCUMENT error code is returned.
	 * \param[in]		sig			KSI signature.
	 * \param[in]		hsh			Document hash.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_verifyDataHash(KSI_Signature *sig, KSI_DataHash *hsh);

	/**
	 * This function verifies the given document using the signature. If the hash value of
	 * the document does not match the input hash value of the signature, a
	 * #KSI_WRONG_DOCUMENT error code is returned.
	 * \param[in]		sig			KSI signature.
	 * \param[in]		doc			Pointer to the document.
	 * \param[in]		doc_len		Length of the document.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_Signature_verifyDocument(KSI_Signature *sig, void *doc, size_t doc_len);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_SIGNATURE_H_ */
