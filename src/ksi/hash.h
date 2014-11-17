#ifndef KSI_HASH_H_
#define KSI_HASH_H_

#include "types_base.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup hash Data Hashing
 * This module consists of two main objects:
 * - #KSI_DataHasher - this object is used to calculate hash values (see
 * #KSI_DataHash).
 * - #KSI_DataHash - this immutable object is used to store the calculated
 * hash value.
 * @{
 */

	/**
	 * The maximum length of an imprint.
	 */
	#define KSI_MAX_IMPRINT_LEN 65 /* Algorithm ID (1 byte) + longest digest */

	/**
	 * Starts a hash computation.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		hash_id 	Identifier of the hash algorithm.
	 * See #KSI_HashAlgorithm_en for possible values.
	 * \param[out] hasher Pointer that will receive pointer to the
	 * hasher object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHasher_add, #KSI_DataHasher_close
	 */
	int KSI_DataHasher_open(KSI_CTX *ctx, int hash_id, KSI_DataHasher **hasher);

	/**
	 * Resets the state of the hash computation.
	 * \param[in]	hasher			The hasher.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHasher_open, #KSI_DataHasher_close
	 */
	int KSI_DataHasher_reset(KSI_DataHasher *hasher);

	/**
	 * Adds data to an open hash computation.
	 *
	 * \param[in]	hasher				Hasher object.
	 * \param[in]	data				Pointer to the data to be hashed.
	 * \param[in]	data_length			Length of the hashed data.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHasher_open, #KSI_GTDataHasher_close
	 */
	int KSI_DataHasher_add(KSI_DataHasher *hasher, const void *data, size_t data_length);

	/**
	 * Finalizes a hash computation.
	 * \param[in]	hasher			Hasher object.
	 * \param[out]	hash			Pointer that will receive pointer to the hash object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHasher_open, #KSI_DataHasher_add, #KSI_DataHasher_free
	 */
	int KSI_DataHasher_close(KSI_DataHasher *hasher, KSI_DataHash **hash);

	/**
	 * Frees the data hasher object.
	 * \param[in]		hasher			Hasher object.
	 *
	 * \see #KSI_DataHasher_open
	 */
	void KSI_DataHasher_free(KSI_DataHasher *hasher);

	/**
	 * Frees the data hash object..
	 *
	 * \param[in]	data_hash			#KSI_DataHash object that is to be freed.
	 *
	 * \see #KSI_DataHasher_close, #KSI_DataHash_fromImprint, #KSI_DataHash_fromDigest
	 */
	void KSI_DataHash_free(KSI_DataHash *hash);

	/**
	 * Calculates the data hash object from the input data.
	 *
	 * \param[in]	ctx				KSI context.
	 * \param[in]	data			Pointer to the input data.
	 * \param[in]	data_length		Length of the imput data.
	 * \param[in]	hash_id			Hash algorithm id.
	 * \param[out]	hash			Pointer to the pointer receiving the data hash object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHash_free
	 */
	int KSI_DataHash_create(KSI_CTX *ctx, const void *data, size_t data_length, int hash_id, KSI_DataHash **hash);

	/**
	 * Creates a clone of the data hash.
	 *
	 * \param[in]	from	Data hash to be cloned.
	 * \param[out]	to		Pointer to the receiving pointer to the cloned object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_DataHash_clone(KSI_DataHash *from, KSI_DataHash **to);

	/**
	 * Interneal data access method.
	 *
	 * \param[in]	hash			Data hash object.
	 * \param[out]	hash_id			Algorithm used to compute the hash.
	 * \param[out]	digest			Binary digest value.
	 * \param[out]	digest_length	Length of the digest value.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note If an output variable is set to \c NULL the value will be ignored.
	 * \see #KSI_DataHash_free, #KSI_DataHash_create, #KSI_DataHash_fromDigest
	 */
	int KSI_DataHash_extract(const KSI_DataHash *hash, int *hash_id, const unsigned char **digest, unsigned int *digest_length);

	/**
	 * Constructor for #KSI_DataHash object from existing hash value.
	 * \param[in]		ctx				KSI context.
	 * \param[in]		algorithm		Algorithm used to compute the digest value.
	 * \param[in]		digest			Binary digest value.
	 * \param[in]		digest_length	Lengt of the binary digest value.
	 * \param[in]		hash			Pointer that will receive pointer to the hash object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHash_free, #KSI_DataHash_extract, #KSI_DataHash_fromImprint, #KSI_DataHash_create, #KSI_DataHasher_close
	 */
	int KSI_DataHash_fromDigest(KSI_CTX *ctx, int hash_id, const unsigned char *digest, unsigned int digest_length, KSI_DataHash **hash);

	/**
	 * Encodes the data hash object as an imprtint.
	 *
	 * \param[in]	hash			Data hash object.
	 * \param[out]	imprint			Pointer that will receive pointer to the imprint.
	 * \param[out]	imprint_length	Pointer that will reveive the length of the imprint.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_DataHash_getImprint(const KSI_DataHash *hash, const unsigned char **imprint, unsigned int *imprint_length);

	/**
	 * Constructor for #KSI_DataHash object from existing imprint.
	 *
	 * \param[in]	ctx				KSI context.
	 * \param[in]	imprint			Pointer to the imprint.
	 * \param[in]	imprint_length	Length of the imprint.
	 * \param[out]	hash			Pointer that will receive pointer to the data hash objet.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHash_free, #KSI_DataHash_getImprint, #KSI_DataHash_fromDigest
	 */
	int KSI_DataHash_fromImprint(KSI_CTX *ctx, const unsigned char *imprint, unsigned int imprint_length, KSI_DataHash **hash);

	/**
	 * Returns the hash algorithm specified by the \c name parameter. If the algorithm
	 * name is not recognized -1 is returned.
	 * \param[in]	name			Name of the hash function.
	 *
	 * \return The hash algorithm id or -1 if it was not found.
	 * \see #KSI_getHashAlgorithmName
	 */
	int KSI_getHashAlgorithmByName(const char *name);

	/**
	 * Returns the hash length in bytes for the given hash algorithm id or -1 if the
	 * hash algorithm is not recognized or supported.
	 *
	 * \param[in]	hash_id		Hash algorithm id
	 *
	 * \return Length of the hash value calculated by the given hash algorithm. Returns value -1 on error.
	 */
	unsigned int KSI_getHashLength(int hash_id);

	/**
	 * This function is used to check if the given hash algorithm is trusted. If
	 * the hash algorithm is trusted it returns 1, in all other cases 0.
	 * \param[in]	hash_id			Hash algorithm id.
	 *
	 * \return Returns 1 if algorithm is trusted, otherwise return 0.
	 * \see #KSI_isHashAlgorithmSupported
	 */
	int KSI_isHashAlgorithmTrusted(int hash_id);

	/**
	 * Is the given hash algorithm \c hash_id supported by the API.
	 * \param[in]	hash_id			Hash algorithm id.
	 *
	 * \return Returns 0 if algorithm is not supported, otherwise non-zero.
	 * \see #KSI_isHashAlgorithmTrusted
	 */
	int KSI_isHashAlgorithmSupported(int hash_id);

	/**
	 * Returns a pointer to constant string containing the name of the hash algorithm. Returns NULL if
	 * the algorithm is unknown.
	 * \param[in]	hash_algorithm			The hash algorithm id.
	 *
	 * \return Name of the algorithm or NULL on error.
	 * \see #KSI_getHashAlgorithmByName
	 */
	const char *KSI_getHashAlgorithmName(int hash_id);

	/**
	 * Returns 1 if the two given data hash objects are both not \c NULL and the hash values
	 * equal to each other.
	 * \param[in]	left			One data hash object.
	 * \param[in]	right			An other data hash object.
	 *
	 * \return Returns 0 if the hash object are \c NULL or are not equal, otherwise non-zero value
	 * is returned.
	 */
	int KSI_DataHash_equals(const KSI_DataHash *left, const KSI_DataHash *right);

	/**
	 * This function creates a data hash object from the payload of a raw TLV object.
	 * \param[in]	tlv			TLV object.
	 * \param[out]	hsh			Data hash object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHash_free, #KSI_DataHash_toTlv
	 */
	int KSI_DataHash_fromTlv(KSI_TLV *tlv, KSI_DataHash **hsh);

	/**
	 * Creates a TLV object with the imprint of the given data hash object as the payload.
	 * \param[in]	hsh				Data hash object.
	 * \param[in]	tag				The numeric tag value of the TLV.
	 * \param[in]	isNonCritical	TLV non-critical flag.
	 * \param[in]	isForward		TLV forward-flag.
	 * \param[out]	tlv				Pointer to the receiving TLV pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_TLV_free, #KSI_DataHash_fromTlv
	 */
	int KSI_DataHash_toTlv(KSI_CTX *ctx, KSI_DataHash *hsh, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);
	
	/**
	 * Accessor method for extracting the hash algorithm from the #KSI_DataHash.
     * \param	hash		Data hash object.
     * \param	hashAlg		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
     */
	int KSI_DataHash_getHashAlg(const KSI_DataHash *hash, int *hashAlg);

	/**
	 * Parses the metha value if the hash value is formatted:
	 * - 2 bytes of length (n).
	 * - n bytes of metadata.
	 * - digest length - n bytse of padding with zero values.
	 * \param[in]	metaHash		Metahash value.
	 * \param[out]	data			Pointer to the receiving pointer.
	 * \param[out]	data_len		Pointer to the receiving length variable.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHash_free, #KSI_DataHash_toTlv
	 */
	int KSI_DataHash_MetaHash_parseMeta(const KSI_DataHash *metaHash, const unsigned char **data, int *data_len);

	/**
	 * Works the same way as #KSI_DataHash_fromTlv, but performs an additional
	 * format check on the digest value and makes sure the binary digest is a
	 * null terminated sequence of bytes.
	 * \param[in]	tlv			TLV object.
	 * \param[out]	hsh			Pointer to the receiving data hash object pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_DataHash_MetaHash_fromTlv(KSI_TLV *tlv, KSI_DataHash **hsh);

	/**
	 * Creates a string representation of the datahash.
	 * \param[in]		hsh		Input hash object.
	 * \param[in,out]	buf		Pointer to the receiving buffer.
	 * \param[in]		buf_len	Length of the receiving buffer.
	 */
	char *KSI_DataHash_toString(const KSI_DataHash *hsh, char *buf, unsigned buf_len);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_HASH_H_ */
