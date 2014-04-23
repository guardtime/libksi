#ifndef KSI_HASH_H_
#define KSI_HASH_H_

#include "ksi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * Starts a hash computation.
	 * \see #KSI_DataHasher_add, #KSI_DataHasher_close
	 *
	 * \param[in] ctx Ksi context.
	 * \param[in] hash_algorithm Identifier of the hash algorithm.
	 * See #KSI_HashAlgorithm for possible values.
	 * \param[out] hasher Pointer that will receive pointer to the
	 * hasher object.
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_DataHasher_open(KSI_CTX *ctx, int hash_algorithm, KSI_DataHasher **hasher);

	/**
	 * Resets the state of the hash computation.
	 * \see #KSI_DataHasher_open, #KSI_DataHasher_close
	 *
	 * \param[in] hasher Pointer to the hasher.
	 */
	int KSI_DataHasher_reset(KSI_DataHasher *hasher);

	/**
	 * Adds data to an open hash computation.
	 * \see #KSI_DataHasher_open, #KSI_GTDataHasher_close
	 *
	 * \param[in] hasher Pointer to the hasher object.
	 * \param data \c (in) - Pointer to the data to be hashed.
	 * \param data_length \c (in) - Length of the hashed data.
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_DataHasher_add(KSI_DataHasher *hasher, const void *data, size_t data_length);

	/**
	 * Finalizes a hash computation.
	 * \see #KSI_DataHasher_open, #KSI_DataHasher_add, #KSI_DataHasher_free
	 *
	 * \param[in] hasher	Pointer to the hasher object.
	 * \param[out] hash		Pointer that will receive pointer to the hash object.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_DataHasher_close(KSI_DataHasher *hasher, KSI_DataHash **hash);
	void *KSI_DataHasher_getHahshContext(KSI_DataHasher *hasher);
	int KSI_DataHasher_getAlgorithm(KSI_DataHasher *hasher);
	/**
	 * Frees memory used by hasher.
	 *
	 * \param data_hash \c (in) - \c GTDataHash object that is to be freed.
	 *
	 * \see #KSI_free()
	 */
	void KSI_DataHash_free(KSI_DataHash *hash);

	/**
	 * Calculates the data hash object from the input data.
	 *
	 * @param[in]		ctx				KSI context.
	 * @param[in]		data			Pointer to the input data.
	 * @param[in]		data_length		Length of the imput data.
	 * @param[in]		hash_id			Hash algorithm id.
	 * @param[out]		hash			Pointer to the pointer receiving the data hash object.
	 *
	 * @return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_DataHash_create(KSI_CTX *ctx, const void *data, size_t data_length, int hash_id, KSI_DataHash **hash);

	/**
	 * Creates a clone of the data hash.
	 *
	 * @param[in]	from	Data hash to be cloned.
	 * @param[out]	to		Pointer to the receiving pointer to the cloned object.
	 *
	 * @return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_DataHash_clone(KSI_DataHash *from, KSI_DataHash **to);

	/**
	 * Interneal data access method.
	 *
	 * \param[in]	hash			Data hash object.
	 * \param[out]	algorithm		Algorithm used to compute the hash.
	 * \param[out]	digest			Binary digest value.
	 * \param[out]	digest_length	Length of the digest value.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 *
	 * \note The digest value returned by this function has to be freed by the
	 * programmer with #KSI_free.
	 */
	int KSI_DataHash_getData(KSI_DataHash *hash, int *hash_id, const unsigned char **digest, int *digest_length);

	/**
	 * Constructor for #KSI_DataHash object from existing hash value.
	 * \param[in]	ctx				KSI context.
	 * \param[in]	algorithm		Algorithm used to compute the digest value.
	 * \param[in]	digest			Binary digest value.
	 * \param[in]	digest_length	Lengt of the binary digest value.
	 * \param[in]	hash			Pointer that will receive pointer to the hash object.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_DataHash_fromDigest(KSI_CTX *ctx, int hash_id, const unsigned char *digest, int digest_length, KSI_DataHash **hash);

	/**
	 * Reevaluates the #KSI_DataHash object with another precalculated hash value.
	 * \param[in]	algorithm		Algorithm used to compute the digest value.
	 * \param[in]	digest			Binary digest value.
	 * \param[in]	digest_length	Lengt of the binary digest value.
	 * \param[in]	hash			Pointer to the existing hash object.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_DataHash_fromData_ex(int hash_id, const unsigned char *digest, int digest_length, KSI_DataHash *hash);

	/**
	 * Encodes the data hash object as an imprtint.
	 *
	 * \param[in]	hash			Data hash object.
	 * \param[out]	imprint			Pointer that will receive pointer to the imprint.
	 * \param[out]	imprint_length	Pointer that will reveive the length of the imprint.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_DataHash_getImprint(KSI_DataHash *hash, const unsigned char **imprint, int *imprint_length);

	/**
	 * Encodes the data hash object as an imprint into an existing array.
	 *
	 * @param[in]	hash			Data hash object.
	 * @param[in]	target			Pointer to the existing target memory.
	 * @param[in]	target_size		Maximum output length.
	 * @param[out]	target_length	Length of the serialized imprint.
	 */
	int KSI_DataHash_getImprint_ex(KSI_DataHash *hash, unsigned char *target, int target_size, int *target_length);

	/**
	 * Constructor for #KSI_DataHash object from existing imprint.
	 *
	 * \param[in]	ctx				KSI context.
	 * \param[in]	imprint			Pointer to the imprint.
	 * \param[in]	imprint_length	Length of the imprint.
	 * \param[out]	hash			Pointer that will receive pointer to the data hash objet.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_DataHash_fromImprint(KSI_CTX *ctx, const unsigned char *imprint, int imprint_length, KSI_DataHash **hash);

	/**
	 * Reevaluates the existing #KSI_DataHash object.
	 *
	 * \param[in]	imprint			Pointer to hash imprint.
	 * \param[in]	imprint_length	Length of the imprint.
	 * \param[out]	hash			Pointer to the data hash object.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_DataHash_fromImprint_ex(unsigned char *imprint, int imprint_length, KSI_DataHash *hash);

	/**
	 *
	 */
	const char *KSI_getHashAlgorithmName(int hash_algorithm);

	/**
	 *
	 */
	int KSI_getHashAlgorithmByName(const char *name);

	/**
	 *
	 */
	int KSI_DataHash_create(KSI_CTX *ctx, const void *data, size_t data_length, int hash_id, KSI_DataHash **hash);

	/**
	 *
	 */
	int KSI_DataHash_clone(KSI_DataHash *from, KSI_DataHash **to);

	/**
	 * Returns the hash length in bytes for the given hash algorithm id.
	 *
	 * \param[in]	hash_id		Hash algorithm id
	 *
	 * \return Length of the hash value calculated by the given hash algorithm. Returns negative value on error.
	 */
	int KSI_getHashLength(int hash_id);

	/**
	 * Fixes hash algorithm ID: replaces default ID with the current default
	 * as necessary.
	 **/
	int KSI_fixHashAlgorithm(int hash_id);

	/**
	 * Is \p hash_id hash algorithm trusted?
	 * @param[in]	hash_id		Hash algorithm id.
	 *
	 * @return Returns 0 if algorithm is not trusted, otherwise non-zero.
	 */
	int KSI_isTrusteddHashAlgorithm(int hash_id);

	/**
	 * Is \p hash_id hash algorithm supported by the API.
	 * @param[in]	hash_id		Hash algorithm id.
	 *
	 * @return Returns 0 if algorithm is not supported, otherwise non-zero.
	 */
	int KSI_isSupportedHashAlgorithm(int hash_id);

	/**
	 * Returns a pointer to constant string containing the name of the hash algorithm. Returns NULL if
	 * the algorithm is unknown.
	 *
	 * \param[in]	hash_algorithm	The hash algorithm id.
	 *
	 * \return Name of the algorithm or NULL on error.
	 */
	const char *KSI_getHashAlgorithmName(int hash_algorithm);

	/**
	 * Returns the hash algorithm id for the given name.
	 *
	 * \param[in]	name	Hash algorithm name.
	 *
	 * \return Hash algorithm id or -1 on error.
	 */
	int KSI_getHashAlgorithmByName(const char *name);
	/**
	 *
	 */
	int KSI_DataHash_equals(KSI_DataHash *left, KSI_DataHash *right);

#ifdef __cplusplus
}
#endif

#endif /* KSI_HASH_H_ */
