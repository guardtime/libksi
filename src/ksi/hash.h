/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

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
	 * This structure is used for calculating the hash values.
	 * \see #KSI_DataHash, #KSI_DataHasher_open, #KSI_DataHasher_reset, #KSI_DataHasher_close, #KSI_DataHasher_free
	 */
	typedef struct KSI_DataHasher_st KSI_DataHasher;

	/**
	 * This structure represents hashed data.
	 * \see #KSI_DataHasher, #KSI_DataHasher_close, #KSI_DataHash_free
	 */
	typedef struct KSI_DataHash_st KSI_DataHash;

	/**
	 * The Guardtime representation of hash algorithms, necessary to calculate
	 * instances of #KSI_DataHasher and #KSI_DataHash.
	 */
	typedef enum KSI_HashAlgorithm_en {
		/** An invalid hash algorithm. This is returned from #KSI_getHashAlgorithmByName,  */
		KSI_HASHALG_INVALID = -1,

		/** The SHA-1 algorithm. */
		KSI_HASHALG_SHA1 = 0x00,
		/** The SHA-256 algorithm. */
		KSI_HASHALG_SHA2_256 = 0x01,
		/** The RIPEMD-160 algorithm. */
		KSI_HASHALG_RIPEMD160 = 0x02,
		/** The SHA-224 algorithm. */
		KSI_HASHALG_SHA2_224 = 0x03,
		/** The SHA-384 algorithm. */
		KSI_HASHALG_SHA2_384 = 0x04,
		/** The SHA-512 algorithm. */
		KSI_HASHALG_SHA2_512 = 0x05,
		/** The SHA3-244 algorithm. */
		KSI_HASHALG_SHA3_244 = 0x07,
		/** The SHA3-256 algorithm. */
		KSI_HASHALG_SHA3_256 = 0x08,
		/** The SHA3-384 algorithm. */
		KSI_HASHALG_SHA3_384 = 0x09,
		/** The SHA3-512 algorithm */
		KSI_HASHALG_SHA3_512 = 0x0a,
		/** The SM3 algorithm.*/
		KSI_HASHALG_SM3 = 0x0b,

		/* Number of known hash algorithms. */
		KSI_NUMBER_OF_KNOWN_HASHALGS,
	} KSI_HashAlgorithm;


	/**
	 * The maximum length of an imprint.
	 */
	#define KSI_MAX_IMPRINT_LEN 65 /* Algorithm ID (1 byte) + longest digest */

	/**
	 * Starts a hash computation.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		algo_id 	Identifier of the hash algorithm.
	 * See #KSI_HashAlgorithm_en for possible values.
	 * \param[out] hasher Pointer that will receive pointer to the
	 * hasher object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHasher_add, #KSI_DataHasher_close
	 */
	int KSI_DataHasher_open(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, KSI_DataHasher **hasher);

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
	 * \see #KSI_DataHasher_open, #KSI_DataHasher_close
	 */
	int KSI_DataHasher_add(KSI_DataHasher *hasher, const void *data, size_t data_length);

	/**
	 * Adds the imprint of the given datahash to the hasher.
	 * \param[in]	hasher				Hasher object.
	 * \param[in]	hsh					Datahash object.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_DataHasher_addImprint(KSI_DataHasher *hasher, const KSI_DataHash *hsh);
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
	 * \param[in]	hash			#KSI_DataHash object that is to be freed.
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
	 * \param[in]	algo_id			Hash algorithm id.
	 * \param[out]	hash			Pointer to the pointer receiving the data hash object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHash_free
	 */
	int KSI_DataHash_create(KSI_CTX *ctx, const void *data, size_t data_length, KSI_HashAlgorithm algo_id, KSI_DataHash **hash);

	/**
	 * Creates a clone of the data hash.
	 *
	 * \param[in]	from	Data hash to be cloned.
	 * \param[out]	to		Pointer to the receiving pointer to the cloned object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	KSI_FN_DEPRECATED(int KSI_DataHash_clone(KSI_DataHash *from, KSI_DataHash **to));

	/**
	 * Extracts the hashing algorithm, digest and its length from the #KSI_DataHash. If any
	 * of the output pointers is \c NULL, it is ignored. The digest is a pointer to an
	 * internal field of the #KSI_DataHash thus extracting the digest does not make a
	 * copy of the buffer. This means the digest pointer is valid until #KSI_DataHash_free
	 * is called on the object.
	 *
	 * \param[in]	hash			Data hash object.
	 * \param[out]	algo_id			Algorithm used to compute the hash.
	 * \param[out]	digest			Binary digest value.
	 * \param[out]	digest_length	Length of the digest value.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note If an output variable is set to \c NULL the value will be ignored.
	 * \see #KSI_DataHash_free, #KSI_DataHash_create, #KSI_DataHash_fromDigest
	 */
	int KSI_DataHash_extract(const KSI_DataHash *hash, KSI_HashAlgorithm *algo_id, const unsigned char **digest, size_t *digest_length);

	/**
	 * Constructor for #KSI_DataHash object from existing hash value.
	 *
	 * \param[in]		ctx				KSI context.
	 * \param[in]		algo_id			Algorithm used to compute the digest value.
	 * \param[in]		digest			Binary digest value.
	 * \param[in]		digest_length	Length of the binary digest value.
	 * \param[in]		hash			Pointer that will receive pointer to the hash object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHash_free, #KSI_DataHash_extract, #KSI_DataHash_fromImprint, #KSI_DataHash_create, #KSI_DataHasher_close
	 */
	int KSI_DataHash_fromDigest(KSI_CTX *ctx, KSI_HashAlgorithm algo_id, const unsigned char *digest, size_t digest_length, KSI_DataHash **hash);

	/**
	 * Encodes the data hash object as an imprint.
	 *
	 * \param[in]	hash			Data hash object.
	 * \param[out]	imprint			Pointer that will receive pointer to the imprint.
	 * \param[out]	imprint_length	Pointer that will receive the length of the imprint.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_DataHash_getImprint(const KSI_DataHash *hash, const unsigned char **imprint, size_t *imprint_length);

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
	int KSI_DataHash_fromImprint(KSI_CTX *ctx, const unsigned char *imprint, size_t imprint_length, KSI_DataHash **hash);

	/**
	 * Returns the hash algorithm specified by the \c name parameter. If the algorithm
	 * name is not recognized the value of KSI_HASHALG_INVALID, witch is not a
	 * correct hashing algorithm, is returned. To verify the correctness of the returned
	 * value #KSI_isHashAlgorithmSupported or #KSI_isHashAlgorithmTrusted function must be used.
	 * \param[in]	name			Name of the hash function.
	 *
	 * \return The hash algorithm id or -1 if it was not found.
	 * \see #KSI_getHashAlgorithmName
	 */
	KSI_HashAlgorithm KSI_getHashAlgorithmByName(const char *name);

	/**
	 * Returns the hash length in bytes for the given hash algorithm id or -1 if the
	 * hash algorithm is not recognized or supported.
	 *
	 * \param[in]	algo_id		Hash algorithm id
	 *
	 * \return Length of the hash value calculated by the given hash algorithm. Returns value -1 on error.
	 */
	unsigned int KSI_getHashLength(KSI_HashAlgorithm algo_id);

	/**
	 * This function is used to check if the given hash algorithm is trusted. If
	 * the hash algorithm is trusted it returns 1, in all other cases 0.
	 * \param[in]	algo_id			Hash algorithm id.
	 *
	 * \return Returns 1 if algorithm is trusted, otherwise return 0.
	 * \see #KSI_isHashAlgorithmSupported
	 */
	int KSI_isHashAlgorithmTrusted(KSI_HashAlgorithm algo_id);

	/**
	 * Is the given hash algorithm \c hash_id supported by the API.
	 * \param[in]	algo_id			Hash algorithm id.
	 *
	 * \return Returns 0 if algorithm is not supported, otherwise non-zero.
	 * \see #KSI_isHashAlgorithmTrusted
	 */
	int KSI_isHashAlgorithmSupported(KSI_HashAlgorithm algo_id);

	/**
	 * Returns a pointer to constant string containing the name of the hash algorithm. Returns NULL if
	 * the algorithm is unknown.
	 * \param[in]	algo_id			The hash algorithm id.
	 *
	 * \return Name of the algorithm or NULL on error.
	 * \see #KSI_getHashAlgorithmByName
	 */
	const char *KSI_getHashAlgorithmName(KSI_HashAlgorithm algo_id);

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

	KSI_DEFINE_FN_FROM_TLV(KSI_DataHash);
	KSI_DEFINE_FN_TO_TLV(KSI_DataHash);

	/**
	 * Accessor method for extracting the hash algorithm from the #KSI_DataHash.
     * \param	hash		Data hash object.
     * \param	algo_id		Pointer to the receiving pointer.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
     */
	int KSI_DataHash_getHashAlg(const KSI_DataHash *hash, KSI_HashAlgorithm *algo_id);

	/**
	 * Parses the meta value if the hash value is formatted:
	 * - 2 bytes of length (n).
	 * - n bytes of metadata.
	 * - digest length - n bytes of padding with zero values.
	 * \param[in]	metaHash		Metahash value.
	 * \param[out]	data			Pointer to the receiving pointer.
	 * \param[out]	data_len		Pointer to the receiving length variable.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_DataHash_free, #KSI_DataHash_toTlv
	 */
	int KSI_DataHash_MetaHash_parseMeta(const KSI_DataHash *metaHash, const unsigned char **data, size_t *data_len);

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
	 * \return Returns the pointer to the buffer or NULL on error.
	 */
	char *KSI_DataHash_toString(const KSI_DataHash *hsh, char *buf, size_t buf_len);

	KSI_DEFINE_REF(KSI_DataHash);
/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_HASH_H_ */
