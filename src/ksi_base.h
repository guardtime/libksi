#ifndef _KSI_BASE_H_
#define _KSI_BASE_H_

#include <stdio.h>
#include <stdint.h>

#include "include/ksi_base32.h"
#include "include/ksi_common.h"
#include "include/ksi_hash.h"
#include "include/ksi_hashchain.h"
#include "include/ksi_io.h"
#include "include/ksi_publicationsfile.h"
#include "include/ksi_list.h"
#include "include/ksi_net_curl.h"
#include "include/ksi_signature.h"
#include "include/ksi_tlv.h"
#include "include/ksi_tlv_template.h"
#include "include/ksi_pkitruststore.h"
#include "include/ksi_types.h"
#include "include/ksi_crc32.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup base KSI base functionality
 * @{
 */

/**
 * KSI function returnvalues.
 */
enum KSI_StatusCode {
/* RETURN CODES WHICH ARE NOT ERRORS */
	KSI_OK = 0,

/* SYNTAX ERRORS */
	/**
	 * Argument to function was invalid. Mostly this indicates \c NULL
	 * pointer.
	 */
	KSI_INVALID_ARGUMENT = 0x100,
	/**
	 * Either arguments to function or responses from the server had
	 * invalid format.
	 */
	KSI_INVALID_FORMAT = 0x101,
	/**
	 * The given hash algorithm is considered untrustworthy by
	 * the verification policy.
	 */
	KSI_UNTRUSTED_HASH_ALGORITHM = 0x102,
	/**
	 * This hash algorithm is not implemented.
	 */
	KSI_UNAVAILABLE_HASH_ALGORITHM = 0x103,
	/**
	 * Buffer too small to perform operation.
	 */
	KSI_BUFFER_OVERFLOW = 0x104,
	/**
	 * TLV payload has wrong type for operation.
	 */
	KSI_TLV_PAYLOAD_TYPE_MISMATCH = 0x105,
	/**
	 * The async operation has not finished.
	 */
	KSI_ASYNC_NOT_FINISHED = 0x106,
	/**
	 * Invalid KSI signature.
	 */
	KSI_INVALID_SIGNATURE = 0x107,
	/**
	 * Invalid PKI signature.
	 */
	KSI_INVALID_PKI_SIGNATURE = 0x108,
	/**
	 * The PKI signature is not trusted by the API.
	 */
	KSI_PKI_CERTIFICATE_NOT_TRUSTED = 0x109,
/* SYSTEM ERRORS */
	/**
	 * Out of memory.
	 */
	KSI_OUT_OF_MEMORY = 0x200,
	/**
	 * IO error occured.
	 */
	KSI_IO_ERROR = 0x201,
	/**
	 * A network error occured.
	 */
	KSI_NETWORK_ERROR,
	/**
	 * A HTTP error occured.
	 */
	KSI_HTTP_ERROR,
	/**
	 * The aggregator returned an error.
	 */
	KSI_AGGREGATOR_ERROR,
	/**
	 * The extender returned an error.
	 */
	KSI_EXTENDER_ERROR,
	/**
	 * The extender returned a wrong calendar chain.
	 */
	KSI_EXTEND_WRONG_CAL_CHAIN,
	/**
	 * No suitable publication to extend to.
	 */
	KSI_EXTEND_NO_SUITABLE_PUBLICATION,
	/**
	 * The publication in the signature was not fround in the publications file.
	 */
	KSI_VERIFY_PUBLICATION_NOT_FOUND,
	/**
	 * The publication in the signature does not match the publication in the publications file.
	 */
	KSI_VERIFY_PUBLICATION_MISMATCH,
	/**
	 * Invalid publication.
	 */
	KSI_INVALID_PUBLICATION,
	/**
	 * Cryptographic operation could not be performed. Likely causes are
	 * unsupported cryptographic algorithms, invalid keys and lack of
	 * resources.
	 */
	KSI_CRYPTO_FAILURE,

	/**
	 * Unknown error occured.
	 */
	KSI_UNKNOWN_ERROR
};
/**
 * Function to convert a #KSI_StatusCode value to a human readable
 * string value.
 *
 * \param[in]		statusCode		#KSI_StatusCode value.
 *
 * \return A pointer to a statically allocated string value. This pointer may
 * not be freed by the caller.
 */
const char *KSI_getErrorString(int statusCode);

/**
 * Constructor for the central KSI object #KSI_CTX. For thread safety, this object
 * may not be shared between threads. Also, this object may be freed only if there
 * are no other objects created using this object - this applies recursively to other
 * objects created by the user.
 *
 * \param[in]		ctx			Pointer to the receiving pointer.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
int KSI_CTX_new(KSI_CTX **ctx);

/**
 * Destructor for KSI context object #KSI_CTX.
 * \param[in]	ctx		KSI ctx.
 *
 * \note This function should not be called when there still exist some
 * objects created using this context.
 */
void KSI_CTX_free(KSI_CTX *ctx);

/**
 * Returns the current status of the error container.
 * \param[in]	ctx		KSI context.
 *
 * \return The current status code of the KSI \c ctx. If \c ctx is NULL a
 * #KSI_INVALID_ARGUMENT is returned.
 */
int KSI_CTX_getStatus(KSI_CTX *ctx);

/**
 * Finalizes the current error stack.
 * \param[in]		err		Pointer to the error object.
 */
int KSI_ERR_apply(KSI_ERR *err);

/**
 * Dump error stack trace to stream.
 * \param[in]		ctx		KSI context object.
 * \param[in]		f		Output stream.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
int KSI_ERR_statusDump(KSI_CTX *ctx, FILE *f);

/**
 * The Guardtime representation of hash algorithms, necessary to calculate
 * instances of #KSI_DataHasher and #KSI_DataHash.
 */
enum KSI_HashAlgorithm {
	/** The SHA-1 algorithm. */
	KSI_HASHALG_SHA1 = 0,
	/** The SHA-256 algorithm. */
	KSI_HASHALG_SHA2_256,
	/** The RIPEMD-160 algorithm. */
	KSI_HASHALG_RIPEMD160,
	/** The SHA-224 algorithm. */
	KSI_HASHALG_SHA2_224,
	/** The SHA-384 algorithm. */
	KSI_HASHALG_SHA2_384,
	/** The SHA-512 algorithm. */
	KSI_HASHALG_SHA2_512,
	/** The RIPEMD-256 algorithm. */
	KSI_HASHALG_RIPEMD_256,
	/** The SHA3-244 algorithm. */
	KSI_HASHALG_SHA3_244,
	/** The SHA3-256 algorithm. */
	KSI_HASHALG_SHA3_256,
	/** The SHA3-384 algorithm. */
	KSI_HASHALG_SHA3_384,
	/** The SHA3-512 algoritm */
	KSI_HASHALG_SHA3_512,
	/** The SM3 algorithm.*/
	KSI_HASHALG_SM3,

	/* Number of known hash algorithms. */
	KSI_NUMBER_OF_KNOWN_HASHALGS,
};

/**
 * KSI global initiation of resources. This function should be called once (independently of
 * the number of threads) at the beginning of the program.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an
 * error code).
 *
 * \note At the end of the program #KSI_global_cleanup should be called.
 */
int KSI_global_init(void);

/**
 * Cleanup function for global objects. This should be called as the last KSI statement executed.
 */
void KSI_global_cleanup(void);

/**
 * Allocates \c size bytes of memory.
 * \param[in]	size		Size of allocated block.
 *
 * \return Pointer to the allocated memory, or \c NULL if an error occurred.
 * \note The caller needs to free the allocated memory with #KSI_free.
 */
void *KSI_malloc(size_t size);

/**
 * Allocates \c num times of \c size bytes of memory.
 * \param[in]	num		Number of blocks to allocate.
 * \param[in]	size	Size of a single block.
 *
 * \return Pointer to the allocated memory, or \c NULL if an error occurred.
 * \note The caller needs to free the allocated memory with #KSI_free.
 */
void *KSI_calloc(size_t num, size_t size);

/**
 * Reallocates pointer \c ptr to \c size bytes.
 * \param[in]	ptr		Pointer to the memory being reallocated.
 * \param[in]	size	New size in bytes.
 *
 * \return Pointer to the allocated memory, or \c NULL if an error occurred.
 * \note The caller needs to free the allocated memory with #KSI_free.
 */
void *KSI_realloc(void *ptr, size_t size);

/**
 * Free memory allocated by #KSI_malloc, #KSI_calloc or #KSI_realloc.
 * \param[in]	ptr		Pointer to the memory to be freed.
 */
void KSI_free(void *ptr);

/**
 * Send a binary signing request using the specified KSI context.
 * \param[in]		ctx					KSI context object.
 * \param[in]		request				Pointer to the binary request.
 * \param[in]		request_length		Length of the binary request.
 * \param[out]		handle				Pointer to the receiving pointer of the network handle.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_sendSignRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle);

/**
 * Send a binary extend request using the specified KSI context.
 * \param[in]		ctx					KSI context object.
 * \param[in]		request				Pointer to the binary request.
 * \param[in]		request_length		Length of the binary request.
 * \param[out]		handle				Pointer to the receiving pointer of the network handle.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_sendExtendRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle);

/**
 * Send a binary request to download publications file using the specified KSI context.
 * \param[in]		ctx					KSI context object.
 * \param[in]		request				Pointer to the binary request.
 * \param[in]		request_length		Length of the binary request.
 * \param[out]		handle				Pointer to the receiving pointer of the network handle.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_sendPublicationRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle);

/**
 * Converts the base-32 encoded publicationstring into #KSI_PublicationData object.
 * \param[in]		ctx				KSI context.
 * \param[in]		publication		Pointer to base-32 encoded publications string.
 * \param[in]		published_data	Pointer to the receiving pointer.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \note The output memory has to be freed by the caller using #KSI_PublicationData_free.
 */
int KSI_PublicationData_fromBase32(KSI_CTX *ctx, const char *publication, KSI_PublicationData **published_data);

/**
 * Functioin to concert the published data into a base-32 encoded null-terminated string.
 * \param[in]		published_data		Pointer to the published data object.
 * \param[out]		publication			Pointer to the receiving pointer.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \note The putput memory has to be freed by the caller using #KSI_free.
 */
int KSI_PublicationData_toBase32(const KSI_PublicationData *published_data, char **publication);

/**
 * Accessor method for the publications file. It will download the publications file from
 * the uri specified by the KSI context.
 * \param[in]		ctx			KSI context.
 * \param[out]		pubFile		Pointer to the receiving pointer.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \note The output value may not be freed by the caller.
 */
int KSI_receivePublicationsFile(KSI_CTX *ctx, KSI_PublicationsFile **pubFile);
int KSI_createSignature(KSI_CTX *ctx, const KSI_DataHash *dataHash, KSI_Signature **sig);
int KSI_extendSignature(KSI_CTX *ctx, KSI_Signature *sig, KSI_Signature **extended);

int KSI_getPKITruststore(KSI_CTX *ctx, KSI_PKITruststore **pki);
int KSI_getNetworkProvider(KSI_CTX *ctx, KSI_NetProvider **net);
int KSI_getLogger(KSI_CTX *ctx, KSI_Logger **logger);

int KSI_setPKITruststore(KSI_CTX *ctx, KSI_PKITruststore *pki);
int KSI_setNetworkProvider(KSI_CTX *ctx, KSI_NetProvider *net);
int KSI_setLogger(KSI_CTX *ctx, KSI_Logger *logger);

/**********
 * UTIL's
 **********/

int KSI_decodeHexStr(const char *hexstr, unsigned char *buf, int buf_size, int *buf_length);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif
