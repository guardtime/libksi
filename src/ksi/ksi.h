#ifndef _KSI_BASE_H_
#define _KSI_BASE_H_

#include <stdio.h>
#include <stdint.h>

#include "base32.h"
#include "err.h"
#include "hash.h"
#include "hashchain.h"
#include "io.h"
#include "publicationsfile.h"
#include "log.h"
#include "net.h"
#include "signature.h"
#include "tlv.h"
#include "tlv_template.h"
#include "pkitruststore.h"
#include "types.h"
#include "crc32.h"
#include "verification.h"
#include "hmac.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup base KSI base functionality
 * @{
 */

#define KSI_DEFAULT_URI_AGGREGATOR "192.168.1.29:1234"
#define KSI_DEFAULT_URI_EXTENDER "192.168.1.36:8081/gt-extendingservice"
#define KSI_DEFAULT_URI_PUBLICATIONS_FILE "http://verify.guardtime.com/ksi-publications.bin"

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
	 * A network connection timeout occured.
	 */
	KSI_NETWORK_CONNECTION_TIMEOUT,
	/**
	 * A network send timeout occured.
	 */
	KSI_NETWORK_SEND_TIMEOUT,
	/**
	 * A network recieve timeout occured.
	 */
	KSI_NETWORK_RECIEVE_TIMEOUT,
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
	KSI_VERIFICATION_FAILURE,
	/**
	 * Invalid publication.
	 */
	KSI_INVALID_PUBLICATION,
	/**
	 * The publications file is not signed.
	 */
	KSI_PUBLICATIONS_FILE_NOT_SIGNED_WITH_PKI,
	/**
	 * Cryptographic operation could not be performed. Likely causes are
	 * unsupported cryptographic algorithms, invalid keys and lack of
	 * resources.
	 */
	KSI_CRYPTO_FAILURE,
	
	/**
	 * HMAC mismatch occured
	 */
	KSI_HMAC_MISMATCH,

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
 * This function is used to call global init functions and to register the appropriate
 * global cleanup method. The init function will be called only once per KSI context and
 * the cleanup method will be called when #KSI_CTX_free is called on the context object.
 * The global init and cleanup functions must keep track how many times they are called
 * (if multiple calls cause issues) and allow multiple calls.
 *
 * \param[in] 	initFn		Global initiation function.
 * \param[in]	cleanupFn	Global cleanup function.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
int KSI_CTX_registerGlobals(KSI_CTX *ctx, int (*initFn)(void), void (*cleanupFn)(void));

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
int KSI_ERR_pre(KSI_ERR *err, int cond, char *fileName, int lineNr);

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
	/** The RIPEMD-256 algorithm. */
	KSI_HASHALG_RIPEMD_256 = 0x06,
	/** The SHA3-244 algorithm. */
	KSI_HASHALG_SHA3_244 = 0x07,
	/** The SHA3-256 algorithm. */
	KSI_HASHALG_SHA3_256 = 0x08,
	/** The SHA3-384 algorithm. */
	KSI_HASHALG_SHA3_384 = 0x09,
	/** The SHA3-512 algoritm */
	KSI_HASHALG_SHA3_512 = 0x0a,
	/** The SM3 algorithm.*/
	KSI_HASHALG_SM3 = 0x0b,

	/* Number of known hash algorithms. */
	KSI_NUMBER_OF_KNOWN_HASHALGS,
};

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
 * \param[in]		request				Request object.
 * \param[out]		handle				Pointer to the receiving pointer of the network handle.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_sendSignRequest(KSI_CTX *ctx, KSI_AggregationReq *request, KSI_RequestHandle **handle);

/**
 * Send a binary extend request using the specified KSI context.
 * \param[in]		ctx					KSI context object.
 * \param[in]		request				Request object.
 * \param[out]		handle				Pointer to the receiving pointer of the network handle.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_sendExtendRequest(KSI_CTX *ctx, KSI_ExtendReq *request, KSI_RequestHandle **handle);

/**
 * Send a binary request to download publications file using the specified KSI context.
 * \param[in]		ctx					KSI context object.
 * \param[in]		request				Pointer to the binary request.
 * \param[in]		request_length		Length of the binary request.
 * \param[out]		handle				Pointer to the receiving pointer of the network handle.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_sendPublicationRequest(KSI_CTX *ctx, const unsigned char *request, unsigned request_length, KSI_RequestHandle **handle);

/**
 * Accessor method for the publications file. It will download the publications file from
 * the uri specified by the KSI context.
 * \param[in]		ctx			KSI context.
 * \param[out]		pubFile		Pointer to the receiving pointer.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \note The publications file is not verified, use KSI_PublicationsFile_verify to do so.
 * \see #KSI_PublicationsFile_verify
 */
int KSI_receivePublicationsFile(KSI_CTX *ctx, KSI_PublicationsFile **pubFile);

/**
 * Verify the PKI signature of the publications file using the context.
 * \param[in]		ctx			KSI context.
 * \param[in]		pubFile		Publications file.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_verifyPublicationsFile(KSI_CTX *ctx, KSI_PublicationsFile *pubFile);

/**
 * Use the context to verify the signature.
 * \param[in]		ctx			KSI context.
 * \param[in]		sig			KSI signature.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_verifySignature(KSI_CTX *ctx, KSI_Signature *sig);

/**
 * Create a KSI signature from a given data hash.
 * \param[in]		ctx			KSI context.
 * \param[in]		dataHash	Data hash object from the document to be signed.
 * \param[out]		sig			Pointer to the receiving pointer to the KSI signature object.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_Signature_free, #KSI_extendSignature
 */
int KSI_createSignature(KSI_CTX *ctx, KSI_DataHash *dataHash, KSI_Signature **sig);

/**
 * Extend the signature to the earlyest available publication.
 * \param[in]		ctx			KSI context.
 * \param[in]		sig			Signature to be extended.
 * \param[out]		extended	Pointer to the receiving pointer to the extended signature.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_Signature_free, #KSI_createSignature
 */
int KSI_extendSignature(KSI_CTX *ctx, KSI_Signature *sig, KSI_Signature **extended);

/**
 * Setter for the internal log level.
 * \param[in]		ctx			KSI context.
 * \param[in]		level		Log level.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_LOG_LVL_en
 */
int KSI_CTX_setLogLevel(KSI_CTX *ctx, int level);

/**
 * Set the log output file.
 * \param[in]		ctx			KSI context.
 * \param[in]		fileName	Output file name.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \note When the fileName is set to \c NULL the log is sent to the standard output. To
 * turn the logger off use #KSI_setLogLevel with #KSI_LOG_NONE.
 */
int KSI_CTX_setLogFile(KSI_CTX *ctx, char *fileName);

int KSI_getPKITruststore(KSI_CTX *ctx, KSI_PKITruststore **pki);
int KSI_getNetworkProvider(KSI_CTX *ctx, KSI_NetworkClient **net);
int KSI_getLogger(KSI_CTX *ctx, KSI_Logger **logger);
int KSI_setPublicationsFile(KSI_CTX *ctx, KSI_PublicationsFile *var);
int KSI_getPublicationCertEmail(KSI_CTX *ctx, const char **address);

int KSI_setPKITruststore(KSI_CTX *ctx, KSI_PKITruststore *pki);
int KSI_setNetworkProvider(KSI_CTX *ctx, KSI_NetworkClient *net);
int KSI_setLogger(KSI_CTX *ctx, KSI_Logger *logger);
int KSI_getPublicationsFile(KSI_CTX *ctx, KSI_PublicationsFile **var);
int KSI_setPublicationCertEmail(KSI_CTX *ctx, const char *email);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif
