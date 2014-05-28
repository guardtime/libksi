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

enum KSI_StatusCode {
/* RETURN CODES WHICH ARE NOT ERRORS */
	KSI_OK = 0,

/* SYNTAX ERRORS */
	/**
	 * Argument to function was invalid. Mostly this indicates \c NULL
	 * pointer.
	 */
	KSI_INVALID_ARGUMENT = 0x00000100,
	/**
	 * Either arguments to function or responses from the server had
	 * invalid format.
	 */
	KSI_INVALID_FORMAT,
	/**
	 * The given hash algorithm is considered untrustworthy by
	 * the verification policy.
	 */
	KSI_UNTRUSTED_HASH_ALGORITHM,
	KSI_UNAVAILABLE_HASH_ALGORITHM,
	/**
	 * Buffer too small to perform operation.
	 */
	KSI_BUFFER_OVERFLOW,
	/**
	 * TLV payload has wrong type for operation.
	 */
	KSI_TLV_PAYLOAD_TYPE_MISMATCH,

	/**
	 * The async operation has not finished.
	 */
	KSI_ASYNC_NOT_FINISHED,

	KSI_INVALID_SIGNATURE,
	KSI_INVALID_PKI_SIGNATURE,
	KSI_PKI_CERTIFICATE_NOT_TRUSTED,
/* SYSTEM ERRORS */
	KSI_OUT_OF_MEMORY = 0x00000300,
	KSI_IO_ERROR,
	KSI_NETWORK_ERROR,
	KSI_HTTP_ERROR,
	KSI_AGGREGATOR_ERROR,
	KSI_EXTENDER_ERROR,
	KSI_EXTEND_WRONG_CAL_CHAIN,
	KSI_EXTEND_NO_SUITABLE_PUBLICATION,
	KSI_VERIFY_PUBLICATION_NOT_FOUND,
	KSI_VERIFY_PUBLICATION_MISMATCH,
	KSI_INVALID_PUBLICATION,
	/**
	 * Cryptographic operation could not be performed. Likely causes are
	 * unsupported cryptographic algorithms, invalid keys and lack of
	 * resources.
	 */
	KSI_CRYPTO_FAILURE,


	KSI_UNKNOWN_ERROR
};

const char *KSI_getErrorString(int statusCode);

/**
 * Initialize KSI context #KSI_CTX
 */

int KSI_CTX_new(KSI_CTX **context);

/**
 * Free KSI context.
 */
void KSI_CTX_free(KSI_CTX *context);

/****************************
 *  ERROR HANDLING FUNCTIONS.
 ****************************/

/**
 * Returns the current status of the error container.
 * \param[in]	ctx		KSI context.
 *
 * \return The current status code of the KSI context. If #ctx is NULL a
 * #KSI_INVALID_ARGUMENT is returned.
 */
int KSI_CTX_getStatus(KSI_CTX *ctx);

/**
 * Finalizes the current error stack.
 */
int KSI_ERR_apply(KSI_ERR *err);

/**
 * Dump error stack trace to stream
 */
int KSI_ERR_statusDump(KSI_CTX *ctx, FILE *f);

/**
 * Set log file.
 *
 * \note this method will append to the file if it exists.
 */
int KSI_LOG_init(KSI_CTX *ctx, char *fileName, int logLevel);

/**
 * Change the log level.
 */
int KSI_LOG_setLevel(int logLevel);

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

int KSI_global_init(void);

void KSI_global_cleanup(void);

int KSI_CTX_setNetworkProvider(KSI_CTX *ctx, KSI_NetProvider *netProvider);

void *KSI_malloc(size_t size);
void *KSI_calloc(size_t num, size_t size);
void *KSI_realloc(void *ptr, size_t size);
void KSI_free(void *ptr);

/**
 *
 */
int KSI_sendSignRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle);
/**
 *
 */
int KSI_sendExtendRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle);

/**
 *
 */
int KSI_sendPublicationRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle);


int KSI_PublicationData_fromBase32(KSI_CTX *ctx,	const char *publication, int publication_length, KSI_PublicationData **published_data);
int KSI_PublicationData_toBase32(const KSI_PublicationData *published_data, char **publication);

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

#ifdef __cplusplus
}
#endif

#endif
