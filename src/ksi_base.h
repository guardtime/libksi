#ifndef _KSI_BASE_H_
#define _KSI_BASE_H_

#include <stdio.h>

/* Returns true if context has no errors. */
#define KSI_CTX_OK(ctx) ((ctx) != NULL && (ctx)->statusCode == KSI_OK && (ctx)->errors_count == 0)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct KSI_CTX_st KSI_CTX;
typedef struct KSI_ERR_st KSI_ERR;
typedef struct KSI_TLV_st KSI_TLV;

/* KSI reader type. */
typedef struct KSI_RDR_st KSI_RDR;

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
	 * Either arguments to function or responses from timestamping server had
	 * invalid format.
	 */
	KSI_INVALID_FORMAT,
	/**
	 * The given hash algorithm is considered untrustworthy by
	 * the verification policy.
	 */
	KSI_UNTRUSTED_HASH_ALGORITHM,
	/**
	 * Buffer too small to perform operation.
	 */
	KSI_BUFFER_OVERFLOW,
	/**
	 * TLV payload has wrong type for operation.
	 */
	KSI_TLV_PAYLOAD_TYPE_MISMATCH,

/* SYSTEM ERRORS */
	KSI_OUT_OF_MEMORY = 0x00000300,
	KSI_IO_ERROR,
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
 * Get the last status set.
 */
int KSI_ERR_getStatus(KSI_CTX *ctx);

/**
 * Dump error stack trace to stream
 */
int KSI_CTX_statusDump(KSI_CTX *ctx, FILE *f);

/****************
 * LOG FUNCTIONS.
 ****************/

// TODO!

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

/***********
 *
 * DATA HASH
 *
 ***********/

/**
 * \ingroup common
 *
 * The Guardtime representation of hash algorithms, necessary to calculate
 * instances of #KSI_DataHash.
 *
 * The currently supported algorithms are:
 * <table>
 * <tr><th>Name</th><th>OID</th><th>GT ID</th><th>digest size (bytes)</th></tr>
 * <tr><td>SHA1</td><td>1.3.14.3.2.26</td><td>0</td><td>20</td></tr>
 * <tr><td>SHA224</td><td>2.16.840.1.101.3.4.2.4</td><td>3</td><td>28</td></tr>
 * <tr><td>SHA256</td><td>2.16.840.1.101.3.4.2.1</td><td>1</td><td>32</td></tr>
 * <tr><td>SHA384</td><td>2.16.840.1.101.3.4.2.2</td><td>4</td><td>48</td></tr>
 * <tr><td>SHA512</td><td>2.16.840.1.101.3.4.2.3</td><td>5</td><td>64</td></tr>
 * <tr><td>RIPEMD160</td><td>1.3.36.3.2.1</td><td>2</td><td>20</td></tr>
 * </table>
 *
 * Names are as in the ASN.1 OID registry as defined in ITU-T Rec. X.660 / ISO/IEC 9834 series.
 */
enum KSI_HashAlgorithm {
	/** The SHA-1 algorithm. */
	KSI_HASHALG_SHA1 = 0,
	/** The SHA-256 algorithm. */
	KSI_HASHALG_SHA256,
	/** The RIPEMD-160 algorithm. */
	KSI_HASHALG_RIPEMD160,
	/** The SHA-224 algorithm. */
	KSI_HASHALG_SHA224,
	/** The SHA-384 algorithm. */
	KSI_HASHALG_SHA384,
	/** The SHA-512 algorithm. */
	KSI_HASHALG_SHA512,
	/** Use default algorithm. */
	KSI_HASHALG_DEFAULT = -1
};

#ifdef __cplusplus
}
#endif

#endif
