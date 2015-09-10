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

#ifndef _KSI_BASE_H_
#define _KSI_BASE_H_

#include <stdio.h>
#include <stdint.h>

#include "types.h"
#include "hash.h"
#include "publicationsfile.h"
#include "log.h"
#include "signature.h"
#include "verification.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup base KSI base functionality
 * @{
 */

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
	 * The given hash algorithm is considered as untrusted by
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
	 * IO error occurred.
	 */
	KSI_IO_ERROR = 0x201,
	/**
	 * A network error occurred.
	 */
	KSI_NETWORK_ERROR = 0x202,
	/**
	 * A network connection timeout occurred.
	 */
	KSI_NETWORK_CONNECTION_TIMEOUT = 0x203,
	/**
	 * A network send timeout occurred.
	 */
	KSI_NETWORK_SEND_TIMEOUT = 0x204,
	/**
	 * A network receive timeout occurred.
	 */
	KSI_NETWORK_RECIEVE_TIMEOUT = 0x205,
	/**
	 * A HTTP error occurred.
	 */
	KSI_HTTP_ERROR = 0x206,
	/**
	 * The extender returned a wrong calendar chain.
	 */
	KSI_EXTEND_WRONG_CAL_CHAIN = 0x207,
	/**
	 * No suitable publication to extend to.
	 */
	KSI_EXTEND_NO_SUITABLE_PUBLICATION = 0x208,
	/**
	 * The publication in the signature was not found in the publications file.
	 */
	KSI_VERIFICATION_FAILURE = 0x20a,
	/**
	 * Invalid publication.
	 */
	KSI_INVALID_PUBLICATION = 0x20b,
	/**
	 * The publications file is not signed.
	 */
	KSI_PUBLICATIONS_FILE_NOT_SIGNED_WITH_PKI = 0x20c,
	/**
	 * Cryptographic operation could not be performed. Likely causes are
	 * unsupported cryptographic algorithms, invalid keys and lack of
	 * resources.
	 */
	KSI_CRYPTO_FAILURE = 0x20d,

	/**
	 * HMAC mismatch occurred
	 */
	KSI_HMAC_MISMATCH = 0x20e,

	/* Generic service errors */

	/**
	 * Pattern for errors with client request.
	 */
	KSI_SERVICE_INVALID_REQUEST = 0x400,
	/**
	 * The request could not be authenticated (missing or unknown login identifier, MAC check failure, etc).
	 */
	KSI_SERVICE_AUTHENTICATION_FAILURE = 0x401,
	/**
	 * The request contained invalid payload (unknown payload type, missing mandatory elements, unknown critical elements, etc).
	 */
	KSI_SERVICE_INVALID_PAYLOAD = 0x402,
	/**
	 * The server encountered an unspecified internal error.
	 */
	KSI_SERVICE_INTERNAL_ERROR = 0x403,
	/**
	 * The server encountered unspecified critical errors connecting to upstream servers.
	 */
	KSI_SERVICE_UPSTREAM_ERROR = 0x404,
	/**
	 * No response from upstream aggregators.
	 */
	KSI_SERVICE_UPSTREAM_TIMEOUT = 0x405,
	/**
	 * The extender returned an error.
	 */
	KSI_SERVICE_UNKNOWN_ERROR = 0x406,

	/* Aggregator errors */

	/**
	 * The request indicated client-side aggregation tree larger than allowed for the client (retrying would not succeed either).
	 */
	KSI_SERVICE_AGGR_REQUEST_TOO_LARGE = 0x407,
	/**
	 * The request combined with other requests from the same client in the same round would create an aggregation sub-tree
	 * larger than allowed for the client (retrying in a later round could succeed).
	 */
	KSI_SERVICE_AGGR_REQUEST_OVER_QUOTA = 0x408,
	/**
	 * Too many requests from the client in the same round (retrying in a later round could succeed)
	 */
	KSI_SERVICE_AGGR_TOO_MANY_REQUESTS = 0x409,
	/**
	 * Input hash value in the client request is longer than the server allows.
	 */
	KSI_SERVICE_AGGR_INPUT_TOO_LONG = 0x40a,

	/* Extender status codes. */

	/**
	 * The request asked for a hash chain going backwards in time Pattern for local errors in the server.
	 */
	KSI_SERVICE_EXTENDER_INVALID_TIME_RANGE = 0x501,
	/**
	 * The server misses the internal database needed to service the request (most likely it has not been initialized yet).
	 */
	KSI_SERVICE_EXTENDER_DATABASE_MISSING = 0x502,
	/**
	 * The server's internal database is in an inconsistent state.
	 */
	KSI_SERVICE_EXTENDER_DATABASE_CORRUPT = 0x503,
	/**
	 * The request asked for hash values older than the oldest round in the server's database.
	 */
	KSI_SERVICE_EXTENDER_REQUEST_TIME_TOO_OLD = 0x504,
	/**
	 * The request asked for hash values newer than the newest round in the server's database.
	 */
	KSI_SERVICE_EXTENDER_REQUEST_TIME_TOO_NEW = 0x505,

	/**
	 * The request asked for hash values newer than the current real time.
	 */
	KSI_SERVICE_EXTENDER_REQUEST_TIME_IN_FUTURE = 0x506,

	/**
	 * The signature was not found in the multi signature container.
	 */
	KSI_MULTISIG_NOT_FOUND = 0x601,
	/**
	 * The multi signature container is in an invalid state.
	 */
	KSI_MULTISIG_INVALID_STATE = 0x602,

	/**
	 * Unknown error occurred.
	 */
	KSI_UNKNOWN_ERROR = 0xffff
};

/**
 * This function returns a pointer to a constant string describing the
 * version number of the package.
 * \return A constant pointer to a string.
 */
const char *KSI_getVersion(void);

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
 * \param[in]	ctx			KSI context.
 * \param[in] 	initFn		Global initiation function.
 * \param[in]	cleanupFn	Global cleanup function.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
int KSI_CTX_registerGlobals(KSI_CTX *ctx, int (*initFn)(void), void (*cleanupFn)(void));

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
 * Get base error message.
 * \param[in]		ctx		KSI context object.
 * \param[out]		buf		Buffer for storing error message.
 * \param[in]		len		The length of the buffer.
 * \param[out]		error	Pointer to buffer for base error code. Can be NULL.		
 * \param[out]		ext		Pointer to buffer for external component error code. Can be NULL.		
 * \return status code (#KSI_OK, when operation succeeded, otherwise an
 * error code).
 */
int KSI_ERR_getBaseErrorMessage(KSI_CTX *ctx, char *buf, size_t len, int *error, int *ext);

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
 * Free memory allocated by #KSI_malloc or #KSI_calloc.
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
int KSI_sendPublicationRequest(KSI_CTX *ctx, const unsigned char *request, size_t request_length, KSI_RequestHandle **handle);

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
 * Extend the signature to the earliest available publication.
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
 * \see #KSI_LOG_LVL_en, #KSI_CTX_setLoggerCallback.
 */
int KSI_CTX_setLogLevel(KSI_CTX *ctx, int level);

/**
 * This function sets the callback for logging for the context. For logging to streams
 * #KSI_LOG_StreamLogger can be used.
 * \param[in]	ctx		KSI context.
 * \param[in]	cb		Logger callback function.
 * \param[in]	logCtx	Pointer to logger context, may be \c NULL.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_LOG_StreamLogger, KSI_CTX_setLogLevel
 * \note The stream must be freed by the caller.
 */
int KSI_CTX_setLoggerCallback(KSI_CTX *ctx, KSI_LoggerCallback cb, void *logCtx);

/**
 * This function sets the callback which is executed on every requests header #KSI_Header
 * prior to serializing and submitting the request. The callback should be used when
 * additional data (i.e session id and message id) should be added to the header.
 * \param[in]	ctx		KSI context.
 * \param[in]	cb		Request header callback function.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_CTX_setRequestHeaderCallback(KSI_CTX *ctx, KSI_RequestHeaderCallback cb);

/**
 * Setter for publications file url.
 * \param[in]	ctx		KSI_context.
 * \param[in]	uri		URL to the publications file.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_CTX_setPublicationUrl(KSI_CTX *ctx, const char *uri);

/**
 * Configuration method for the extender.
 * \param[in]	ctx		KSI context.
 * \param[in]	uri		Extending service URI.
 * \param[in]	loginId The login id for the service.
 * \param[in]	key		Key for the loginId.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_CTX_setExtender(KSI_CTX *ctx, const char *uri, const char *loginId, const char *key);

/**
 * Configuration method for the aggregator.
 * \param[in]	ctx		KSI context.
 * \param[in]	uri		Aggregation service URI.
 * \param[in]	loginId The login id for the service.
 * \param[in]	key		Key for the loginId.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_CTX_setAggregator(KSI_CTX *ctx, const char *uri, const char *loginId, const char *key);

/**
 * Setter for transfer timeout.
 * \param[in]	ctx		KSI context.
 * \param[in]	timeout	Transfer timeout in seconds.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_CTX_setTransferTimeoutSeconds(KSI_CTX *ctx, int timeout);

/**
 * Setter for connection timeout.
 * \param[in]	ctx		KSI context.
 * \param[in]	timeout	Connection timeout in seconds.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_CTX_setConnectionTimeoutSeconds(KSI_CTX *ctx, int timeout);

/**
 * Setter function for the publications file.
 * \param[in]	ctx		KSI context.
 * \param[in]	var		Publications file.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_CTX_setPublicationsFile(KSI_CTX *ctx, KSI_PublicationsFile *var);

/**
 * Setter for the PKI truststore.
 * \param[in]	ctx		KSI context.
 * \param[in]	pki		PKI trust store.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_CTX_setPKITruststore(KSI_CTX *ctx, KSI_PKITruststore *pki);

/**
 * Setter for the network provider.
 * \param[in]	ctx		KSI context,.
 * \param[in]	net		Network provider.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_CTX_setNetworkProvider(KSI_CTX *ctx, KSI_NetworkClient *net);

/**
 * Setter for the e-mail address used to verify the PKI signature in the publications file.
 * \param[in]	ctx		KSI context.
 * \param[in]	email	Email address.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \note This method is deprecated and will be removed in later versions, use
 * #KSI_CTX_putPubFileCertConstraint with #KSI_CERT_EMAIL instead.
 */
KSI_FN_DEPRECATED(int KSI_CTX_setPublicationCertEmail(KSI_CTX *ctx, const char *email));

#define KSI_CERT_EMAIL "1.2.840.113549.1.9.1"
#define KSI_CERT_COMMON_NAME "2.5.4.3"
#define KSI_CERT_COUNTRY "2.5.4.6"
#define KSI_CERT_ORGANIZATION "2.5.4.10"

/**
 * This method specifies the default constraints for verifying the publications file PKI certificate.
 * The input consists of an array of OID and expected value pairs terminated by a pair of two NULLs. Except
 * in the last terminating NULL pair, the expected value may not be NULL - this will make the function
 * to return #KSI_INVALID_ARGUMENT.
 * \param[in]	ctx		KSI context.
 * \param[in]	arr		Array of OID and value pairs, terminated by a pair of NULLs.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \note The function does not take ownership of the input array and makes a copy of it, thus the
 * caller is responsible for freeing the memory which can be done right after a successful call
 * to this function.
 * \code{.c}
 * KSI_CertConstraint arr[] = {
 * 		{ KSI_CERT_EMAIL, "publications@guardtime.com"},
 * 		{ NULL, NULL }
 * };
 * res = KSI_CTX_setDefaultPubFileCertConstraints(ctx, arr);
 * \endcode
 */
int KSI_CTX_setDefaultPubFileCertConstraints(KSI_CTX *ctx, const KSI_CertConstraint *arr);

/**
 * Getter function for the PKI truststore object.
 * \param[in]	ctx		KSI context.
 * \param[out]	pki		Pointer to the receiving PKI trust store pointer.
  * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_CTX_getPKITruststore(KSI_CTX *ctx, KSI_PKITruststore **pki);

/**
 * Getter function for the publications file.
 * \param[in]	ctx		KSI context.
 * \param[out]	var		Pointer to the receiving pointer to publications file.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_CTX_getPublicationsFile(KSI_CTX *ctx, KSI_PublicationsFile **var);

/**
 * Getter function for the e-mail address used to verify the publications file PKI signature.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \param[in]	ctx		KSI context.
 * \param[out]	address	Pointer to the receiving pointer.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \note The user may not free the output pointer, as it belongs to the context.
 */
int KSI_CTX_getPublicationCertEmail(KSI_CTX *ctx, const char **address);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif
