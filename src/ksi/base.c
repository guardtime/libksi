#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "internal.h"
#include "net_http.h"

#define KSI_ERR_STACK_LEN 16

typedef void (*GlobalCleanupFn)(void);
typedef int (*GlobalInitFn)(void);

KSI_DEFINE_LIST(GlobalCleanupFn)

struct KSI_CTX_st {

	/******************
	 *  ERROR HANDLING.
	 ******************/

	/* Status code of the last executed function. */
	int statusCode;

	/* Array of errors. */
	KSI_ERR *errors;

	/* Length of error array. */
	unsigned int errors_size;

	/* Count of errors (usually #error_end - #error_start + 1, unless error count > #errors_size. */
	unsigned int errors_count;

	KSI_Logger *logger;

	/************
	 * TRANSPORT.
	 ************/

	KSI_NetworkClient *netProvider;

	KSI_PKITruststore *pkiTruststore;

	KSI_PublicationsFile *publicationsFile;

	char *publicationCertEmail;

	KSI_List *cleanupFnList;

};

KSI_IMPLEMENT_LIST(GlobalCleanupFn, NULL);


const char *KSI_getErrorString(int statusCode) {
	switch (statusCode) {
		case KSI_OK:
			return "No errors";
		case KSI_INVALID_ARGUMENT:
			return "Invalid argument";
		case KSI_INVALID_FORMAT:
			return "Invalid format";
		case KSI_UNTRUSTED_HASH_ALGORITHM:
			return "The hash algorithm is not trusted";
		case KSI_UNAVAILABLE_HASH_ALGORITHM:
			return "The hash algorith is not implemented or unavailable";
		case KSI_BUFFER_OVERFLOW:
			return "Buffer overflow";
		case KSI_TLV_PAYLOAD_TYPE_MISMATCH:
			return "TLV payload type mismatch";
		case KSI_ASYNC_NOT_FINISHED:
			return "Asynchronous call not yet finished.";
		case KSI_INVALID_SIGNATURE:
			return "Invalid KSI signature.";
		case KSI_INVALID_PKI_SIGNATURE:
			return "Invalid PKI signature.";
		case KSI_PKI_CERTIFICATE_NOT_TRUSTED:
			return "The PKI certificate is not trusted.";
		case KSI_OUT_OF_MEMORY:
			return "Out of memory";
		case KSI_IO_ERROR:
			return "I/O error";
		case KSI_NETWORK_ERROR:
			return "Network error";
		case KSI_NETWORK_CONNECTION_TIMEOUT:
			return "Network connection timeout";
		case KSI_NETWORK_SEND_TIMEOUT:
			return "Network send timeout";
		case KSI_NETWORK_RECIEVE_TIMEOUT:
			return "Network recieve timeout";
		case KSI_HTTP_ERROR:
			return "HTTP error";
		case KSI_AGGREGATOR_ERROR:
			return "Failure from aggregator.";
		case KSI_EXTENDER_ERROR:
			return "Failure from extender.";
		case KSI_EXTEND_WRONG_CAL_CHAIN:
			return "The given calendar chain is not a continuation of the signature calendar chain.";
		case KSI_EXTEND_NO_SUITABLE_PUBLICATION:
			return "There is no suitable publication yet.";
		case KSI_VERIFICATION_FAILURE:
			return "Verification failed.";
		case KSI_INVALID_PUBLICATION:
			return "Invalid publication";
		case KSI_PUBLICATIONS_FILE_NOT_SIGNED_WITH_PKI:
			return "The publications file is not signed.";
		case KSI_CRYPTO_FAILURE:
			return "Cryptographic failure";
		case KSI_UNKNOWN_ERROR:
			return "Unknown internal error";
		default:
			return "Unknown status code";
	}
}

int KSI_CTX_new(KSI_CTX **context) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *ctx = NULL;
	KSI_NetworkClient *netProvider = NULL;
	KSI_PKITruststore *pkiTruststore = NULL;
	KSI_Logger *logger = NULL;

	ctx = KSI_new(KSI_CTX);
	if (ctx == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	/* Init error stack */
	ctx->errors_size = KSI_ERR_STACK_LEN;
	ctx->errors = KSI_malloc(sizeof(KSI_ERR) * ctx->errors_size);
	if (ctx->errors == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	ctx->errors_count = 0;
	ctx->publicationsFile = NULL;
	ctx->pkiTruststore = NULL;
	ctx->netProvider = NULL;
	ctx->logger = NULL;
	ctx->publicationCertEmail = NULL;


	KSI_ERR_clearErrors(ctx);

	/* Create global cleanup list as the first thing. */
	res = KSI_List_new(NULL, &ctx->cleanupFnList);
	if (res != KSI_OK) goto cleanup;

	/* Create and set the logger. */
	res = KSI_Logger_new(ctx, NULL, KSI_LOG_FATAL, &logger);
	if (res != KSI_OK) goto cleanup;

	res = KSI_setLogger(ctx, logger);
	if (res != KSI_OK) goto cleanup;

	/* Initialize curl as the net handle. */
	res = KSI_HttpClient_new(ctx, &netProvider);
	if (res != KSI_OK) goto cleanup;

	res = KSI_setNetworkProvider(ctx, netProvider);
	if (res != KSI_OK) goto cleanup;
	netProvider = NULL;

	/* Create and set the PKI truststore */
	res = KSI_PKITruststore_new(ctx, 1, &pkiTruststore);
	if (res != KSI_OK) goto cleanup;
	res = KSI_setPKITruststore(ctx, pkiTruststore);
	if (res != KSI_OK) goto cleanup;
	pkiTruststore = NULL;

	res = KSI_setPublicationCertEmail(ctx, "publications@guardtime.com");
	if (res != KSI_OK) goto cleanup;

	/* Return the context. */
	*context = ctx;
	ctx = NULL;

	res = KSI_OK;

cleanup:

	KSI_NetworkClient_free(netProvider);
	KSI_PKITruststore_free(pkiTruststore);

	KSI_CTX_free(ctx);

	return res;
}

int KSI_CTX_registerGlobals(KSI_CTX *ctx, int (*initFn)(void), void (*cleanupFn)(void)) {
	int res = KSI_UNKNOWN_ERROR;
	size_t *pos = NULL;

	if (ctx == NULL || initFn == NULL || cleanupFn == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_List_indexOf(ctx->cleanupFnList, (void *)cleanupFn, &pos);
	if (res != KSI_OK) goto cleanup;

	/* Only run the init function if the cleanup function is not found. */
	if (pos == NULL) {
		res = initFn();
		if (res != KSI_OK) goto cleanup;

		res = KSI_List_append(ctx->cleanupFnList, (void *)cleanupFn);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_free(pos);

	return res;
}

static void globalCleanup(KSI_CTX *ctx) {
	int res;
	size_t pos;
	void (*fn)(void);

	for (pos = 0; pos < KSI_List_length(ctx->cleanupFnList); pos++) {
		res = KSI_List_elementAt(ctx->cleanupFnList, pos, (void **)&fn);
		if (res != KSI_OK) {
			KSI_LOG_error(ctx, "Unable to retreive cleanupfunction.");
			break;
		}

		if (fn == NULL) {
			KSI_LOG_error(ctx, "Got NULL as global cleanup method.");
			break;
		}

		fn();
	}
}

/**
 *
 */
void KSI_CTX_free(KSI_CTX *ctx) {
	size_t pos;
	if (ctx != NULL) {
		/* Call cleanup methods. */
		globalCleanup(ctx);

		KSI_List_free(ctx->cleanupFnList);

		KSI_free(ctx->errors);

		KSI_Logger_free(ctx->logger);

		KSI_NetworkClient_free(ctx->netProvider);
		KSI_PKITruststore_free(ctx->pkiTruststore);

		KSI_PublicationsFile_free(ctx->publicationsFile);
		KSI_free(ctx->publicationCertEmail);

		KSI_free(ctx);
	}
}

int KSI_sendSignRequest(KSI_CTX *ctx, KSI_AggregationReq *request, KSI_RequestHandle **handle) {
	KSI_ERR err;
	KSI_RequestHandle *tmp = NULL;
	int res;
	KSI_NetworkClient *netProvider = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, request != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	netProvider = ctx->netProvider;

	res = KSI_NetworkClient_sendSignRequest(netProvider, request, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RequestHandle_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_sendExtendRequest(KSI_CTX *ctx, KSI_ExtendReq *request, KSI_RequestHandle **handle) {
	KSI_ERR err;
	KSI_RequestHandle *tmp = NULL;
	int res;
	KSI_NetworkClient *netProvider = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, request != NULL) goto cleanup;
	KSI_PRE(&err, handle != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	netProvider = ctx->netProvider;

	res = KSI_NetworkClient_sendExtendRequest(netProvider, request, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RequestHandle_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_sendPublicationRequest(KSI_CTX *ctx, const unsigned char *request, unsigned request_length, KSI_RequestHandle **handle) {
	KSI_ERR err;
	KSI_RequestHandle *hndl = NULL;
	int res;
	KSI_NetworkClient *netProvider = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	netProvider = ctx->netProvider;

	res = KSI_RequestHandle_new(ctx, request, request_length, &hndl);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetworkClient_sendPublicationsFileRequest(netProvider, hndl);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = hndl;
	hndl = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RequestHandle_free(hndl);

	return KSI_RETURN(&err);

}

int KSI_receivePublicationsFile(KSI_CTX *ctx, KSI_PublicationsFile **pubFile) {
	KSI_ERR err;
	int res;
	KSI_RequestHandle *handle = NULL;
	unsigned char *raw = NULL;
	unsigned raw_len = 0;
	KSI_PublicationsFile *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, pubFile != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);


	/* TODO! Implement mechanism for reloading (e.g cache timeout) */
	if (ctx->publicationsFile == NULL) {
		KSI_LOG_debug(ctx, "Receiving publications file.");

		res = KSI_sendPublicationRequest(ctx, NULL, 0, &handle);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_RequestHandle_getResponse(handle, &raw, &raw_len);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_PublicationsFile_parse(ctx, raw, raw_len, &tmp);
		KSI_CATCH(&err, res) goto cleanup;

		ctx->publicationsFile = tmp;
		tmp = NULL;

		KSI_LOG_debug(ctx, "Publications file received.");
	}

	*pubFile = ctx->publicationsFile;

	KSI_SUCCESS(&err);

cleanup:

	KSI_RequestHandle_free(handle);
	KSI_PublicationsFile_free(tmp);

	return KSI_RETURN(&err);

}

int KSI_verifyPublicationsFile(KSI_CTX *ctx, KSI_PublicationsFile *pubFile) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, pubFile != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_PublicationsFile_verify(pubFile, ctx);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_verifySignature(KSI_CTX *ctx, KSI_Signature *sig) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_Signature_verify(sig, ctx);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_createSignature(KSI_CTX *ctx, const KSI_DataHash *dataHash, KSI_Signature **sig) {
	KSI_ERR err;
	int res;
	KSI_Signature *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, dataHash != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_Signature_create(ctx, dataHash, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*sig = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_extendSignature(KSI_CTX *ctx, KSI_Signature *sig, KSI_Signature **extended) {
	KSI_ERR err;
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_Integer *signingTime = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Signature *extSig = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_receivePublicationsFile(ctx, &pubFile);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_Signature_getSigningTime(sig, &signingTime);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PublicationsFile_getNearestPublication(pubFile, signingTime, &pubRec);
	KSI_CATCH(&err, res) goto cleanup;

	if (pubRec == NULL) {
		KSI_FAIL(&err, KSI_EXTEND_NO_SUITABLE_PUBLICATION, NULL);
		goto cleanup;
	}

	res = KSI_Signature_extend(sig, ctx, pubRec, &extSig);
	KSI_CATCH(&err, res) goto cleanup;

	*extended = extSig;
	extSig = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Signature_free(extSig);
	return KSI_RETURN(&err);
}

int KSI_extendSignatureToPublication(KSI_CTX *ctx, KSI_Signature *sig, char *pubString, KSI_Signature **extended) {
	KSI_ERR err;
	int res;
	KSI_PublicationsFile *pubFile = NULL;
	KSI_Integer *signingTime = NULL;
	KSI_PublicationRecord *pubRec = NULL;
	KSI_Signature *extSig = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_PRE(&err, pubString != NULL) goto cleanup;
	KSI_PRE(&err, extended != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_receivePublicationsFile(ctx, &pubFile);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_Signature_getSigningTime(sig, &signingTime);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PublicationsFile_getNearestPublication(pubFile, signingTime, &pubRec);
	KSI_CATCH(&err, res) goto cleanup;

	if (pubRec == NULL) {
		KSI_FAIL(&err, KSI_EXTEND_NO_SUITABLE_PUBLICATION, NULL);
		goto cleanup;
	}

	res = KSI_Signature_extend(sig, ctx, pubRec, &extSig);
	KSI_CATCH(&err, res) goto cleanup;

	*extended = extSig;
	extSig = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Signature_free(extSig);
	return KSI_RETURN(&err);
}

int KSI_CTX_setLogLevel(KSI_CTX *ctx, int level) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_LOG_setLogLevel(ctx->logger, level);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_CTX_setLogFile(KSI_CTX *ctx, char *fileName) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_LOG_setLogFile(ctx->logger, fileName);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}


int KSI_ERR_init(KSI_CTX *ctx, KSI_ERR *err) {
	err->ctx = ctx;

	KSI_ERR_fail(err, KSI_UNKNOWN_ERROR, 0, "null", 0, "Internal error: Probably a function returned without a distinctive success or error.");

	return KSI_OK;
}

int KSI_ERR_apply(KSI_ERR *err) {
	KSI_CTX *ctx = err->ctx;
	KSI_ERR *ctxErr = NULL;

	if (ctx != NULL) {
		if (err->statusCode != KSI_OK) {
			ctxErr = ctx->errors + (ctx->errors_count % ctx->errors_size);

			ctxErr->statusCode = err->statusCode;
			ctxErr->extErrorCode = err->extErrorCode;
			ctxErr->lineNr = err->lineNr;
			strncpy(ctxErr->fileName, KSI_strnvl(err->fileName), sizeof(err->fileName));
			strncpy(ctxErr->message, KSI_strnvl(err->message), sizeof(err->message));

			ctx->errors_count++;
		}

		ctx->statusCode = err->statusCode;
	}
	/* Return the result, which does not indicate the result of this method. */
	return err->statusCode;
}

void KSI_ERR_success(KSI_ERR *err) {
	err->statusCode = KSI_OK;
	*err->message = '\0';
}

int KSI_ERR_pre(KSI_ERR *err, int cond, char *fileName, int lineNr) {
	if (!cond) {
		KSI_ERR_init(NULL, err);
		KSI_ERR_fail(err, KSI_INVALID_ARGUMENT, 0, fileName, lineNr, NULL);
	}

	return !cond;
}

int KSI_ERR_fail(KSI_ERR *err, int statusCode, long extErrorCode, char *fileName, unsigned int lineNr, const char *message) {
	err->extErrorCode = extErrorCode;
	err->statusCode = statusCode;
	if (message == NULL) {
		strncpy(err->message, KSI_getErrorString(statusCode), sizeof(err->message));
	} else {
		strncpy(err->message, KSI_strnvl(message), sizeof(err->message));
	}
	strncpy(err->fileName, KSI_strnvl(fileName), sizeof(err->fileName));
	err->lineNr = lineNr;

	return KSI_OK;
}

void KSI_ERR_clearErrors(KSI_CTX *ctx) {
	if (ctx != NULL) {
		ctx->statusCode = KSI_UNKNOWN_ERROR;
		ctx->errors_count = 0;
	}
}

int KSI_ERR_statusDump(KSI_CTX *ctx, FILE *f) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ERR *err = NULL;
	unsigned int i;

	fprintf(f, "KSI error trace:\n");
	if (ctx->errors_count == 0) {
		printf("  No errors.\n");
		goto cleanup;
	}

	/* List all errors, starting from the most general. */
	for (i = 0; i < ctx->errors_count && i < ctx->errors_size; i++) {
		err = ctx->errors + ((ctx->errors_count - i - 1) % ctx->errors_size);
		fprintf(f, "  %3u) %s:%u - (%d/%ld) %s\n", ctx->errors_count - i, err->fileName, err->lineNr,err->statusCode, err->extErrorCode, err->message);
	}

	/* If there where more errors than buffers for the errors, indicate the fact */
	if (ctx->errors_count > ctx->errors_size) {
		fprintf(f, "  ... (more errors)\n");
	}

	res = KSI_OK;

cleanup:

	return res;
}

void *KSI_malloc(size_t size) {
	return malloc(size);
}

void *KSI_calloc(size_t num, size_t size) {
	return calloc(num, size);
}

void *KSI_realloc(void *ptr, size_t size) {
	return realloc(ptr, size);
}

void KSI_free(void *ptr) {
	free(ptr);
}

/**
 *
 */
int KSI_CTX_getStatus(KSI_CTX *ctx) {
	/* Will fail with segfault if context is null. */
	return ctx == NULL ? KSI_INVALID_ARGUMENT : ctx->statusCode;
}


#define CTX_VALUEP_SETTER(var, nam, typ, fre)												\
int KSI_set##nam(KSI_CTX *ctx, typ *var) { 													\
	int res = KSI_UNKNOWN_ERROR;															\
	if (ctx == NULL) {																		\
		res = KSI_INVALID_ARGUMENT;															\
		goto cleanup;																		\
	}																						\
	if (ctx->var != NULL) {																	\
		fre(ctx->var);																		\
	}																						\
	ctx->var = var;																			\
	res = KSI_OK;																			\
cleanup:																					\
	return res;																				\
} 																							\

#define CTX_VALUEP_GETTER(var, nam, typ) 													\
int KSI_get##nam(KSI_CTX *ctx, typ **var) { 												\
	int res = KSI_UNKNOWN_ERROR;															\
	if (ctx == NULL || var == NULL) {														\
		res = KSI_INVALID_ARGUMENT;															\
		goto cleanup;																		\
	}																						\
	*var = ctx->var;																		\
	res = KSI_OK;																			\
cleanup:																					\
	return res;																				\
} 																							\

#define CTX_GET_SET_VALUE(var, nam, typ, fre) 												\
	CTX_VALUEP_SETTER(var, nam, typ, fre)													\
	CTX_VALUEP_GETTER(var, nam, typ)														\

CTX_GET_SET_VALUE(pkiTruststore, PKITruststore, KSI_PKITruststore, KSI_PKITruststore_free)
CTX_GET_SET_VALUE(netProvider, NetworkProvider, KSI_NetworkClient, KSI_NetworkClient_free)
CTX_GET_SET_VALUE(logger, Logger, KSI_Logger, KSI_Logger_free)
CTX_GET_SET_VALUE(publicationsFile, PublicationsFile, KSI_PublicationsFile, KSI_PublicationsFile_free)

int KSI_setPublicationCertEmail(KSI_CTX *ctx, const char *email) {
	int res = KSI_UNKNOWN_ERROR;
	char *tmp = NULL;
	if (ctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (email != NULL && email[0] != '\0') {
		size_t len = strlen(email);
		tmp = KSI_calloc(len + 1, 1);
		if (tmp == NULL) {
			res = KSI_OUT_OF_MEMORY;
			goto cleanup;
		}

		memcpy(tmp, email, len + 1);
	}

	ctx->publicationCertEmail = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:
	KSI_free(tmp);
	return res;
}
CTX_VALUEP_GETTER(publicationCertEmail, PublicationCertEmail, const char)
