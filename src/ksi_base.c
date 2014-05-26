#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "ksi_internal.h"

#define KSI_ERR_STACK_LEN 16

KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord)

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
		case KSI_OUT_OF_MEMORY:
			return "Out of memory";
		case KSI_IO_ERROR:
			return "I/O error";
		case KSI_NETWORK_ERROR:
			return "Network error";
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
		case KSI_VERIFY_PUBLICATION_NOT_FOUND:
			return "Unknown publication";
		case KSI_CRYPTO_FAILURE:
			return "Cryptographic failure";
		case KSI_PKI_CERTIFICATE_NOT_TRUSTED:
			return "PKI Certificate not trusted.";
		case KSI_UNKNOWN_ERROR:
			return "Unknown internal error";
		default:
			return "Unknown status code";
	}
}

int KSI_CTX_new(KSI_CTX **context) {
	int res = KSI_UNKNOWN_ERROR;

	KSI_CTX *ctx = NULL;
	KSI_NetProvider *netProvider = NULL;
	KSI_PKITruststore *pkiTruststore = NULL;

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

	KSI_ERR_clearErrors(ctx);
	KSI_LOG_init(ctx, NULL, KSI_LOG_DEBUG);

	/* Initialize curl as the net handle. */
	res = KSI_CurlNetProvider_new(ctx, &netProvider);
	if (res != KSI_OK) goto cleanup;

	/* Configure curl net provider */
	if ((res = KSI_CurlNetProvider_setSignerUrl(netProvider,"192.168.1.29:1234"/* "192.168.1.36:3333"*/)) != KSI_OK) goto cleanup;
	if ((res = KSI_CurlNetProvider_setExtenderUrl(netProvider, "192.168.1.36:8010/gt-extendingservice")) != KSI_OK) goto cleanup;
	if ((res = KSI_CurlNetProvider_setPublicationUrl(netProvider, "file:///root/dev/ksi-c-api/test/resource/tlv/publications-4.tlv")) != KSI_OK) goto cleanup;
	if ((res = KSI_CurlNetProvider_setConnectTimeoutSeconds(netProvider, 5)) != KSI_OK) goto cleanup;
	if ((res = KSI_CurlNetProvider_setReadTimeoutSeconds(netProvider, 5)) != KSI_OK) goto cleanup;

	res = KSI_CTX_setNetworkProvider(ctx, netProvider);
	if (res != KSI_OK) goto cleanup;
	netProvider = NULL;

	/* Create and set the PKI truststore */
	res = KSI_PKITruststore_new(ctx, 1, &pkiTruststore);
	if (res != KSI_OK) goto cleanup;

	res = KSI_CTX_setPKITruststore(ctx, pkiTruststore);
	if (res != KSI_OK) goto cleanup;
	pkiTruststore = NULL;

	/* Return the context. */
	*context = ctx;
	ctx = NULL;

	res = KSI_OK;

cleanup:

	KSI_NetProvider_free(netProvider);
	KSI_PKITruststore_free(pkiTruststore);

	KSI_CTX_free(ctx);

	return res;
}

/**
 *
 */
void KSI_CTX_free(KSI_CTX *context) {
	if (context != NULL) {
		KSI_free(context->errors);

		if (context->logStream) fclose(context->logStream);
		KSI_free(context->logFile);

		KSI_NetProvider_free(context->netProvider);
		KSI_PKITruststore_free(context->pkiTruststore);

		KSI_PublicationsFile_free(context->publicationsFile);

		KSI_free(context);
	}
}

/**
 *
 */
int KSI_global_init(void) {
	int res = KSI_UNKNOWN_ERROR;

	res = KSI_CurlNetProvider_global_init();
	if (res != KSI_OK) goto cleanup;

	res = KSI_PKITruststore_global_init();
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

/**
 *
 */
void KSI_global_cleanup(void) {
	KSI_CurlNetProvider_global_cleanup();
}

int KSI_sendSignRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle) {
	KSI_ERR err;
	KSI_NetHandle *hndl = NULL;
	int res;
	KSI_NetProvider *netProvider = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, request != NULL) goto cleanup;
	KSI_PRE(&err, request_length > 0) goto cleanup;

	KSI_BEGIN(ctx, &err);

	netProvider = ctx->netProvider;

	res = KSI_NetHandle_new(ctx, request, request_length, &hndl);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_sendSignRequest(netProvider, hndl);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = hndl;
	hndl = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetHandle_free(hndl);

	return KSI_RETURN(&err);
}

int KSI_sendExtendRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle) {
	KSI_ERR err;
	KSI_NetHandle *hndl = NULL;
	int res;
	KSI_NetProvider *netProvider = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, request != NULL) goto cleanup;
	KSI_PRE(&err, request_length > 0) goto cleanup;

	KSI_BEGIN(ctx, &err);

	netProvider = ctx->netProvider;

	res = KSI_NetHandle_new(ctx, request, request_length, &hndl);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_sendExtendRequest(netProvider, hndl);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = hndl;
	hndl = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetHandle_free(hndl);

	return KSI_RETURN(&err);
}

static int setValue(KSI_CTX *ctx, const char *variableName, void **target, void *value, void (*valueFree)(void *)) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, target != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	KSI_LOG_debug(ctx, "Setting variable %s to point to 0x%xll", variableName, (unsigned long long)value);

	if (valueFree != NULL && *target != NULL) {
		valueFree(*target);
	}

	*target = value;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

static int getValue(KSI_CTX *ctx, const char *variableName, int offset, void **value) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, offset >= 0) goto cleanup;
	KSI_PRE(&err, value != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	KSI_LOG_debug(ctx, "KSI_CTX_set%s(ctx, 0x%llx) -> %d", variableName, (unsigned long long)value, offset);

	*value = ((unsigned char *)ctx) + offset;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_base32ToPublishedData(KSI_CTX *ctx,	const char *publication, int publication_length, KSI_PublicationData **published_data) {
	KSI_ERR err;
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *binary_publication = NULL;
	size_t binary_publication_length;
	KSI_PublicationData *tmp_published_data = NULL;
	int i;
	unsigned long tmp_ulong;
	KSI_uint64_t tmp_uint64;
	int hash_alg;
	size_t hash_size;
	KSI_DataHash *pubHash = NULL;
	KSI_Integer *pubTime;

	KSI_PRE(&err, publication != NULL) goto cleanup;
	KSI_PRE(&err, published_data != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (publication_length < 0) {
		publication_length = strlen(publication);
	}

	res = KSI_base32Decode(publication, publication_length, &binary_publication, &binary_publication_length);
	KSI_CATCH(&err, res) goto cleanup;

	if (binary_publication_length < 13) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	tmp_ulong = 0;
	for (i = 0; i < 4; ++i) {
		tmp_ulong <<= 8;
		tmp_ulong |= binary_publication[binary_publication_length - 4 + i];
	}

	if (KSI_crc32(binary_publication, binary_publication_length - 4, 0) !=
			tmp_ulong) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_PublicationData_new(ctx, &tmp_published_data);
	KSI_CATCH(&err, res) goto cleanup;

	tmp_uint64 = 0;
	for (i = 0; i < 8; ++i) {
		tmp_uint64 <<= 8;
		tmp_uint64 |= binary_publication[i];
	}

	res = KSI_Integer_new(ctx, tmp_uint64, &pubTime);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PublicationData_setTime(tmp_published_data, pubTime);
	KSI_CATCH(&err, res) goto cleanup;
	pubTime = NULL;


	hash_alg = binary_publication[8];
	if (!KSI_isSupportedHashAlgorithm(hash_alg)) {
		KSI_FAIL(&err, KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	hash_size = KSI_getHashLength(hash_alg);
	if (binary_publication_length != 8 + 1 + hash_size + 4) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_fromImprint(ctx, binary_publication + 8, hash_size + 1, &pubHash);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PublicationData_setImprint(tmp_published_data, pubHash);
	KSI_CATCH(&err, res) goto cleanup;
	pubHash = NULL;

	*published_data = tmp_published_data;
	tmp_published_data = NULL;

	res = KSI_OK;

cleanup:
	KSI_Integer_free(pubTime);
	KSI_DataHash_free(pubHash);
	KSI_free(binary_publication);
	KSI_PublicationData_free(tmp_published_data);

	return res;
}

int KSI_publishedDataToBase32(const KSI_PublicationData *published_data, char **publication) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_Integer *publicationTime = NULL;
	const unsigned char *imprint = NULL;
	int imprint_len = 0;
	int res;
	KSI_uint64_t publication_identifier = 0;
	unsigned char *binary_publication = NULL;
	size_t binary_publication_length;
	int i;
	unsigned long tmp_ulong;
	char *tmp_publication = NULL;

	KSI_PRE(&err, published_data != NULL) goto cleanup;
	ctx = KSI_PublicationData_getCtx((KSI_PublicationData *)published_data);

	KSI_BEGIN(ctx, &err);

	res = KSI_PublicationData_getImprint(published_data, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_len);
	KSI_CATCH(&err, res) goto cleanup;

	binary_publication_length =	8 + imprint_len + 4;
	binary_publication = KSI_calloc(binary_publication_length, 1);
	if (binary_publication == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = KSI_PublicationData_getTime(published_data, &publicationTime);
	KSI_CATCH(&err, res) goto cleanup;

	for (i = 7; i >= 0; --i) {
		binary_publication[i] = (unsigned char) (publication_identifier & 0xff);
		publication_identifier >>= 8;
	}

	memcpy(binary_publication + 8, imprint, imprint_len);

	tmp_ulong = KSI_crc32(binary_publication, binary_publication_length - 4, 0);
	for (i = 3; i >= 0; --i) {
		binary_publication[binary_publication_length - 4 + i] =
			(unsigned char) (tmp_ulong & 0xff);
		tmp_ulong >>= 8;
	}

	res = KSI_base32Encode(binary_publication, binary_publication_length, 6, &tmp_publication);
	KSI_CATCH(&err, res) goto cleanup;

	*publication = tmp_publication;
	tmp_publication = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(binary_publication);
	KSI_free(tmp_publication);

	return KSI_RETURN(&err);
}

int KSI_sendPublicationRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle) {
	KSI_ERR err;
	KSI_NetHandle *hndl = NULL;
	int res;
	KSI_NetProvider *netProvider = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	netProvider = ctx->netProvider;

	res = KSI_NetHandle_new(ctx, request, request_length, &hndl);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_NetProvider_sendPublicationsFileRequest(netProvider, hndl);
	KSI_CATCH(&err, res) goto cleanup;

	*handle = hndl;
	hndl = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetHandle_free(hndl);

	return KSI_RETURN(&err);

}

int KSI_receivePublicationsFile(KSI_CTX *ctx, KSI_PublicationsFile **pubFile) {
	KSI_ERR err;
	int res;
	KSI_NetHandle *handle = NULL;
	const unsigned char *raw = NULL;
	int raw_len = 0;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, pubFile != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	/* TODO! Implement mechanism for reloading (e.g cache timeout) */
	if (ctx->publicationsFile == NULL) {
		res = KSI_sendPublicationRequest(ctx, NULL, 0, &handle);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_NetHandle_receive(handle);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_NetHandle_getResponse(handle, &raw, &raw_len);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_PublicationsFile_parse(ctx, raw, raw_len, &ctx->publicationsFile);
		KSI_CATCH(&err, res) goto cleanup;
	}

	*pubFile = ctx->publicationsFile;

	KSI_SUCCESS(&err);

cleanup:

	KSI_NetHandle_free(handle);

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

	res = KSI_Signature_sign(ctx, dataHash, &tmp);
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

	res = KSI_Signature_extend(sig, pubRec, &extSig);
	KSI_CATCH(&err, res) goto cleanup;

	*extended = extSig;
	extSig = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Signature_free(extSig);
	return KSI_RETURN(&err);
}

#define CTX_VALUEP_SETTER(var, nam, typ, fre)										\
int KSI_CTX_set##nam(KSI_CTX *ctx, typ *val) { 										\
	return setValue(ctx, #nam, (void **)&ctx->var, (void *)val, fre);				\
} 																					\

#define CTX_VALUEP_GETTER(var, nam, typ) 											\
int KSI_CTX_get##nam(KSI_CTX *ctx, typ **val) { 									\
	return getValue(ctx, #nam, offsetof(KSI_CTX, var), (void **)val);				\
} 																					\

#define CTX_GET_SET_VALUE(var, nam, typ, fre) 										\
	CTX_VALUEP_SETTER(var, nam, typ, fre)											\
	CTX_VALUEP_GETTER(var, nam, typ)												\

CTX_GET_SET_VALUE(pkiTruststore, PKITruststore, KSI_PKITruststore, NULL)
CTX_GET_SET_VALUE(netProvider, NetworkProvider, KSI_NetProvider, KSI_NetProvider_free)
