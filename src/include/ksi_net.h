/*
 * ksi_net.h
 *
 *  Created on: 11.04.2014
 *      Author: henri
 */

#ifndef KSI_NET_H_
#define KSI_NET_H_

#include "ksi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

	void KSI_NET_Handle_freeNetContext(void *netCtx);

	int KSI_NET_global_init(void);

	void KSI_NET_global_cleanup(void);

	/** Transport Providers */
	int KSI_NET_CURL_new(KSI_CTX *ctx, KSI_NetProvider **netProvider);
	int KSI_NET_CURL_setSignerUrl(KSI_NetProvider *netProvider, char *val);
	int KSI_NET_CURL_setExtenderUrl(KSI_NetProvider *netProvider, char *val);
	int KSI_NET_CURL_setPublicationUrl(KSI_NetProvider *netProvider, char *val);
	int KSI_NET_CURL_setConnectionTimeoutSeconds(KSI_NetProvider *netProvider, int val);
	int KSI_NET_CURL_setReadTimeoutSeconds(KSI_NetProvider *netProvider, int val);
	/**
	 *
	 */
	int KSI_NET_sendRequest(KSI_CTX *ctx, const char *url, const unsigned char *request, int request_length, KSI_NetHandle **handle);

	/**
	 *
	 */
	int KSI_NET_sendSignRequest(KSI_NetProvider *netProvider, const unsigned char *request, int request_length, KSI_NetHandle **handle);
	/**
	 *
	 */
	int KSI_NET_sendExtendRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle);

	/**
	 *
	 */
	int KSI_NET_sendPublicationRequest(KSI_CTX *ctx, const unsigned char *request, int request_length, KSI_NetHandle **handle);

	/**
	 *
	 */
	int KSI_NET_getResponse(KSI_NetHandle *handle, unsigned char **response, int *response_length, int copy);

	/**
	 *
	 */
	void KSI_NetHandle_free(KSI_NetHandle *heandle);

	/**
	 *
	 */
	void KSI_NetProvider_free(KSI_NetProvider *provider);

	int KSI_Signature_validate(KSI_Signature *sig);
	void KSI_Signature_free(KSI_Signature *sig);
	int KSI_Signature_getDataHash(KSI_Signature *sig, const KSI_DataHash ** hsh);
	int KSI_Signature_getSigningTime(KSI_Signature *sig, KSI_Integer *signTime);
	int KSI_Signature_getSignerIdentity(KSI_Signature *sig, char **identity);
	int KSI_Signature_getCalendarHash(KSI_Signature *sig, const KSI_DataHash **hsh);
	/** TODO! For now these are just mock declarations
	int KSI_Signature_getPublishedData(KSI_Signature *sig, char **pub_data);
	int KSI_Signature_getPublicationReference(KSI_Signature *sig, char **pub_ref);
	int KSI_Signature_getPublicationSignature(KSI_Signature *sig, char **pub_sig);
	*/

	int KSI_NetHandle_setResponse(KSI_NetHandle *handle, const unsigned char *response, int response_len);
	int KSI_NetHandle_setNetContext(KSI_NetHandle *handle, void *, void (*netCtx_free)(void *));
	void *KSI_NetHandle_getNetContext(KSI_NetHandle *handle);
	int KSI_NetHandle_getRequest(KSI_NetHandle *handle, const unsigned char **response, int *response_len);
	void *KSI_NetHandle_getNetContext(KSI_NetHandle *handle);
	int KSI_NetHandle_new(KSI_CTX *ctx, KSI_NetHandle **handle);
	int KSI_NetHandle_setReadResponseFn(KSI_NetHandle *handle, int fn(KSI_NetHandle *));

	int KSI_NetProvider_new(KSI_CTX *ctx, KSI_NetProvider **provider);
	int KSI_NetProvider_setNetCtx(KSI_NetProvider *provider, void *netCtx, void (*netCtx_free)(void *));
	int KSI_NetProvider_setSendSignRequestFn(KSI_NetProvider *provider, int (*fn)(KSI_NetProvider *, KSI_NetHandle *));
	int KSI_NetProvider_setExtendSignRequestFn(KSI_NetProvider *provider, int (*fn)(KSI_NetProvider *, KSI_NetHandle *));
	int KSI_NetProvider_setSendPublicationRequestFn(KSI_NetProvider *provider, int (*fn)(KSI_NetProvider *, KSI_NetHandle *));
	void *KSI_NetProvider_getNetContext(KSI_NetProvider *provider);


#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_H_ */
