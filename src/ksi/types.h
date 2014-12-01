#ifndef KSI_COM_TYPES_H_
#define KSI_COM_TYPES_H_

#include <time.h>
#include "types_base.h"
#include "list.h"
#include "common.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup ksi_types KSI Types
 * @{
 */
	typedef struct KSI_MetaData_st KSI_MetaData;
	typedef struct KSI_HashChainLink_st KSI_HashChainLink;
	typedef KSI_HashChainLink KSI_CalendarHashChainLink;
	typedef struct KSI_CalendarHashChain_st KSI_CalendarHashChain;
	typedef struct KSI_ExtendPdu_st KSI_ExtendPdu;
	typedef struct KSI_AggregationPdu_st KSI_AggregationPdu;
	typedef struct KSI_Header_st KSI_Header;
	typedef struct KSI_Config_st KSI_Config;
	typedef struct KSI_AggregationReq_st KSI_AggregationReq;
	typedef struct KSI_RequestAck_st KSI_RequestAck;
	typedef struct KSI_AggregationResp_st KSI_AggregationResp;
	typedef struct KSI_ExtendReq_st KSI_ExtendReq;
	typedef struct KSI_ExtendResp_st KSI_ExtendResp;
	typedef struct KSI_PKISignedData_st KSI_PKISignedData;
	typedef struct KSI_PublicationsHeader_st KSI_PublicationsHeader;
	typedef struct KSI_CertificateRecord_st KSI_CertificateRecord;
	typedef struct KSI_PublicationData_st KSI_PublicationData;
	typedef struct KSI_PublicationRecord_st KSI_PublicationRecord;

	/**
	 * Callback for request header.
	 * \param[in]	hdr		Pointer to the header.
	 * \return Implementation must return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
	 */
	typedef int (*KSI_RequestHeaderCallback)(KSI_Header *hdr);

	/**
	 * Template type.
	 */
	typedef struct KSI_TlvTemplate_st KSI_TlvTemplate;

	/**
	 * Implementation independent type for PKI certificates.
	 */
	typedef struct KSI_PKICertificate_st KSI_PKICertificate;

	/**
	 * Implementation independent type for PKI signature.
	 */
	typedef struct KSI_PKISignature_st KSI_PKISignature;

	/**
	 * Implementation independent PKI truststore.
	 */
	typedef struct KSI_PKITruststore_st KSI_PKITruststore;

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
	 * Network resource handle returned from functions sending or preparing network requests.
	 *
	 *	\see #KSI_NetworkClient_sendExtendRequest, #KSI_NetworkClient_sendSignRequest, #KSI_NetworkClient_sendPublicationsFileRequest
	 */
	typedef struct KSI_NetHandle_st KSI_RequestHandle;

	/**
	 * A generic network client, which needs to have a concrete implementation.
	 * \see #KSI_HttpClient_new
	 */
	typedef struct KSI_NetworkClient_st KSI_NetworkClient;

	/**
	 * Representation of the aggregation hash chain.
	 */
	typedef struct KSI_AggregationHashChain_st KSI_AggregationHashChain;

	/**
	 * Representation of the calendar authentication record.
	 */
	typedef struct KSI_CalendarAuthRec_st KSI_CalendarAuthRec;

	/**
	 * Representation of the aggregation authentication record.
	 */
	typedef struct KSI_AggregationAuthRec_st KSI_AggregationAuthRec;

	KSI_DEFINE_LIST(KSI_MetaData);
	KSI_DEFINE_LIST(KSI_HashChainLink);
	KSI_DEFINE_LIST(KSI_CalendarHashChainLink);
	KSI_DEFINE_LIST(KSI_CalendarHashChain);
	KSI_DEFINE_LIST(KSI_ExtendPdu);
	KSI_DEFINE_LIST(KSI_AggregationPdu);
	KSI_DEFINE_LIST(KSI_Header);
	KSI_DEFINE_LIST(KSI_Config);
	KSI_DEFINE_LIST(KSI_AggregationReq);
	KSI_DEFINE_LIST(KSI_RequestAck);
	KSI_DEFINE_LIST(KSI_AggregationResp);
	KSI_DEFINE_LIST(KSI_ExtendReq);
	KSI_DEFINE_LIST(KSI_ExtendResp);
	KSI_DEFINE_LIST(KSI_PKISignedData);
	KSI_DEFINE_LIST(KSI_PublicationsHeader);
	KSI_DEFINE_LIST(KSI_CertificateRecord);
	KSI_DEFINE_LIST(KSI_PublicationData);
	KSI_DEFINE_LIST(KSI_PublicationRecord);
	KSI_DEFINE_LIST(KSI_Integer);
	KSI_DEFINE_LIST(KSI_OctetString);
	KSI_DEFINE_LIST(KSI_Utf8String);
	KSI_DEFINE_LIST(KSI_Utf8StringNZ);
	KSI_DEFINE_LIST(KSI_AggregationHashChain)
	KSI_DEFINE_LIST(KSI_TLV);
	KSI_DEFINE_LIST(KSI_PKICertificate);

/*
 * KSI_MetaData
 */
void KSI_MetaData_free(KSI_MetaData *t);
int KSI_MetaData_new(KSI_CTX *ctx, KSI_MetaData **t);
int KSI_MetaData_getRaw(const KSI_MetaData *t, KSI_OctetString **raw);
int KSI_MetaData_getClientId(const KSI_MetaData *t, KSI_Utf8String **clientId);
int KSI_MetaData_getMachineId(const KSI_MetaData *t, KSI_Integer **machineId);
int KSI_MetaData_getSequenceNr(const KSI_MetaData *t, KSI_Integer **sequenceNr);
int KSI_MetaData_setRaw(KSI_MetaData *t, KSI_OctetString *raw);
int KSI_MetaData_setClientId(KSI_MetaData *t, KSI_Utf8String *clientId);
int KSI_MetaData_setMachineId(KSI_MetaData *t, KSI_Integer *machineId);
int KSI_MetaData_setSequenceNr(KSI_MetaData *t, KSI_Integer *sequenceNr);

/*
 * KSI_ExtendPdu
 */
void KSI_ExtendPdu_free(KSI_ExtendPdu *t);
int KSI_ExtendPdu_new(KSI_CTX *ctx, KSI_ExtendPdu **t);
int KSI_ExtendPdu_calculateHmac(KSI_ExtendPdu *t, int hashAlg, const char *key, KSI_DataHash **hmac);
int KSI_ExtendPdu_getHeader(const KSI_ExtendPdu *t, KSI_Header **header);
int KSI_ExtendPdu_getRequest(const KSI_ExtendPdu *t, KSI_ExtendReq **request);
int KSI_ExtendPdu_getResponse(const KSI_ExtendPdu *t, KSI_ExtendResp **response);
int KSI_ExtendPdu_getHmac(const KSI_ExtendPdu *t, KSI_DataHash **hmac);
int KSI_ExtendPdu_getHeaderTlv(const KSI_ExtendPdu *t, KSI_TLV ** headerTLV );
int KSI_ExtendPdu_getPayloadTlv(const KSI_ExtendPdu *t, KSI_TLV ** payloadTLV );
int KSI_ExtendPdu_setHeader(KSI_ExtendPdu *t, KSI_Header *header);
int KSI_ExtendPdu_setRequest(KSI_ExtendPdu *t, KSI_ExtendReq *request);
int KSI_ExtendPdu_setResponse(KSI_ExtendPdu *t, KSI_ExtendResp *response);
int KSI_ExtendPdu_setHmac(KSI_ExtendPdu *t, KSI_DataHash *hamc);
int KSI_ExtendPdu_setHeaderTlv(KSI_ExtendPdu *t, KSI_TLV * headerTLV );
int KSI_ExtendPdu_setPayloadTlv(KSI_ExtendPdu *t, KSI_TLV * payloadTLV );

KSI_DEFINE_OBJECT_PARSE(KSI_ExtendPdu);
KSI_DEFINE_OBJECT_SERIALIZE(KSI_ExtendPdu);

/*
 * KSI_AggregationPdu
 */

void KSI_AggregationPdu_free(KSI_AggregationPdu *t);
int KSI_AggregationPdu_new(KSI_CTX *ctx, KSI_AggregationPdu **t);
int KSI_AggregationPdu_calculateHmac(KSI_AggregationPdu *t, int hashAlg, const char *key, KSI_DataHash **hmac);
int KSI_AggregationPdu_getHeader(const KSI_AggregationPdu *t, KSI_Header **header);
int KSI_AggregationPdu_getRequest(const KSI_AggregationPdu *t, KSI_AggregationReq **request);
int KSI_AggregationPdu_getResponse(const KSI_AggregationPdu *t, KSI_AggregationResp **response);
int KSI_AggregationPdu_getHmac(const KSI_AggregationPdu *t, KSI_DataHash **hmac);
int KSI_AggregationPdu_getHeaderTlv(const KSI_AggregationPdu *t, KSI_TLV ** headerTLV);
int KSI_AggregationPdu_getPayloadTlv(const KSI_AggregationPdu *t, KSI_TLV ** payloadTLV);
int KSI_AggregationPdu_setHeader(KSI_AggregationPdu *t, KSI_Header *header);
int KSI_AggregationPdu_setRequest(KSI_AggregationPdu *t, KSI_AggregationReq *request);
int KSI_AggregationPdu_setResponse(KSI_AggregationPdu *t, KSI_AggregationResp *response);
int KSI_AggregationPdu_setHmac(KSI_AggregationPdu *t, KSI_DataHash *hmac);
int KSI_AggregationPdu_setHeaderTlv(KSI_AggregationPdu *t, KSI_TLV * headerTLV);
int KSI_AggregationPdu_setPayloadTlv(KSI_AggregationPdu *t, KSI_TLV * payloadTLV);

KSI_DEFINE_OBJECT_PARSE(KSI_AggregationPdu);
KSI_DEFINE_OBJECT_SERIALIZE(KSI_AggregationPdu);

/*
 * KSI_Header
 */
void KSI_Header_free(KSI_Header *t);
int KSI_Header_new(KSI_CTX *ctx, KSI_Header **t);
int KSI_Header_getInstanceId(const KSI_Header *t, KSI_Integer **instanceId);
int KSI_Header_getMessageId(const KSI_Header *t, KSI_Integer **messageId);
int KSI_Header_getLoginId(const KSI_Header *t, KSI_OctetString **clientId);
int KSI_Header_setInstanceId(KSI_Header *t, KSI_Integer *instanceId);
int KSI_Header_setMessageId(KSI_Header *t, KSI_Integer *messageId);
int KSI_Header_setLoginId(KSI_Header *t, KSI_OctetString *clientId);

/*
 * KSI_Config
 */
void KSI_Config_free(KSI_Config *t);
int KSI_Config_new(KSI_CTX *ctx, KSI_Config **t);
int KSI_Config_getMaxLevel(const KSI_Config *t, KSI_Integer **maxLevel);
int KSI_Config_getAggrAlgo(const KSI_Config *t, KSI_Integer **aggrAlgo);
int KSI_Config_getAggrPeriod(const KSI_Config *t, KSI_Integer **aggrPeriod);
int KSI_Config_getParentUri(const KSI_Config *t, KSI_LIST(KSI_Utf8String) **parentUri);
int KSI_Config_setMaxLevel(KSI_Config *t, KSI_Integer *maxLevel);
int KSI_Config_setAggrAlgo(KSI_Config *t, KSI_Integer *aggrAlgo);
int KSI_Config_setAggrPeriod(KSI_Config *t, KSI_Integer *aggrPeriod);
int KSI_Config_setParentUri(KSI_Config *t, KSI_LIST(KSI_Utf8String) *parentUri);

/*
 * KSI_AggregationReq
 */
void KSI_AggregationReq_free(KSI_AggregationReq *t);
int KSI_AggregationReq_new(KSI_CTX *ctx, KSI_AggregationReq **t);
int KSI_AggregationReq_getRequestId(const KSI_AggregationReq *t, KSI_Integer **requestId);
int KSI_AggregationReq_getRequestHash(const KSI_AggregationReq *t, KSI_DataHash **requestHash);
int KSI_AggregationReq_getRequestLevel(const KSI_AggregationReq *t, KSI_Integer **requestLevel);
int KSI_AggregationReq_getConfig(const KSI_AggregationReq *t, KSI_Config **config);
int KSI_AggregationReq_setRequestId(KSI_AggregationReq *t, KSI_Integer *requestId);
int KSI_AggregationReq_setRequestHash(KSI_AggregationReq *t, KSI_DataHash *requestHash);
int KSI_AggregationReq_setRequestLevel(KSI_AggregationReq *t, KSI_Integer *requestLevel);
int KSI_AggregationReq_setConfig(KSI_AggregationReq *t, KSI_Config *config);

KSI_DEFINE_OBJECT_PARSE(KSI_AggregationReq);
KSI_DEFINE_OBJECT_SERIALIZE(KSI_AggregationReq);

/*
 * KSI_RequestAck
 */
void KSI_RequestAck_free(KSI_RequestAck *t);
int KSI_RequestAck_new(KSI_CTX *ctx, KSI_RequestAck **t);
KSI_CTX *KSI_RequestAck_getCtx(KSI_RequestAck *t);
int KSI_RequestAck_getAggregationPeriod(const KSI_RequestAck *t, KSI_Integer **aggregationPeriod);
int KSI_RequestAck_getAggregationDelay(const KSI_RequestAck *t, KSI_Integer **aggregationDelay);
int KSI_RequestAck_setAggregationPeriod(KSI_RequestAck *t, KSI_Integer *aggregationPeriod);
int KSI_RequestAck_setAggregationDelay(KSI_RequestAck *t, KSI_Integer *aggregationDelay);

/*
 * KSI_AggregationResp
 */
void KSI_AggregationResp_free(KSI_AggregationResp *t);
int KSI_AggregationResp_new(KSI_CTX *ctx, KSI_AggregationResp **t);
int KSI_AggregationResp_getRequestId(const KSI_AggregationResp *t, KSI_Integer **requestId);
int KSI_AggregationResp_getStatus(const KSI_AggregationResp *t, KSI_Integer **status);
int KSI_AggregationResp_getErrorMsg(const KSI_AggregationResp *t, KSI_Utf8String **errorMsg);
int KSI_AggregationResp_getConfig(const KSI_AggregationResp *t, KSI_Config **config);
int KSI_AggregationResp_getRequestAck(const KSI_AggregationResp *t, KSI_RequestAck **requestAck);
int KSI_AggregationResp_getCalendarChain(const KSI_AggregationResp *t, KSI_CalendarHashChain **calendarChain);
int KSI_AggregationResp_getAggregationChainList(const KSI_AggregationResp *t, KSI_LIST(KSI_AggregationHashChain) **aggregationChainList);
int KSI_AggregationResp_getCalendarAuthRec(const KSI_AggregationResp *t, KSI_CalendarAuthRec **calendarAuthRec);
int KSI_AggregationResp_getAggregationAuthRec(const KSI_AggregationResp *t, KSI_AggregationAuthRec **aggregationAuthRec);
int KSI_AggregationResp_getBaseTlv (const KSI_AggregationResp *o, KSI_TLV **baseTlv);
int KSI_AggregationResp_setRequestId(KSI_AggregationResp *t, KSI_Integer *requestId);
int KSI_AggregationResp_setStatus(KSI_AggregationResp *t, KSI_Integer *status);
int KSI_AggregationResp_setErrorMsg(KSI_AggregationResp *t, KSI_Utf8String *errorMsg);
int KSI_AggregationResp_setConfig(KSI_AggregationResp *t, KSI_Config *config);
int KSI_AggregationResp_setRequestAck(KSI_AggregationResp *t, KSI_RequestAck *requestAck);
int KSI_AggregationResp_setCalendarChain(KSI_AggregationResp *t, KSI_CalendarHashChain *calendarChain);
int KSI_AggregationResp_setAggregationChainList(KSI_AggregationResp *t, KSI_LIST(KSI_AggregationHashChain) *aggregationChainList);
int KSI_AggregationResp_setCalendarAuthRec(KSI_AggregationResp *t, KSI_CalendarAuthRec *calendarAuthRec);
int KSI_AggregationResp_setAggregationAuthRec(KSI_AggregationResp *t, KSI_AggregationAuthRec *aggregationAuthRec);
int KSI_AggregationResp_setBaseTlv (KSI_AggregationResp *o, KSI_TLV *baseTlv);

KSI_DEFINE_OBJECT_PARSE(KSI_AggregationResp);
KSI_DEFINE_OBJECT_SERIALIZE(KSI_AggregationResp);

/*
 * KSI_ExtendReq
 */
void KSI_ExtendReq_free(KSI_ExtendReq *t);
int KSI_ExtendReq_new(KSI_CTX *ctx, KSI_ExtendReq **t);
int KSI_ExtendReq_getRequestId(const KSI_ExtendReq *t, KSI_Integer **requestId);
int KSI_ExtendReq_getAggregationTime(const KSI_ExtendReq *t, KSI_Integer **aggregationTime);
int KSI_ExtendReq_getPublicationTime(const KSI_ExtendReq *t, KSI_Integer **publicationTime);
int KSI_ExtendReq_setRequestId(KSI_ExtendReq *t, KSI_Integer *requestId);
int KSI_ExtendReq_setAggregationTime(KSI_ExtendReq *t, KSI_Integer *aggregationTime);
int KSI_ExtendReq_setPublicationTime(KSI_ExtendReq *t, KSI_Integer *publicationTime);

KSI_DEFINE_OBJECT_PARSE(KSI_ExtendReq);
KSI_DEFINE_OBJECT_SERIALIZE(KSI_ExtendReq);

/*
 * KSI_ExtendResp
 */
void KSI_ExtendResp_free(KSI_ExtendResp *t);
int KSI_ExtendResp_new(KSI_CTX *ctx, KSI_ExtendResp **t);
int KSI_ExtendResp_getRequestId(const KSI_ExtendResp *t, KSI_Integer **requestId);
int KSI_ExtendResp_getStatus(const KSI_ExtendResp *t, KSI_Integer **status);
int KSI_ExtendResp_getErrorMsg(const KSI_ExtendResp *t, KSI_Utf8String **errorMsg);
int KSI_ExtendResp_getLastTime(const KSI_ExtendResp *t, KSI_Integer **lastTime);
int KSI_ExtendResp_getCalendarHashChain(const KSI_ExtendResp *t, KSI_CalendarHashChain **calendarHashChain);
int KSI_ExtendResp_getBaseTlv (const KSI_ExtendResp *o, KSI_TLV **baseTlv);
int KSI_ExtendResp_setRequestId(KSI_ExtendResp *t, KSI_Integer *requestId);
int KSI_ExtendResp_setStatus(KSI_ExtendResp *t, KSI_Integer *status);
int KSI_ExtendResp_setErrorMsg(KSI_ExtendResp *t, KSI_Utf8String *errorMsg);
int KSI_ExtendResp_setLastTime(KSI_ExtendResp *t, KSI_Integer *lastTime);
int KSI_ExtendResp_setCalendarHashChain(KSI_ExtendResp *t, KSI_CalendarHashChain *calendarHashChain);
int KSI_ExtendResp_setBaseTlv (KSI_ExtendResp *o, KSI_TLV *baseTlv);

KSI_DEFINE_OBJECT_PARSE(KSI_ExtendResp);
KSI_DEFINE_OBJECT_SERIALIZE(KSI_ExtendResp);

/*
 * KSI_PKISignedData
 */
void KSI_PKISignedData_free(KSI_PKISignedData *t);
int KSI_PKISignedData_new(KSI_CTX *ctx, KSI_PKISignedData **t);
int KSI_PKISignedData_getSignatureValue(const KSI_PKISignedData *t, KSI_OctetString **signatureValue);
int KSI_PKISignedData_getCertId(const KSI_PKISignedData *t, KSI_OctetString **certId);
int KSI_PKISignedData_getCertificate(const KSI_PKISignedData *t, KSI_PKICertificate **cert);
int KSI_PKISignedData_getCertRepositoryUri(const KSI_PKISignedData *t, KSI_Utf8String **certRepositoryUri);
int KSI_PKISignedData_setSignatureValue(KSI_PKISignedData *t, KSI_OctetString *signatureValue);
int KSI_PKISignedData_setCertId(KSI_PKISignedData *t, KSI_OctetString *certId);
int KSI_PKISignedData_setCertificate(KSI_PKISignedData *t, KSI_PKICertificate *cert);
int KSI_PKISignedData_setCertRepositoryUri(KSI_PKISignedData *t, KSI_Utf8String *certRepositoryUri);

/*
 * KSI_PublicationsHeader
 */
void KSI_PublicationsHeader_free(KSI_PublicationsHeader *t);
int KSI_PublicationsHeader_new(KSI_CTX *ctx, KSI_PublicationsHeader **t);
int KSI_PublicationsHeader_getVersion(const KSI_PublicationsHeader *t, KSI_Integer **version);
int KSI_PublicationsHeader_getTimeCreated(const KSI_PublicationsHeader *t, KSI_Integer **timeCreated);
int KSI_PublicationsHeader_getRepositoryUri(const KSI_PublicationsHeader *t, KSI_Utf8String **repositoryUri);
int KSI_PublicationsHeader_setVersion(KSI_PublicationsHeader *t, KSI_Integer *version);
int KSI_PublicationsHeader_setTimeCreated(KSI_PublicationsHeader *t, KSI_Integer *timeCreated);
int KSI_PublicationsHeader_setRepositoryUri(KSI_PublicationsHeader *t, KSI_Utf8String *repositoryUri);

/*
 * KSI_CertificateRecord
 */
void KSI_CertificateRecord_free(KSI_CertificateRecord *t);
int KSI_CertificateRecord_new(KSI_CTX *ctx, KSI_CertificateRecord **t);
int KSI_CertificateRecord_getCertId(const KSI_CertificateRecord *t, KSI_OctetString **certId);
int KSI_CertificateRecord_getCert(const KSI_CertificateRecord *t, KSI_PKICertificate **cert);
int KSI_CertificateRecord_setCertId(KSI_CertificateRecord *t, KSI_OctetString *certId);
int KSI_CertificateRecord_setCert(KSI_CertificateRecord *t, KSI_PKICertificate *cert);

/*
 * KSI_AggregationAuthRec
 */
void KSI_AggregationAuthRec_free(KSI_AggregationAuthRec *aar);
int KSI_AggregationAuthRec_new(KSI_CTX *ctx, KSI_AggregationAuthRec **out);

int KSI_AggregationAuthRec_getAggregationTime(const KSI_AggregationAuthRec *rec, KSI_Integer **aggregationTime);
int KSI_AggregationAuthRec_getChainIndex(const KSI_AggregationAuthRec *rec, KSI_LIST(KSI_Integer) **chainIndexesList);
int KSI_AggregationAuthRec_getInputHash(const KSI_AggregationAuthRec *rec, KSI_DataHash **inputHash);
int KSI_AggregationAuthRec_getSigAlgo(const KSI_AggregationAuthRec *rec, KSI_Utf8String **signatureAlgo);
int KSI_AggregationAuthRec_getSigData(const KSI_AggregationAuthRec *rec, KSI_PKISignedData **signatureData);

int KSI_AggregationAuthRec_setAggregationTime(KSI_AggregationAuthRec *rec, KSI_Integer *aggregationTime);
int KSI_AggregationAuthRec_setChainIndex(KSI_AggregationAuthRec *rec, KSI_LIST(KSI_Integer) *chainIndexesList);
int KSI_AggregationAuthRec_setInputHash(KSI_AggregationAuthRec *rec, KSI_DataHash *inputHash);
int KSI_AggregationAuthRec_setSigAlgo(KSI_AggregationAuthRec *rec, KSI_Utf8String *signatureAlgo);
int KSI_AggregationAuthRec_setSigData(KSI_AggregationAuthRec *rec, KSI_PKISignedData *signatureData);

/*
 * KSI_CalendarAuthRec
 */
void KSI_CalendarAuthRec_free(KSI_CalendarAuthRec *calAuth);
int KSI_CalendarAuthRec_new(KSI_CTX *ctx, KSI_CalendarAuthRec **out);

int KSI_CalendarAuthRec_getSignedData(const KSI_CalendarAuthRec *rec, KSI_TLV **pubDataTlv);
int KSI_CalendarAuthRec_getPublishedData(const KSI_CalendarAuthRec *rec, KSI_PublicationData **pubData);
int KSI_CalendarAuthRec_getSignatureAlgo(const KSI_CalendarAuthRec *rec, KSI_Utf8String **signatureAlgo);
int KSI_CalendarAuthRec_getSignatureData(const KSI_CalendarAuthRec *rec, KSI_PKISignedData **signatureData);

int KSI_CalendarAuthRec_setSignedData(KSI_CalendarAuthRec *rec, KSI_TLV *pubDataTlv);
int KSI_CalendarAuthRec_setPublishedData(KSI_CalendarAuthRec *rec, KSI_PublicationData *pubData);
int KSI_CalendarAuthRec_setSignatureAlgo(KSI_CalendarAuthRec *rec, KSI_Utf8String *signatureAlgo);
int KSI_CalendarAuthRec_setSignatureData(KSI_CalendarAuthRec *rec, KSI_PKISignedData *signatureData);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif


#endif
