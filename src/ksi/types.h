#ifndef KSI_COM_TYPES_H_
#define KSI_COM_TYPES_H_

#include <time.h>
#include "types_base.h"
#include "list.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * KSI_MetaData
 */
void KSI_MetaData_free(KSI_MetaData *t);
int KSI_MetaData_new(KSI_CTX *ctx, KSI_MetaData **t);
KSI_CTX *KSI_MetaData_getCtx(KSI_MetaData *t);
int KSI_MetaData_getRaw(const KSI_MetaData *t, KSI_OctetString **raw);
int KSI_MetaData_getClientId(const KSI_MetaData *t, KSI_Utf8String **clientId);
int KSI_MetaData_getMachineId(const KSI_MetaData *t, KSI_Integer **machineId);
int KSI_MetaData_getSequenceNr(const KSI_MetaData *t, KSI_Integer **sequenceNr);
int KSI_MetaData_setRaw(KSI_MetaData *t, KSI_OctetString *raw);
int KSI_MetaData_setClientId(KSI_MetaData *t, KSI_Utf8String *clientId);
int KSI_MetaData_setMachineId(KSI_MetaData *t, KSI_Integer *machineId);
int KSI_MetaData_setSequenceNr(KSI_MetaData *t, KSI_Integer *sequenceNr);

/**
 * KSI_HashChainLink
 */
void KSI_HashChainLink_free(KSI_HashChainLink *t);
int KSI_HashChainLink_new(KSI_CTX *ctx, KSI_HashChainLink **t);
KSI_CTX *KSI_HashChainLink_getCtx(KSI_HashChainLink *t);
int KSI_HashChainLink_getIsLeft(const KSI_HashChainLink *t, int *isLeft);
int KSI_HashChainLink_getLevelCorrection(const KSI_HashChainLink *t, int *levelCorrection);
int KSI_HashChainLink_getMetaHash(const KSI_HashChainLink *t, KSI_DataHash **metaHash);
int KSI_HashChainLink_getMetaData(const KSI_HashChainLink *t, KSI_MetaData **metaData);
int KSI_HashChainLink_getImprint(const KSI_HashChainLink *t, KSI_DataHash **imprint);
int KSI_HashChainLink_setIsLeft(KSI_HashChainLink *t, int isLeft);
int KSI_HashChainLink_setLevelCorrection(KSI_HashChainLink *t, int levelCorrection);
int KSI_HashChainLink_setMetaHash(KSI_HashChainLink *t, KSI_DataHash *metaHash);
int KSI_HashChainLink_setMetaData(KSI_HashChainLink *t, KSI_MetaData *metaData);
int KSI_HashChainLink_setImprint(KSI_HashChainLink *t, KSI_DataHash *imprint);

/**
 * KSI_CalendarHashChain
 */
void KSI_CalendarHashChain_free(KSI_CalendarHashChain *t);
int KSI_CalendarHashChain_new(KSI_CTX *ctx, KSI_CalendarHashChain **t);
KSI_CTX *KSI_CalendarHashChain_getCtx(KSI_CalendarHashChain *t);
int KSI_CalendarHashChain_aggregate(KSI_CalendarHashChain *chain, KSI_DataHash **hsh);
int KSI_CalendarHashChain_calculateAggregationTime(KSI_CalendarHashChain *chain, time_t *aggrTime);
int KSI_CalendarHashChain_getPublicationTime(const KSI_CalendarHashChain *t, KSI_Integer **publicationTime);
int KSI_CalendarHashChain_getAggregationTime(const KSI_CalendarHashChain *t, KSI_Integer **aggregationTime);
int KSI_CalendarHashChain_getInputHash(const KSI_CalendarHashChain *t, KSI_DataHash **inputHash);
int KSI_CalendarHashChain_getHashChain(const KSI_CalendarHashChain *t, KSI_LIST(KSI_HashChainLink) **hashChain);
int KSI_CalendarHashChain_setPublicationTime(KSI_CalendarHashChain *t, KSI_Integer *publicationTime);
int KSI_CalendarHashChain_setAggregationTime(KSI_CalendarHashChain *t, KSI_Integer *aggregationTime);
int KSI_CalendarHashChain_setInputHash(KSI_CalendarHashChain *t, KSI_DataHash *inputHash);
int KSI_CalendarHashChain_setHashChain(KSI_CalendarHashChain *t, KSI_LIST(KSI_HashChainLink) *hashChain);

/**
 * KSI_ExtendPdu
 */
void KSI_ExtendPdu_free(KSI_ExtendPdu *t);
int KSI_ExtendPdu_new(KSI_CTX *ctx, KSI_ExtendPdu **t);
KSI_CTX *KSI_ExtendPdu_getCtx(KSI_ExtendPdu *t);
int KSI_ExtendPdu_getRequest(const KSI_ExtendPdu *t, KSI_ExtendReq **request);
int KSI_ExtendPdu_getResponse(const KSI_ExtendPdu *t, KSI_ExtendResp **response);
int KSI_ExtendPdu_setRequest(KSI_ExtendPdu *t, KSI_ExtendReq *request);
int KSI_ExtendPdu_setResponse(KSI_ExtendPdu *t, KSI_ExtendResp *response);

/**
 * KSI_AggregationPdu
 */
void KSI_AggregationPdu_free(KSI_AggregationPdu *t);
int KSI_AggregationPdu_new(KSI_CTX *ctx, KSI_AggregationPdu **t);
KSI_CTX *KSI_AggregationPdu_getCtx(KSI_AggregationPdu *t);
int KSI_AggregationPdu_getRequest(const KSI_AggregationPdu *t, KSI_AggregationReq **request);
int KSI_AggregationPdu_getResponse(const KSI_AggregationPdu *t, KSI_AggregationResp **response);
int KSI_AggregationPdu_setRequest(KSI_AggregationPdu *t, KSI_AggregationReq *request);
int KSI_AggregationPdu_setResponse(KSI_AggregationPdu *t, KSI_AggregationResp *response);

/**
 * KSI_Header
 */
void KSI_Header_free(KSI_Header *t);
int KSI_Header_new(KSI_CTX *ctx, KSI_Header **t);
KSI_CTX *KSI_Header_getCtx(KSI_Header *t);
int KSI_Header_getInstanceId(const KSI_Header *t, KSI_Integer **instanceId);
int KSI_Header_getMessageId(const KSI_Header *t, KSI_Integer **messageId);
int KSI_Header_getClientId(const KSI_Header *t, KSI_OctetString **clientId);
int KSI_Header_setInstanceId(KSI_Header *t, KSI_Integer *instanceId);
int KSI_Header_setMessageId(KSI_Header *t, KSI_Integer *messageId);
int KSI_Header_setClientId(KSI_Header *t, KSI_OctetString *clientId);

/**
 * KSI_Config
 */
void KSI_Config_free(KSI_Config *t);
int KSI_Config_new(KSI_CTX *ctx, KSI_Config **t);
KSI_CTX *KSI_Config_getCtx(KSI_Config *t);
int KSI_Config_getMaxLevel(const KSI_Config *t, KSI_Integer **maxLevel);
int KSI_Config_getAggrAlgo(const KSI_Config *t, KSI_Integer **aggrAlgo);
int KSI_Config_getAggrPeriod(const KSI_Config *t, KSI_Integer **aggrPeriod);
int KSI_Config_getParentUri(const KSI_Config *t, KSI_LIST(KSI_Utf8String) **parentUri);
int KSI_Config_setMaxLevel(KSI_Config *t, KSI_Integer *maxLevel);
int KSI_Config_setAggrAlgo(KSI_Config *t, KSI_Integer *aggrAlgo);
int KSI_Config_setAggrPeriod(KSI_Config *t, KSI_Integer *aggrPeriod);
int KSI_Config_setParentUri(KSI_Config *t, KSI_LIST(KSI_Utf8String) *parentUri);

/**
 * KSI_AggregationReq
 */
void KSI_AggregationReq_free(KSI_AggregationReq *t);
int KSI_AggregationReq_new(KSI_CTX *ctx, KSI_AggregationReq **t);
KSI_CTX *KSI_AggregationReq_getCtx(KSI_AggregationReq *t);
int KSI_AggregationReq_getHeader(const KSI_AggregationReq *t, KSI_Header **header);
int KSI_AggregationReq_getRequestId(const KSI_AggregationReq *t, KSI_Integer **requestId);
int KSI_AggregationReq_getRequestHash(const KSI_AggregationReq *t, KSI_DataHash **requestHash);
int KSI_AggregationReq_getRequestLevel(const KSI_AggregationReq *t, KSI_Integer **requestLevel);
int KSI_AggregationReq_getConfig(const KSI_AggregationReq *t, KSI_Config **config);
int KSI_AggregationReq_setHeader(KSI_AggregationReq *t, KSI_Header *header);
int KSI_AggregationReq_setRequestId(KSI_AggregationReq *t, KSI_Integer *requestId);
int KSI_AggregationReq_setRequestHash(KSI_AggregationReq *t, KSI_DataHash *requestHash);
int KSI_AggregationReq_setRequestLevel(KSI_AggregationReq *t, KSI_Integer *requestLevel);
int KSI_AggregationReq_setConfig(KSI_AggregationReq *t, KSI_Config *config);

/**
 * KSI_RequestAck
 */
void KSI_RequestAck_free(KSI_RequestAck *t);
int KSI_RequestAck_new(KSI_CTX *ctx, KSI_RequestAck **t);
KSI_CTX *KSI_RequestAck_getCtx(KSI_RequestAck *t);
int KSI_RequestAck_getAggregationPeriod(const KSI_RequestAck *t, KSI_Integer **aggregationPeriod);
int KSI_RequestAck_getAggregationDelay(const KSI_RequestAck *t, KSI_Integer **aggregationDelay);
int KSI_RequestAck_setAggregationPeriod(KSI_RequestAck *t, KSI_Integer *aggregationPeriod);
int KSI_RequestAck_setAggregationDelay(KSI_RequestAck *t, KSI_Integer *aggregationDelay);

/**
 * KSI_AggregationResp
 */
void KSI_AggregationResp_free(KSI_AggregationResp *t);
int KSI_AggregationResp_new(KSI_CTX *ctx, KSI_AggregationResp **t);
KSI_CTX *KSI_AggregationResp_getCtx(KSI_AggregationResp *t);
int KSI_AggregationResp_getHeader(const KSI_AggregationResp *t, KSI_Header **header);
int KSI_AggregationResp_getRequestId(const KSI_AggregationResp *t, KSI_Integer **requestId);
int KSI_AggregationResp_getStatus(const KSI_AggregationResp *t, KSI_Integer **status);
int KSI_AggregationResp_getErrorMsg(const KSI_AggregationResp *t, KSI_Utf8String **errorMsg);
int KSI_AggregationResp_getConfig(const KSI_AggregationResp *t, KSI_Config **config);
int KSI_AggregationResp_getRequestAck(const KSI_AggregationResp *t, KSI_RequestAck **requestAck);
int KSI_AggregationResp_getCalendarChain(const KSI_AggregationResp *t, KSI_CalendarHashChain **calendarChain);
int KSI_AggregationResp_getAggregationChainList(const KSI_AggregationResp *t, KSI_LIST(KSI_AggregationHashChain) **aggregationChainList);
int KSI_AggregationResp_getCalendarAuthRec(const KSI_AggregationResp *t, KSI_CalendarAuthRec **calendarAuthRec);
int KSI_AggregationResp_getAggregationAuthRec(const KSI_AggregationResp *t, KSI_AggregationAuthRec **aggregationAuthRec);
int KSI_AggregationResp_setHeader(KSI_AggregationResp *t, KSI_Header *header);
int KSI_AggregationResp_setRequestId(KSI_AggregationResp *t, KSI_Integer *requestId);
int KSI_AggregationResp_setStatus(KSI_AggregationResp *t, KSI_Integer *status);
int KSI_AggregationResp_setErrorMsg(KSI_AggregationResp *t, KSI_Utf8String *errorMsg);
int KSI_AggregationResp_setConfig(KSI_AggregationResp *t, KSI_Config *config);
int KSI_AggregationResp_setRequestAck(KSI_AggregationResp *t, KSI_RequestAck *requestAck);
int KSI_AggregationResp_setCalendarChain(KSI_AggregationResp *t, KSI_CalendarHashChain *calendarChain);
int KSI_AggregationResp_setAggregationChainList(KSI_AggregationResp *t, KSI_LIST(KSI_AggregationHashChain) *aggregationChainList);
int KSI_AggregationResp_setCalendarAuthRec(KSI_AggregationResp *t, KSI_CalendarAuthRec *calendarAuthRec);
int KSI_AggregationResp_setAggregationAuthRec(KSI_AggregationResp *t, KSI_AggregationAuthRec *aggregationAuthRec);

/**
 * KSI_ExtendReq
 */
void KSI_ExtendReq_free(KSI_ExtendReq *t);
int KSI_ExtendReq_new(KSI_CTX *ctx, KSI_ExtendReq **t);
KSI_CTX *KSI_ExtendReq_getCtx(KSI_ExtendReq *t);
int KSI_ExtendReq_getHeader(const KSI_ExtendReq *t, KSI_Header **header);
int KSI_ExtendReq_getRequestId(const KSI_ExtendReq *t, KSI_Integer **requestId);
int KSI_ExtendReq_getAggregationTime(const KSI_ExtendReq *t, KSI_Integer **aggregationTime);
int KSI_ExtendReq_getPublicationTime(const KSI_ExtendReq *t, KSI_Integer **publicationTime);
int KSI_ExtendReq_setHeader(KSI_ExtendReq *t, KSI_Header *header);
int KSI_ExtendReq_setRequestId(KSI_ExtendReq *t, KSI_Integer *requestId);
int KSI_ExtendReq_setAggregationTime(KSI_ExtendReq *t, KSI_Integer *aggregationTime);
int KSI_ExtendReq_setPublicationTime(KSI_ExtendReq *t, KSI_Integer *publicationTime);

/**
 * KSI_ExtendResp
 */
void KSI_ExtendResp_free(KSI_ExtendResp *t);
int KSI_ExtendResp_new(KSI_CTX *ctx, KSI_ExtendResp **t);
KSI_CTX *KSI_ExtendResp_getCtx(KSI_ExtendResp *t);
int KSI_ExtendResp_getHeader(const KSI_ExtendResp *t, KSI_Header **header);
int KSI_ExtendResp_getRequestId(const KSI_ExtendResp *t, KSI_Integer **requestId);
int KSI_ExtendResp_getStatus(const KSI_ExtendResp *t, KSI_Integer **status);
int KSI_ExtendResp_getErrorMsg(const KSI_ExtendResp *t, KSI_Utf8String **errorMsg);
int KSI_ExtendResp_getLastTime(const KSI_ExtendResp *t, KSI_Integer **lastTime);
int KSI_ExtendResp_getCalendarHashChain(const KSI_ExtendResp *t, KSI_CalendarHashChain **calendarHashChain);
int KSI_ExtendResp_setHeader(KSI_ExtendResp *t, KSI_Header *header);
int KSI_ExtendResp_setRequestId(KSI_ExtendResp *t, KSI_Integer *requestId);
int KSI_ExtendResp_setStatus(KSI_ExtendResp *t, KSI_Integer *status);
int KSI_ExtendResp_setErrorMsg(KSI_ExtendResp *t, KSI_Utf8String *errorMsg);
int KSI_ExtendResp_setLastTime(KSI_ExtendResp *t, KSI_Integer *lastTime);
int KSI_ExtendResp_setCalendarHashChain(KSI_ExtendResp *t, KSI_CalendarHashChain *calendarHashChain);

/**
 * KSI_PKISignedData
 */
void KSI_PKISignedData_free(KSI_PKISignedData *t);
int KSI_PKISignedData_new(KSI_CTX *ctx, KSI_PKISignedData **t);
KSI_CTX *KSI_PKISignedData_getCtx(KSI_PKISignedData *t);
int KSI_PKISignedData_getSignatureValue(const KSI_PKISignedData *t, KSI_OctetString **signatureValue);
int KSI_PKISignedData_getCertId(const KSI_PKISignedData *t, KSI_OctetString **certId);
int KSI_PKISignedData_getCertRepositoryUri(const KSI_PKISignedData *t, KSI_Utf8String **certRepositoryUri);
int KSI_PKISignedData_setSignatureValue(KSI_PKISignedData *t, KSI_OctetString *signatureValue);
int KSI_PKISignedData_setCertId(KSI_PKISignedData *t, KSI_OctetString *certId);
int KSI_PKISignedData_setCertRepositoryUri(KSI_PKISignedData *t, KSI_Utf8String *certRepositoryUri);

/**
 * KSI_PublicationsHeader
 */
void KSI_PublicationsHeader_free(KSI_PublicationsHeader *t);
int KSI_PublicationsHeader_new(KSI_CTX *ctx, KSI_PublicationsHeader **t);
KSI_CTX *KSI_PublicationsHeader_getCtx(KSI_PublicationsHeader *t);
int KSI_PublicationsHeader_getVersion(const KSI_PublicationsHeader *t, KSI_Integer **version);
int KSI_PublicationsHeader_getTimeCreated(const KSI_PublicationsHeader *t, KSI_Integer **timeCreated);
int KSI_PublicationsHeader_getRepositoryUri(const KSI_PublicationsHeader *t, KSI_Utf8String **repositoryUri);
int KSI_PublicationsHeader_setVersion(KSI_PublicationsHeader *t, KSI_Integer *version);
int KSI_PublicationsHeader_setTimeCreated(KSI_PublicationsHeader *t, KSI_Integer *timeCreated);
int KSI_PublicationsHeader_setRepositoryUri(KSI_PublicationsHeader *t, KSI_Utf8String *repositoryUri);

/**
 * KSI_CertificateRecord
 */
void KSI_CertificateRecord_free(KSI_CertificateRecord *t);
int KSI_CertificateRecord_new(KSI_CTX *ctx, KSI_CertificateRecord **t);
KSI_CTX *KSI_CertificateRecord_getCtx(KSI_CertificateRecord *t);
int KSI_CertificateRecord_getCertId(const KSI_CertificateRecord *t, KSI_OctetString **certId);
int KSI_CertificateRecord_getCert(const KSI_CertificateRecord *t, KSI_PKICertificate **cert);
int KSI_CertificateRecord_setCertId(KSI_CertificateRecord *t, KSI_OctetString *certId);
int KSI_CertificateRecord_setCert(KSI_CertificateRecord *t, KSI_PKICertificate *cert);

#ifdef __cplusplus
}
#endif


#endif
