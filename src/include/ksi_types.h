#ifndef KSI_COM_TYPES_H_
#define KSI_COM_TYPES_H_


#include "ksi_common.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct KSI_Header_st KSI_Header;
typedef struct KSI_Config_st KSI_Config;
typedef struct KSI_AggregationReq_st KSI_AggregationReq;
typedef struct KSI_RequestAck_st KSI_RequestAck;
typedef struct KSI_AggregationResp_st KSI_AggregationResp;
typedef struct KSI_ExtendReq_st KSI_ExtendReq;
typedef struct KSI_ExtendResp_st KSI_ExtendResp;

/**
 * KSI_Header
 */
void KSI_Header_free(KSI_Header *t);
int KSI_Header_new(KSI_CTX *ctx, KSI_Header **t);
int KSI_Header_getInstanceId(const KSI_Header *t, const KSI_Integer **instanceId);
int KSI_Header_getMessageId(const KSI_Header *t, const KSI_Integer **messageId);
int KSI_Header_getClientId(const KSI_Header *t, const KSI_OctetString **clientId);
int KSI_Header_setInstanceId(KSI_Header *t, KSI_Integer *instanceId);
int KSI_Header_setMessageId(KSI_Header *t, KSI_Integer *messageId);
int KSI_Header_setClientId(KSI_Header *t, KSI_OctetString *clientId);

/**
 * KSI_Config
 */
void KSI_Config_free(KSI_Config *t);
int KSI_Config_new(KSI_CTX *ctx, KSI_Config **t);
int KSI_Config_getMaxLevel(const KSI_Config *t, const KSI_Integer **maxLevel);
int KSI_Config_getAggrAlgo(const KSI_Config *t, const KSI_Integer **aggrAlgo);
int KSI_Config_getAggrPeriod(const KSI_Config *t, const KSI_Integer **aggrPeriod);
int KSI_Config_getParentUri(const KSI_Config *t, const KSI_Utf8String **parentUri);
int KSI_Config_setMaxLevel(KSI_Config *t, KSI_Integer *maxLevel);
int KSI_Config_setAggrAlgo(KSI_Config *t, KSI_Integer *aggrAlgo);
int KSI_Config_setAggrPeriod(KSI_Config *t, KSI_Integer *aggrPeriod);
int KSI_Config_setParentUri(KSI_Config *t, KSI_Utf8String *parentUri);

/**
 * KSI_AggregationReq
 */
void KSI_AggregationReq_free(KSI_AggregationReq *t);
int KSI_AggregationReq_new(KSI_CTX *ctx, KSI_AggregationReq **t);
int KSI_AggregationReq_getHeader(const KSI_AggregationReq *t, const KSI_Header **header);
int KSI_AggregationReq_getRequestId(const KSI_AggregationReq *t, const KSI_Integer **requestId);
int KSI_AggregationReq_getRequestHash(const KSI_AggregationReq *t, const KSI_DataHash **requestHash);
int KSI_AggregationReq_getRequestLevel(const KSI_AggregationReq *t, const KSI_Integer **requestLevel);
int KSI_AggregationReq_getConfig(const KSI_AggregationReq *t, const KSI_Config **config);
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
int KSI_RequestAck_getAggregationPeriod(const KSI_RequestAck *t, const KSI_Integer **aggregationPeriod);
int KSI_RequestAck_getAggregationDelay(const KSI_RequestAck *t, const KSI_Integer **aggregationDelay);
int KSI_RequestAck_setAggregationPeriod(KSI_RequestAck *t, KSI_Integer *aggregationPeriod);
int KSI_RequestAck_setAggregationDelay(KSI_RequestAck *t, KSI_Integer *aggregationDelay);

/**
 * KSI_AggregationResp
 */
void KSI_AggregationResp_free(KSI_AggregationResp *t);
int KSI_AggregationResp_new(KSI_CTX *ctx, KSI_AggregationResp **t);
int KSI_AggregationResp_getHeader(const KSI_AggregationResp *t, const KSI_Header **header);
int KSI_AggregationResp_getRequestId(const KSI_AggregationResp *t, const KSI_Integer **requestId);
int KSI_AggregationResp_getStatus(const KSI_AggregationResp *t, const KSI_Integer **status);
int KSI_AggregationResp_getErrorMsg(const KSI_AggregationResp *t, const KSI_Utf8String **errorMsg);
int KSI_AggregationResp_getConfig(const KSI_AggregationResp *t, const KSI_Config **config);
int KSI_AggregationResp_getRequestAck(const KSI_AggregationResp *t, const KSI_RequestAck **requestAck);
int KSI_AggregationResp_getPayload(const KSI_AggregationResp *t, const KSI_LIST(KSI_TLV) **payload);
int KSI_AggregationResp_setHeader(KSI_AggregationResp *t, KSI_Header *header);
int KSI_AggregationResp_setRequestId(KSI_AggregationResp *t, KSI_Integer *requestId);
int KSI_AggregationResp_setStatus(KSI_AggregationResp *t, KSI_Integer *status);
int KSI_AggregationResp_setErrorMsg(KSI_AggregationResp *t, KSI_Utf8String *errorMsg);
int KSI_AggregationResp_setConfig(KSI_AggregationResp *t, KSI_Config *config);
int KSI_AggregationResp_setRequestAck(KSI_AggregationResp *t, KSI_RequestAck *requestAck);
int KSI_AggregationResp_setPayload(KSI_AggregationResp *t, KSI_LIST(KSI_TLV) *payload);

/**
 * KSI_ExtendReq
 */
void KSI_ExtendReq_free(KSI_ExtendReq *t);
int KSI_ExtendReq_new(KSI_CTX *ctx, KSI_ExtendReq **t);
int KSI_ExtendReq_getHeader(const KSI_ExtendReq *t, const KSI_Header **header);
int KSI_ExtendReq_getRequestId(const KSI_ExtendReq *t, const KSI_Integer **requestId);
int KSI_ExtendReq_getAggregationTime(const KSI_ExtendReq *t, const KSI_Integer **aggregationTime);
int KSI_ExtendReq_getPublicationTime(const KSI_ExtendReq *t, const KSI_Integer **publicationTime);
int KSI_ExtendReq_setHeader(KSI_ExtendReq *t, KSI_Header *header);
int KSI_ExtendReq_setRequestId(KSI_ExtendReq *t, KSI_Integer *requestId);
int KSI_ExtendReq_setAggregationTime(KSI_ExtendReq *t, KSI_Integer *aggregationTime);
int KSI_ExtendReq_setPublicationTime(KSI_ExtendReq *t, KSI_Integer *publicationTime);

/**
 * KSI_ExtendResp
 */
void KSI_ExtendResp_free(KSI_ExtendResp *t);
int KSI_ExtendResp_new(KSI_CTX *ctx, KSI_ExtendResp **t);
int KSI_ExtendResp_getHeader(const KSI_ExtendResp *t, const KSI_Header **header);
int KSI_ExtendResp_getRequestId(const KSI_ExtendResp *t, const KSI_Integer **requestId);
int KSI_ExtendResp_getStatus(const KSI_ExtendResp *t, const KSI_Integer **status);
int KSI_ExtendResp_getErrorMsg(const KSI_ExtendResp *t, const KSI_Utf8String **errorMsg);
int KSI_ExtendResp_getLastTime(const KSI_ExtendResp *t, const KSI_Integer **lastTime);
int KSI_ExtendResp_getPayload(const KSI_ExtendResp *t, const KSI_LIST(KSI_TLV) **payload);
int KSI_ExtendResp_setHeader(KSI_ExtendResp *t, KSI_Header *header);
int KSI_ExtendResp_setRequestId(KSI_ExtendResp *t, KSI_Integer *requestId);
int KSI_ExtendResp_setStatus(KSI_ExtendResp *t, KSI_Integer *status);
int KSI_ExtendResp_setErrorMsg(KSI_ExtendResp *t, KSI_Utf8String *errorMsg);
int KSI_ExtendResp_setLastTime(KSI_ExtendResp *t, KSI_Integer *lastTime);
int KSI_ExtendResp_setPayload(KSI_ExtendResp *t, KSI_LIST(KSI_TLV) *payload);


#ifdef __cplusplus
}
#endif


#endif
