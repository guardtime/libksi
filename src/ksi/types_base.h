#ifndef TYPES_BASE_H_
#define TYPES_BASE_H_

#include <stdint.h>
#include "list.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KSI_uint64_t uint64_t
#define KSI_DEFINE_GET_CTX(type) KSI_CTX *type##_getCtx(const type *o);

typedef struct KSI_CTX_st KSI_CTX;
typedef struct KSI_TLV_st KSI_TLV;
typedef struct KSI_ERR_st KSI_ERR;
typedef struct KSI_RDR_st KSI_RDR;
typedef struct KSI_Integer_st KSI_Integer;
typedef struct KSI_Logger_st KSI_Logger;

typedef struct KSI_MetaData_st KSI_MetaData;
typedef struct KSI_HashChainLink_st KSI_HashChainLink;
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
 * Template type.
 */
typedef struct KSI_TlvTemplate_st KSI_TlvTemplate;

/**
 * Octet string type for storing binary data.
 */
typedef struct KSI_OctetString_st KSI_OctetString;

/**
 * Utf-8 string type.
 */
typedef struct KSI_Utf8String_st KSI_Utf8String;

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
 * Network resource handle
 *
 *	\see #KSI_NET_sendRequest
 */
typedef struct KSI_NetHandle_st KSI_RequestHandle;
typedef struct KSI_NetworkClient_st KSI_NetworkClient;
typedef struct KSI_AggregationHashChain_st KSI_AggregationHashChain;
typedef struct KSI_CalendarAuthRec_st KSI_CalendarAuthRec;
typedef struct KSI_AggregationAuthRec_st KSI_AggregationAuthRec;

KSI_DEFINE_LIST(KSI_MetaData);
KSI_DEFINE_LIST(KSI_HashChainLink);
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
KSI_DEFINE_LIST(KSI_AggregationHashChain)
KSI_DEFINE_LIST(KSI_TLV);
KSI_DEFINE_LIST(KSI_PKICertificate);

/**
 * KSI_Integer
 */
void KSI_Integer_free(KSI_Integer *kint);
int KSI_Integer_getSize(const KSI_Integer *kint, unsigned *size);
char *KSI_Integer_toDateString(const KSI_Integer *kint, char *buf, unsigned buf_len);
KSI_uint64_t KSI_Integer_getUInt64(const KSI_Integer *kint);
int KSI_Integer_new(KSI_CTX *ctx, KSI_uint64_t value, KSI_Integer **kint);
int KSI_Integer_equals(const KSI_Integer *a, const KSI_Integer *b);
int KSI_Integer_compare(const KSI_Integer *a, const KSI_Integer *b);
int KSI_Integer_equalsUInt(const KSI_Integer *o, KSI_uint64_t i);
int KSI_Integer_clone(KSI_Integer *val, KSI_Integer **clone);
int KSI_Integer_fromTlv(KSI_TLV *tlv, KSI_Integer **integer);
int KSI_Integer_toTlv(KSI_Integer *i, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

/**
 * KSI_OctetString
 */
void KSI_OctetString_free(KSI_OctetString *t);
int KSI_OctetString_new(KSI_CTX *ctx, const unsigned char *data, unsigned int data_len, KSI_OctetString **t);
int KSI_OctetString_extract(const KSI_OctetString *t, const unsigned char **data, unsigned int *data_len);
int KSI_OctetString_equals(const KSI_OctetString *left, const KSI_OctetString *right);
int KSI_OctetString_fromTlv(KSI_TLV *tlv, KSI_OctetString **oct);
int KSI_OctetString_toTlv(KSI_OctetString *oct, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

/**
 * KSI_Utf8String
 */

/**
 * Cleanup method for the #KSI_Utf8String object.
 * \param[in]		t			Pointer to the object to be freed.
 *
 */
void KSI_Utf8String_free(KSI_Utf8String *t);

/**
 * Creates a new #KSI_Utf8String object.
 * \param[in]		ctx			KSI context.
 * \param[in]		str			String value.
 * \param[out]		t			Pointer to the receiving pointer.
 *
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 * \see #KSI_Utf8String_free, #KSI_Utf8String_cstr
 */
int KSI_Utf8String_new(KSI_CTX *ctx, const char *str, KSI_Utf8String **t);

/**
 * Returns the actual size of the string in bytes.
 * \param[in]		t		KSI utf8 string object.
 * \return Returns the actual size of the string in bytes or 0 if the object is NULL.
 */
size_t KSI_Utf8String_size(const KSI_Utf8String *t);

/**
 * Returns a constant pointer to a buffer containing the null terminated c string or NULL if the
 * object is NULL.
 * \param[in]		t			Pointer to the string object.
 *
 * \return Pointer to the null terminated c string.
 */
const char *KSI_Utf8String_cstr(const KSI_Utf8String *t);
int KSI_Utf8String_fromTlv(KSI_TLV *tlv, KSI_Utf8String **u8str);
int KSI_Utf8String_toTlv(KSI_Utf8String *u8str, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

/**
 * KSI_AggregationHashChain
 */
void KSI_AggregationHashChain_free(KSI_AggregationHashChain *aggr);
int KSI_AggregationHashChain_new(KSI_CTX *ctx, KSI_AggregationHashChain **out);

int KSI_AggregationHashChain_getAggregationTime(const KSI_AggregationHashChain *aggr, KSI_Integer **aggregationTime);
int KSI_AggregationHashChain_getChainIndex(const KSI_AggregationHashChain * aggr, KSI_LIST(KSI_Integer) **chainIndex);
int KSI_AggregationHashChain_getInputData(const KSI_AggregationHashChain * aggr, KSI_OctetString **inputData);
int KSI_AggregationHashChain_getInputHash(const KSI_AggregationHashChain * aggr, KSI_DataHash **inputHash);
int KSI_AggregationHashChain_getAggrHashId(const KSI_AggregationHashChain * aggr, KSI_Integer **aggrHashId);

int KSI_AggregationHashChain_setAggregationTime(KSI_AggregationHashChain *aggr, KSI_Integer *aggregationTime);
int KSI_AggregationHashChain_setChainIndex(KSI_AggregationHashChain * aggr, KSI_LIST(KSI_Integer) *chainIndex);
int KSI_AggregationHashChain_setInputData(KSI_AggregationHashChain * aggr, KSI_OctetString *inputData);
int KSI_AggregationHashChain_setInputHash(KSI_AggregationHashChain * aggr, KSI_DataHash *inputHash);
int KSI_AggregationHashChain_setAggrHashId(KSI_AggregationHashChain * aggr, KSI_Integer *aggrHashId);

int KSI_AggregationHashChain_toTlv(KSI_TLV *tlv, KSI_AggregationHashChain **rec);
int KSI_AggregationHashChain_fromTlv(KSI_TLV *tlv, KSI_AggregationHashChain **rec);

/**
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

/**
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

KSI_DEFINE_GET_CTX(KSI_DataHash);
KSI_DEFINE_GET_CTX(KSI_DataHasher);
KSI_DEFINE_GET_CTX(KSI_TLV);
KSI_DEFINE_GET_CTX(KSI_NetworkClient);
KSI_DEFINE_GET_CTX(KSI_RequestHandle);
KSI_DEFINE_GET_CTX(KSI_RDR);

#ifdef __cplusplus
}
#endif

#endif /* TYPES_BASE_H_ */
