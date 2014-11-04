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
 * An utf-8 string wich must have at least one printable character.
 */
typedef KSI_Utf8String KSI_Utf8StringNZ;

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

/**
 * Method to free or dereference a KSI_Integer object. The object is
 * not freed if the object is still referenced from somewhere.
 * \param[in]	o		Pointer to be freed
 * \see #KSI_Integer_new, #KSI_Integer_ref
 */
void KSI_Integer_free(KSI_Integer *o);

/**
 * This method converts the #KSI_Integer value as UTC time and converts
 * its value to a string with the following format: "%Y-%m-%d %H:%M:%S UTC".
 * The result is written to buffer. If the buffer is too short, the remainder
 * is discarded. It is guaranteed to set a terminating '\0' to the end of the
 * result.
 *
 * \param[in]	o		Pointer to #KSI_Integer.
 * \param[in]	buf		Pointer to buffer.
 * \param[in]	buf_len	Length of the buffer.
 * \return On success returns buf and NULL if an error occured.
 */
char *KSI_Integer_toDateString(const KSI_Integer *o, char *buf, unsigned buf_len);

/**
 * Returns the native 64-bit value of the #KSI_Integer.
 * \param[in]	o		Pointer to #KSI_Integer.
 * \return The native 64-bit value.
 */
KSI_uint64_t KSI_Integer_getUInt64(const KSI_Integer *o);

/**
 * Constructor to create a new #KSI_Integer.
 * \param[in]	ctx		KSI context.
 * \param[in]	value	Value of the new #KSI_Integer.
 * \param[out]	o		Pointer to the receiving pointer.
 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_Integer_new(KSI_CTX *ctx, KSI_uint64_t value, KSI_Integer **o);

/**
 * Function to determine equality of the values of the two
 * #KSI_Integer objects.
 * \param[in]	a		Left operand.
 * \param[in]	b		Right operand.
 * \return 0 if the values differ, otherwise returns value greater than 0.
 */
int KSI_Integer_equals(const KSI_Integer *a, const KSI_Integer *b);

/**
 * Function to copmare the values of two #KSI_Integer objects.
 * \param[in]	a		Left operand.
 * \param[in]	b		Right operand.
 * \return Returns 0 if the values are equal, -1 if b is greater and 1 otherwise.
 * \note NULL values are treated as they where #KSI_Integer objects with value 0.
 */
int KSI_Integer_compare(const KSI_Integer *a, const KSI_Integer *b);

/**
 * Function to compare the equality of a #KSI_Integer with a native
 * unsigned value.
 * \param[in]	o		Pointer to #KSI_Integer.
 * \param[in]	i		Native unsigned value
 * \return Returns 0 if the values differ, otherwise value greater than 0.
 * \note If a == NULL, the result is always not true.
 */
int KSI_Integer_equalsUInt(const KSI_Integer *o, KSI_uint64_t i);

/**
 * Increases the inner reference count of that object.
 * \param[in]	o		Pointer to #KSI_Integer
 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_Integer_free
 */
int KSI_Integer_ref(KSI_Integer *o);

/**
 * Function to convert a plain #KSI_TLV to a #KSI_Integer. The TLV meta data (i.e.
 * tag, length and flags) are not preserved.
 * \param[in]	tlv		Pointer to #KSI_TLV.
 * \param[out]	o		Pointer to receiving pointer.
 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_Integer_fromTlv(KSI_TLV *tlv, KSI_Integer **o);

/**
 * Function to create a #KSI_TLV object.
 * \param[in]	ctx				KSI context.
 * \param[in]	o				Pointer to #KSI_Integer.
 * \param[in]	tag				The TLV tag value.
 * \param[in]	isNonCritical	Is non-critical TLV flag.
 * \param[in]	isForward		Is forward TLV flag.
 * \param[out]	tlv				Pointer to receiving pointer.
 * \return status code (\c KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSI_Integer_toTlv(KSI_CTX *ctx, KSI_Integer *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

/**
 * KSI_OctetString
 */
void KSI_OctetString_free(KSI_OctetString *t);
int KSI_OctetString_new(KSI_CTX *ctx, const unsigned char *data, unsigned int data_len, KSI_OctetString **t);
int KSI_OctetString_extract(const KSI_OctetString *t, const unsigned char **data, unsigned int *data_len);
int KSI_OctetString_equals(const KSI_OctetString *left, const KSI_OctetString *right);
int KSI_OctetString_fromTlv(KSI_TLV *tlv, KSI_OctetString **oct);
int KSI_OctetString_toTlv(KSI_CTX *ctx, KSI_OctetString *oct, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);
int KSI_OctetString_ref(KSI_OctetString *o);

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
int KSI_Utf8String_new(KSI_CTX *ctx, const unsigned char *str, unsigned len, KSI_Utf8String **t);

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
const char *KSI_Utf8String_cstr(const KSI_Utf8String *o);
int KSI_Utf8String_fromTlv(KSI_TLV *tlv, KSI_Utf8String **o);
int KSI_Utf8String_toTlv(KSI_CTX *ctx, KSI_Utf8String *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);
int KSI_Utf8String_ref(KSI_Utf8String *o);

int KSI_Utf8StringNZ_fromTlv(KSI_TLV *tlv, KSI_Utf8String **o);
int KSI_Utf8StringNZ_toTlv(KSI_CTX *ctx, KSI_Utf8String *o, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

/* TODO! Following functions should not be declared here. */
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
