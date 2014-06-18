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
/**
 * Template type.
 */
typedef struct KSI_TlvTemplate_st KSI_TlvTemplate;
typedef struct KSI_OctetString_st KSI_OctetString;
typedef struct KSI_Utf8String_st KSI_Utf8String;
typedef struct KSI_PKICertificate_st KSI_PKICertificate;
typedef struct KSI_PKISignature_st KSI_PKISignature;
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
typedef struct KSI_NetHandle_st KSI_NetHandle;
typedef struct KSI_NetProvider_st KSI_NetProvider;

void KSI_Integer_free(KSI_Integer *kint);
int KSI_Integer_getSize(const KSI_Integer *kint, int *size);
KSI_uint64_t KSI_Integer_getUInt64(const KSI_Integer *kint);
int KSI_Integer_new(KSI_CTX *ctx, KSI_uint64_t value, KSI_Integer **kint);
int KSI_Integer_equals(const KSI_Integer *a, const KSI_Integer *b);
int KSI_Integer_compare(const KSI_Integer *a, const KSI_Integer *b);
int KSI_Integer_equalsUInt(const KSI_Integer *o, KSI_uint64_t i);
KSI_Integer *KSI_Integer_clone(const KSI_Integer *val);
int KSI_Integer_fromTlv(KSI_TLV *tlv, KSI_Integer **integer);
int KSI_Integer_toTlv(KSI_Integer *i, int tag, int isNonCritical, int isForward, KSI_TLV **tlv);


void KSI_OctetString_free(KSI_OctetString *t);
int KSI_OctetString_new(KSI_CTX *ctx, const unsigned char *data, int data_len, KSI_OctetString **t);
int KSI_OctetString_extract(const KSI_OctetString *t, const unsigned char **data, int *data_len);
int KSI_OctetString_equals(const KSI_OctetString *left, const KSI_OctetString *right);
int KSI_OctetString_fromTlv(KSI_TLV *tlv, KSI_OctetString **oct);
int KSI_OctetString_toTlv(KSI_OctetString *oct, int tag, int isNonCritical, int isForward, KSI_TLV **tlv);

void KSI_Utf8String_free(KSI_Utf8String *t);
int KSI_Utf8String_new(KSI_CTX *ctx, const char *str, KSI_Utf8String **t);
char *KSI_Utf8String_cstr(KSI_Utf8String *t);
int KSI_Utf8String_fromTlv(KSI_TLV *tlv, KSI_Utf8String **u8str);
int KSI_Utf8String_toTlv(KSI_Utf8String *u8str, int tag, int isNonCritical, int isForward, KSI_TLV **tlv);


KSI_DEFINE_LIST(KSI_Integer);
KSI_DEFINE_LIST(KSI_TLV);
KSI_DEFINE_LIST(KSI_Utf8String);
KSI_DEFINE_LIST(KSI_OctetString);
KSI_DEFINE_LIST(KSI_PKICertificate);

KSI_DEFINE_GET_CTX(KSI_DataHash);
KSI_DEFINE_GET_CTX(KSI_DataHasher);
KSI_DEFINE_GET_CTX(KSI_TLV);
KSI_DEFINE_GET_CTX(KSI_NetProvider);
KSI_DEFINE_GET_CTX(KSI_NetHandle);
KSI_DEFINE_GET_CTX(KSI_RDR);

#ifdef __cplusplus
}
#endif

#endif /* TYPES_BASE_H_ */
