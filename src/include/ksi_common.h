#ifndef KSI_COMMON_H_
#define KSI_COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#define KSI_DEFINE_GET_CTX(type) KSI_CTX *type##_getCtx(type *o);

#define KSI_LIST(type) type##List

#define KSI_LIST_FN_NAME(type, name) type##List_##name
#define KSI_DEFINE_LIST(type) 											\
typedef struct type##_list_st KSI_LIST(type);							\
void KSI_LIST_FN_NAME(type, free)(KSI_LIST(type) *);					\
int KSI_LIST_FN_NAME(type, new)(KSI_CTX *, KSI_LIST(type) **);			\
int KSI_LIST_FN_NAME(type, append)(KSI_LIST(type) *, type *);			\
int KSI_LIST_FN_NAME(type, iter)(KSI_LIST(type) *);						\
int KSI_LIST_FN_NAME(type, next)(KSI_LIST(type) *, type **);			\
int KSI_LIST_FN_NAME(type, indexOf)(KSI_LIST(type) *, type *);			\
int KSI_LIST_FN_NAME(type, insertAt)(KSI_LIST(type) *, int, type *);	\
KSI_CTX *type##List_getCtx(KSI_LIST(type) *o);							\

typedef struct KSI_CTX_st KSI_CTX;
typedef struct KSI_ERR_st KSI_ERR;
typedef struct KSI_TLV_st KSI_TLV;
typedef struct KSI_Signature_st KSI_Signature;
typedef struct KSI_RDR_st KSI_RDR;
typedef struct KSI_HashChain_st KSI_HashChain;
typedef struct KSI_Integer_st KSI_Integer;

/**
 * This structure is used for calculating the hash values.
 * \see #KSI_DataHash, #KSI_DataHasher_open, #KSI_DataHasher_reset, #KSI_DataHasher_close, #KSI_DataHasher_free
 */
typedef struct KSI_DataHasher_st KSI_DataHasher;

typedef struct KSI_HashChain_MetaHash_st KSI_MetaHash;

typedef struct KSI_HashChain_MetaHash_st KSI_MetaData;
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

KSI_DEFINE_LIST(KSI_Integer);
KSI_DEFINE_LIST(KSI_TLV);

KSI_DEFINE_GET_CTX(KSI_DataHash);
KSI_DEFINE_GET_CTX(KSI_DataHasher);
KSI_DEFINE_GET_CTX(KSI_TLV);
KSI_DEFINE_GET_CTX(KSI_NetProvider);
KSI_DEFINE_GET_CTX(KSI_NetHandle);
KSI_DEFINE_GET_CTX(KSI_RDR);

#ifdef __cplusplus
}
#endif

#endif /* KSI_COMMON_H_ */
