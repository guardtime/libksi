/*
 * Copyright 2013-2015 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

#ifndef KSI_COM_TYPES_H_
#define KSI_COM_TYPES_H_

#include <time.h>
#include "types_base.h"
#include "list.h"
#include "common.h"
#include "hash.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup ksi_types KSI Types
 * @{
 */
	typedef struct KSI_MetaDataElement_st KSI_MetaDataElement;
	/**
	 * This is a user defined custom meta-data structure.
	 */
	typedef struct KSI_MetaData_st KSI_MetaData;
	typedef struct KSI_HashChainLinkIdentity_st KSI_HashChainLinkIdentity;
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
	typedef struct KSI_ErrorPdu_st KSI_ErrorPdu;

	/* Typedef for the struct KSI_CertConstraint_st */
	typedef struct KSI_CertConstraint_st KSI_CertConstraint;

	/** Typedef for the signature object. */
	typedef struct KSI_Signature_st KSI_Signature;

	/** Typedef for the verification policy. */
	typedef struct KSI_Policy_st KSI_Policy;

	/** Typedef for the verification context. */
	typedef struct KSI_VerificationContext_st KSI_VerificationContext;

	/** Typedef for the verification result. */
	typedef struct KSI_PolicyVerificationResult_st KSI_PolicyVerificationResult;

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
	 * Network endpoint description that must have implementation according to the type of transport layer used.
	 */
	typedef struct KSI_NetEndpoint_st KSI_NetEndpoint;

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

	/**
	 * Helper data structure for encoding parts of the RFC 3161 envelope.
	 */
	typedef struct KSI_RFC3161_st KSI_RFC3161;

	/** Pair of OID and value. */
	struct KSI_CertConstraint_st {
		/** The OID for the constraint. */
		char *oid;
		/** Expected value. */
		char *val;
	};

#define KSI_APPLY_TO_NOT_NULL(val, fn, args) (((val) != NULL) ? ( val->fn != NULL ? (val->fn args) : KSI_INVALID_STATE) : KSI_INVALID_ARGUMENT)


	KSI_DEFINE_LIST(KSI_MetaDataElement);
#define KSI_MetaDataElementList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_MetaDataElementList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_MetaDataElementList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_MetaDataElementList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_MataDataElementList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_MataDataElementList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_MataDataElementList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_MetaDataElementList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_MetaDataElementList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_HashChainLinkIdentity);
#define KSI_HashChainLinkIdentityList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_HashChainLinkIdentityList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_HashChainLinkIdentityList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_HashChainLinkIdentityList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_HashChainLinkIdentityList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_HashChainLinkIdentityList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_HashChainLinkIdentityList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_HashChainLinkIdentityList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_HashChainLinkIdentityList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_HashChainLink);
#define KSI_HashChainLinkList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_HashChainLinkList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_HashChainLinkList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_HashChainLinkList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_HashChainLinkList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_HashChainLinkList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_HashChainLinkList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_HashChainLinkList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_HashChainLinkList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_CalendarHashChainLink);
#define KSI_CalendarHashChainLinkList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_CalendarHashChainLinkList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_CalendarHashChainLinkList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_CalendarHashChainLinkList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_CalendarHashChainLinkList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_CalendarHashChainLinkList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_CalendarHashChainLinkList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_CalendarHashChainLinkList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_CalendarHashChainLinkList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_CalendarHashChain);
#define KSI_CalendarHashChainList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_CalendarHashChainList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_CalendarHashChainList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_CalendarHashChainList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_CalendarHashChainList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_CalendarHashChainList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_CalendarHashChainList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_CalendarHashChainList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_CalendarHashChainList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_ExtendPdu);
#define KSI_ExtendPduList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_ExtendPduList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_ExtendPduList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_ExtendPduList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_ExtendPduList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_ExtendPduList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_ExtendPduList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_ExtendPduList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_ExtendPduList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_AggregationPdu);
#define KSI_AggregationPduList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_AggregationPduList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_AggregationPduList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_AggregationPduList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_AggregationPduList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_AggregationPduList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_AggregationPduList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_AggregationPduList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_AggregationPduList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_Header);
#define KSI_HeaderList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_HeaderList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_HeaderList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_HeaderList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_HeaderList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_HeaderList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_HeaderList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_HeaderList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_HeaderList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_Config);
#define KSI_ConfigList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_ConfigList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_ConfigList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_ConfigList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_ConfigList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_ConfigList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_ConfigList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_ConfigList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_ConfigList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_AggregationReq);
#define KSI_AggregationReqList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_AggregationReqList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_AggregationReqList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_AggregationReqList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_AggregationReqList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_AggregationReqList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_AggregationReqList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_AggregationReqList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_AggregationReqList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_RequestAck);
#define KSI_RequestAckList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_RequestAckList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_RequestAckList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_RequestAckList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_RequestAckList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_RequestAckList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_RequestAckList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_RequestAckList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_RequestAckList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_AggregationResp);
#define KSI_AggregationRespList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_AggregationRespList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_AggregationRespList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_AggregationRespList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_AggregationRespList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_AggregationRespList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_AggregationRespList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_AggregationRespList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_AggregationRespList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_ExtendReq);
#define KSI_ExtendReqList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_ExtendReqList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_ExtendReqList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_ExtendReqList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_ExtendReqList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_ExtendReqList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_ExtendReqList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_ExtendReqList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_ExtendReqList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_ExtendResp);
#define KSI_ExtendRespList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_ExtendRespList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_ExtendRespList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_ExtendRespList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_ExtendRespList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_ExtendRespList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_ExtendRespList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_ExtendRespList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_ExtendRespList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_PKISignedData);
#define KSI_PKISignedDataList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_PKISignedDataList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_PKISignedDataList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_PKISignedDataList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_PKISignedDataList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_PKISignedDataList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_PKISignedDataList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_PKISignedDataList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_PKISignedDataList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_PublicationsHeader);
#define KSI_PublicationsHeaderList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_PublicationsHeaderList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_PublicationsHeaderList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_PublicationsHeaderList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_PublicationsHeaderList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_PublicationsHeaderList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_PublicationsHeaderList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_PublicationsHeaderList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_PublicationsHeaderList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_CertificateRecord);
#define KSI_CertificateRecordList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_CertificateRecordList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_CertificateRecordList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_CertificateRecordList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_CertificateRecordList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_CertificateRecordList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_CertificateRecordList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_CertificateRecordList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_CertificateRecordList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_PublicationData);
#define KSI_PublicationDataList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_PublicationDataList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_PublicationDataList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_PublicationDataList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_PublicationDataList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_PublicationDataList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_PublicationDataList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_PublicationDataList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_PublicationDataList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_PublicationRecord);
#define KSI_PublicationRecordList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_PublicationRecordList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_PublicationRecordList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_PublicationRecordList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_PublicationRecordList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_PublicationRecordList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_PublicationRecordList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_PublicationRecordList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_PublicationRecordList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_Integer);
#define KSI_IntegerList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_IntegerList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_IntegerList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_IntegerList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_IntegerList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_IntegerList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_IntegerList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_IntegerList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_IntegerList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_OctetString);
#define KSI_OctetStringList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_OctetStringList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_OctetStringList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_OctetStringList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_OctetStringList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_OctetStringList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_OctetStringList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_OctetStringList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_OctetStringList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_Utf8String);
#define KSI_Utf8StringList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_Utf8StringList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_Utf8StringList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_Utf8StringList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_Utf8StringList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_Utf8StringList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_Utf8StringList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_Utf8StringList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_Utf8StringList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_Utf8StringNZ);
#define KSI_Utf8StringNZList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_Utf8StringNZList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_Utf8StringNZList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_Utf8StringNZList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_Utf8StringNZList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_Utf8StringNZList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_Utf8StringNZList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_Utf8StringNZList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_Utf8StringNZList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_AggregationHashChain);
#define KSI_AggregationHashChainList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_AggregationHashChainList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_AggregationHashChainList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_AggregationHashChainList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_AggregationHashChainList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_AggregationHashChainList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_AggregationHashChainList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_AggregationHashChainList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_AggregationHashChainList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_CalendarAuthRec);
#define KSI_CalendarAuthRecList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_CalendarAuthRecList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_CalendarAuthRecList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_CalendarAuthRecList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_CalendarAuthRecList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_CalendarAuthRecList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_CalendarAuthRecList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_CalendarAuthRecList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_CalendarAuthRecList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_TLV);
#define KSI_TLVList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_TLVList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_TLVList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_TLVList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_TLVList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_TLVList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_TLVList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_TLVList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_TLVList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_PKICertificate);
#define KSI_PKICertificateList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_PKICertificateList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_PKICertificateList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_PKICertificateList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_PKICertificateList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_PKICertificateList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_PKICertificateList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_PKICertificateList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_PKICertificateList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_AggregationAuthRec);
#define KSI_AggregationAuthRecList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_AggregationAuthRecList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_AggregationAuthRecList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_AggregationAuthRecList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_AggregationAuthRecList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_AggregationAuthRecList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_AggregationAuthRecList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_AggregationAuthRecList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_AggregationAuthRecList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

	KSI_DEFINE_LIST(KSI_RFC3161);
#define KSI_RFC3161List_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_RFC3161List_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_RFC3161List_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_RFC3161List_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_RFC3161List_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_RFC3161List_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_RFC3161List_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_RFC3161List_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_RFC3161List_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

KSI_DEFINE_LIST(KSI_RequestHandle);
#define KSI_RequestHandleList_append(lst, o) KSI_APPLY_TO_NOT_NULL((lst), append, ((lst), (o)))
#define KSI_RequestHandleList_remove(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), removeElement, ((lst), (pos), (o)))
#define KSI_RequestHandleList_indexOf(lst, o, i) KSI_APPLY_TO_NOT_NULL((lst), indexOf, ((lst), (o), (i)))
#define KSI_RequestHandleList_insertAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), insertAt, ((lst), (pos), (o)))
#define KSI_RequestHandleList_replaceAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), replaceAt, ((lst), (pos), (o)))
#define KSI_RequestHandleList_elementAt(lst, pos, o) KSI_APPLY_TO_NOT_NULL((lst), elementAt, ((lst), (pos), (o)))
#define KSI_RequestHandleList_length(lst) (((lst) != NULL && (lst)->length != NULL) ? (lst)->length((lst)) : 0)
#define KSI_RequestHandleList_sort(lst, cmp) KSI_APPLY_TO_NOT_NULL((lst), sort, ((lst), (cmp)))
#define KSI_RequestHandleList_foldl(lst, foldCtx, foldFn) (((lst) != NULL) ? (((lst)->foldl != NULL) ? ((lst)->foldl((lst), (foldCtx), (foldFn))) : KSI_INVALID_STATE) : KSI_OK)

/*
 * KSI_MetaDataElement.
 */
void KSI_MetaDataElement_free(KSI_MetaDataElement *t);
int KSI_MetaDataElement_new(KSI_CTX *ctx, KSI_MetaDataElement **t);
int KSI_MetaDataElement_getClientId(KSI_MetaDataElement *t, KSI_Utf8String **clientId);
int KSI_MetaDataElement_getMachineId(KSI_MetaDataElement *t, KSI_Utf8String **machineId);
int KSI_MetaDataElement_getSequenceNr(KSI_MetaDataElement *t, KSI_Integer **sequenceNr);
int KSI_MetaDataElement_getRequestTimeInMicros(KSI_MetaDataElement *t, KSI_Integer **reqTime);
int KSI_MetaDataElement_setClientId(KSI_MetaDataElement *t, KSI_Utf8String *clientId);
int KSI_MetaDataElement_setMachineId(KSI_MetaDataElement *t, KSI_Utf8String *machineId);
int KSI_MetaDataElement_setSequenceNr(KSI_MetaDataElement *t, KSI_Integer *sequenceNr);
int KSI_MetaDataElement_setRequestTimeInMicros(KSI_MetaDataElement *t, KSI_Integer *reqTime);
int KSI_MetaDataElement_toTlv(KSI_CTX *ctx, const KSI_MetaDataElement *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);
int KSI_MetaDataElement_fromTlv(KSI_TLV *tlv, KSI_MetaDataElement **metaData);
KSI_DEFINE_REF(KSI_MetaDataElement);

/**
 * Destructor for the object.
 * \param[in]	t		Pointer to the custom meta-data.
 */
void KSI_MetaData_free(KSI_MetaData *t);

/**
 * Constructor for the custom meta-data object.
 * \param[in]	ctx		The KSI context.
 * \param[out]	t		Pointer to the receiving pointer.
 * \return Returns #KSI_OK on success or an error code otherwise.
 */
int KSI_MetaData_new(KSI_CTX *ctx, KSI_MetaData **t);

/**
 * Setter for the client Id.
 * \param[in]	t			The custom meta-data object.
 * \param[in]	clientId	The client id.
 * \note The client id object won't change ownership, the caller must free the object.
 * \return Returns #KSI_OK on success or an error code otherwise.
 */
int KSI_MetaData_setClientId(KSI_MetaData *t, KSI_Utf8String *clientId);

/**
 * Setter for the machine Id.
 * \param[in]	t			The custom meta-data object.
 * \param[in]	clientId	The machine id.
 * \note The machine id object won't change ownership, the caller must free the object.
 * \return Returns #KSI_OK on success or an error code otherwise.
 */
int KSI_MetaData_setMachineId(KSI_MetaData *t, KSI_Utf8String *machineId);

/**
 * Setter for the sequence number.
 * \param[in]	t			The custom meta-data object.
 * \param[in]	clientId	The sequence number.
 * \note The sequence number object won't change ownership, the caller must free the object.
 * \return Returns #KSI_OK on success or an error code otherwise.
 */
int KSI_MetaData_setSequenceNr(KSI_MetaData *t, KSI_Integer *sequenceNr);

/**
 * Setter for the request time in microseconds.
 * \param[in]	t			The custom meta-data object.
 * \param[in]	clientId	The request time in microseconds.
 * \note The request time in microseconds object won't change ownership, the caller must free the object.
 * \return Returns #KSI_OK on success or an error code otherwise.
 */
int KSI_MetaData_setRequestTimeInMicros(KSI_MetaData *t, KSI_Integer *reqTime);

KSI_DEFINE_REF(KSI_MetaData);

/*
 * KSI_ExtendPdu
 */
void KSI_ExtendPdu_free(KSI_ExtendPdu *t);
int KSI_ExtendPdu_new(KSI_CTX *ctx, KSI_ExtendPdu **t);
int KSI_ExtendPdu_calculateHmac(const KSI_ExtendPdu *t, KSI_HashAlgorithm algo_id, const char *key, KSI_DataHash **hmac);
int KSI_ExtendPdu_updateHmac(KSI_ExtendPdu *pdu, KSI_HashAlgorithm algo_id, const char *key);
int KSI_ExtendPdu_getHeader(const KSI_ExtendPdu *t, KSI_Header **header);
int KSI_ExtendPdu_getRequest(const KSI_ExtendPdu *t, KSI_ExtendReq **request);
int KSI_ExtendPdu_getResponse(const KSI_ExtendPdu *t, KSI_ExtendResp **response);
int KSI_ExtendPdu_getConfRequest(const KSI_ExtendPdu *t, KSI_Config **confRequest);
int KSI_ExtendPdu_getConfResponse(const KSI_ExtendPdu *t, KSI_Config **confResponse);
int KSI_ExtendPdu_getHmac(const KSI_ExtendPdu *t, KSI_DataHash **hmac);
int KSI_ExtendPdu_getError(const KSI_ExtendPdu *t, KSI_ErrorPdu **error);
int KSI_ExtendPdu_setHeader(KSI_ExtendPdu *t, KSI_Header *header);
int KSI_ExtendPdu_setRequest(KSI_ExtendPdu *t, KSI_ExtendReq *request);
int KSI_ExtendPdu_setResponse(KSI_ExtendPdu *t, KSI_ExtendResp *response);
int KSI_ExtendPdu_setConfRequest(KSI_ExtendPdu *t, KSI_Config *confRequest);
int KSI_ExtendPdu_setConfResponse(KSI_ExtendPdu *t, KSI_Config *confResponse);
int KSI_ExtendPdu_setHmac(KSI_ExtendPdu *t, KSI_DataHash *hamc);
int KSI_ExtendPdu_setError( KSI_ExtendPdu *t, KSI_ErrorPdu *error);
int KSI_ExtendReq_enclose(KSI_ExtendReq *req, const char *loginId, const char *key, KSI_ExtendPdu **pdu);

KSI_DEFINE_OBJECT_PARSE(KSI_ExtendPdu);
KSI_DEFINE_OBJECT_SERIALIZE(KSI_ExtendPdu);

/*
 * KSI_ErrorPdu
 */
int KSI_ErrorPdu_new(KSI_CTX *ctx, KSI_ErrorPdu **pdu);
void KSI_ErrorPdu_free(KSI_ErrorPdu *pdu);
int KSI_ErrorPdu_getStatus(const KSI_ErrorPdu *pdu, KSI_Integer **status);
int KSI_ErrorPdu_getErrorMessage(const KSI_ErrorPdu *pdu, KSI_Utf8String **errorMsg);
int KSI_ErrorPdu_setStatus(KSI_ErrorPdu *pdu, KSI_Integer *status);
int KSI_ErrorPdu_setErrorMessage(KSI_ErrorPdu *pdu, KSI_Utf8String *errorMsg);

/*
 * KSI_AggregationPdu
 */

void KSI_AggregationPdu_free(KSI_AggregationPdu *t);
int KSI_AggregationPdu_new(KSI_CTX *ctx, KSI_AggregationPdu **t);
int KSI_AggregationPdu_calculateHmac(const KSI_AggregationPdu *t, KSI_HashAlgorithm algo_id, const char *key, KSI_DataHash **hmac);
int KSI_AggregationPdu_updateHmac(KSI_AggregationPdu *pdu, KSI_HashAlgorithm algo_id, const char *key);
int KSI_AggregationPdu_getHeader(const KSI_AggregationPdu *t, KSI_Header **header);
int KSI_AggregationPdu_getRequest(const KSI_AggregationPdu *t, KSI_AggregationReq **request);
int KSI_AggregationPdu_getResponse(const KSI_AggregationPdu *t, KSI_AggregationResp **response);
int KSI_AggregationPdu_getConfRequest(const KSI_AggregationPdu *t, KSI_Config **confRequest);
int KSI_AggregationPdu_getConfResponse(const KSI_AggregationPdu *t, KSI_Config **confResponse);
int KSI_AggregationPdu_getAckRequest(const KSI_AggregationPdu *t, KSI_RequestAck **ackRequest);
int KSI_AggregationPdu_getAckResponse(const KSI_AggregationPdu *t, KSI_RequestAck **ackResponse);
int KSI_AggregationPdu_getHmac(const KSI_AggregationPdu *t, KSI_DataHash **hmac);
int KSI_AggregationPdu_getError (const KSI_AggregationPdu *t, KSI_ErrorPdu **error);
int KSI_AggregationPdu_setHeader(KSI_AggregationPdu *t, KSI_Header *header);
int KSI_AggregationPdu_setRequest(KSI_AggregationPdu *t, KSI_AggregationReq *request);
int KSI_AggregationPdu_setResponse(KSI_AggregationPdu *t, KSI_AggregationResp *response);
int KSI_AggregationPdu_setConfRequest(KSI_AggregationPdu *t, KSI_Config *confRequest);
int KSI_AggregationPdu_setConfResponse(KSI_AggregationPdu *t, KSI_Config *confResponse);
int KSI_AggregationPdu_setAckRequest(KSI_AggregationPdu *t, KSI_RequestAck *ackRequest);
int KSI_AggregationPdu_setAckResponse(KSI_AggregationPdu *t, KSI_RequestAck *ackResponse);
int KSI_AggregationPdu_setHmac(KSI_AggregationPdu *t, KSI_DataHash *hmac);
int KSI_AggregationPdu_setError ( KSI_AggregationPdu *t, KSI_ErrorPdu *error);
int KSI_AggregationReq_enclose(KSI_AggregationReq *req, const char *loginId, const char *key, KSI_AggregationPdu **pdu);
KSI_DEFINE_OBJECT_PARSE(KSI_AggregationPdu);
KSI_DEFINE_OBJECT_SERIALIZE(KSI_AggregationPdu);

/*
 * KSI_Header
 */
void KSI_Header_free(KSI_Header *t);
int KSI_Header_new(KSI_CTX *ctx, KSI_Header **t);
int KSI_Header_getInstanceId(const KSI_Header *t, KSI_Integer **instanceId);
int KSI_Header_getMessageId(const KSI_Header *t, KSI_Integer **messageId);
int KSI_Header_getLoginId(const KSI_Header *t, KSI_Utf8String **loginId);
int KSI_Header_setInstanceId(KSI_Header *t, KSI_Integer *instanceId);
int KSI_Header_setMessageId(KSI_Header *t, KSI_Integer *messageId);
int KSI_Header_setLoginId(KSI_Header *t, KSI_Utf8String *loginId);
KSI_DEFINE_GET_CTX(KSI_Header);

int KSI_Header_fromTlv(KSI_TLV *tlv, KSI_Header **data);
int KSI_Header_toTlv (KSI_CTX *ctx, const KSI_Header *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);
/*
 * KSI_Config
 */
void KSI_Config_free(KSI_Config *t);
int KSI_Config_new(KSI_CTX *ctx, KSI_Config **t);
int KSI_Config_getMaxLevel(const KSI_Config *t, KSI_Integer **maxLevel);
int KSI_Config_getAggrAlgo(const KSI_Config *t, KSI_Integer **aggrAlgo);
int KSI_Config_getAggrPeriod(const KSI_Config *t, KSI_Integer **aggrPeriod);
int KSI_Config_getMaxRequests(const KSI_Config *t, KSI_Integer **maxRequests);
int KSI_Config_getParentUri(const KSI_Config *t, KSI_LIST(KSI_Utf8String) **parentUri);
int KSI_Config_getCalendarFirstTime(const KSI_Config *t, KSI_Integer **calendarFirstTime);
int KSI_Config_getCalendarLastTime(const KSI_Config *t, KSI_Integer **calendarLastTime);
int KSI_Config_setMaxLevel(KSI_Config *t, KSI_Integer *maxLevel);
int KSI_Config_setAggrAlgo(KSI_Config *t, KSI_Integer *aggrAlgo);
int KSI_Config_setAggrPeriod(KSI_Config *t, KSI_Integer *aggrPeriod);
int KSI_Config_setMaxRequests(KSI_Config *t, KSI_Integer *maxRequests);
int KSI_Config_setParentUri(KSI_Config *t, KSI_LIST(KSI_Utf8String) *parentUri);
int KSI_Config_setCalendarFirstTime(KSI_Config *t, KSI_Integer *calendarFirstTime);
int KSI_Config_setCalendarLastTime(KSI_Config *t, KSI_Integer *calendarLastTime);
KSI_DEFINE_REF(KSI_Config);

/*
 * KSI_AggregationConf
 */
#define KSI_AggregationConf_free KSI_Config_free
#define KSI_AggregationConf_new KSI_Config_new

/*
 * KSI_ExtendConf
 */
#define KSI_ExtendConf_free KSI_Config_free
#define KSI_ExtendConf_new KSI_Config_new

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
int KSI_AggregationReq_fromTlv (KSI_TLV *tlv, KSI_AggregationReq **data);
int KSI_AggregationReq_toTlv (KSI_CTX *ctx, const KSI_AggregationReq *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

KSI_DEFINE_REF(KSI_AggregationReq);

/*
 * KSI_RequestAck
 */
void KSI_RequestAck_free(KSI_RequestAck *t);
int KSI_RequestAck_new(KSI_CTX *ctx, KSI_RequestAck **t);
KSI_CTX *KSI_RequestAck_getCtx(KSI_RequestAck *t);
int KSI_RequestAck_getRequestTime(const KSI_RequestAck *t, KSI_Integer **requestTime);
int KSI_RequestAck_getReceiptTime(const KSI_RequestAck *t, KSI_Integer **receiptTime);
int KSI_RequestAck_getAcknowledgeTime(const KSI_RequestAck *t, KSI_Integer **acknowledgeTime);
int KSI_RequestAck_getAggregationPeriod(const KSI_RequestAck *t, KSI_Integer **aggregationPeriod);
int KSI_RequestAck_getAggregationDelay(const KSI_RequestAck *t, KSI_Integer **aggregationDelay);
int KSI_RequestAck_getAggregationDrift(const KSI_RequestAck *t, KSI_Integer **aggregationDrift);
int KSI_RequestAck_setRequestTime(KSI_RequestAck *t, KSI_Integer *requestTime);
int KSI_RequestAck_setReceiptTime(KSI_RequestAck *t, KSI_Integer *receiptTime);
int KSI_RequestAck_setAcknowledgeTime(KSI_RequestAck *t, KSI_Integer *acknowledgeTime);
int KSI_RequestAck_setAggregationPeriod(KSI_RequestAck *t, KSI_Integer *aggregationPeriod);
int KSI_RequestAck_setAggregationDelay(KSI_RequestAck *t, KSI_Integer *aggregationDelay);
int KSI_RequestAck_setAggregationDrift(KSI_RequestAck *t, KSI_Integer *aggregationDrift);

/*
 * KSI_AggregationAckReq
 */
#define KSI_AggregationAckReq_free KSI_RequestAck_free
#define KSI_AggregationAckReq_new KSI_RequestAck_new

/*
 * KSI_AggregationAck
 */
#define KSI_AggregationAck_free KSI_RequestAck_free
#define KSI_AggregationAck_new KSI_RequestAck_new

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

int KSI_AggregationResp_fromTlv (KSI_TLV *tlv, KSI_AggregationResp **data);
int KSI_AggregationResp_toTlv (KSI_CTX *ctx, const KSI_AggregationResp *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

/**
 * Verifies that the response is a correct response to the concrete request.
 * \param[in]	resp	Response to be verified.
 * \param[in]	req		Request to be used for verification.
 */
int KSI_AggregationResp_verifyWithRequest(const KSI_AggregationResp *resp, const KSI_AggregationReq *req);


/*
 * KSI_ExtendReq
 */
void KSI_ExtendReq_free(KSI_ExtendReq *t);
int KSI_ExtendReq_new(KSI_CTX *ctx, KSI_ExtendReq **t);
int KSI_ExtendReq_getRequestId(const KSI_ExtendReq *t, KSI_Integer **requestId);
int KSI_ExtendReq_getAggregationTime(const KSI_ExtendReq *t, KSI_Integer **aggregationTime);
int KSI_ExtendReq_getPublicationTime(const KSI_ExtendReq *t, KSI_Integer **publicationTime);
int KSI_ExtendReq_getConfig(const KSI_ExtendReq *t, KSI_Config **config);
int KSI_ExtendReq_setRequestId(KSI_ExtendReq *t, KSI_Integer *requestId);
int KSI_ExtendReq_setAggregationTime(KSI_ExtendReq *t, KSI_Integer *aggregationTime);
int KSI_ExtendReq_setPublicationTime(KSI_ExtendReq *t, KSI_Integer *publicationTime);
int KSI_ExtendReq_setConfig(KSI_ExtendReq *t, KSI_Config *config);
int KSI_ExtendReq_fromTlv (KSI_TLV *tlv, KSI_ExtendReq **data);
int KSI_ExtendReq_toTlv (KSI_CTX *ctx, const KSI_ExtendReq *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

KSI_DEFINE_REF(KSI_ExtendReq);

/*
 * KSI_ExtendResp
 */
void KSI_ExtendResp_free(KSI_ExtendResp *t);
int KSI_ExtendResp_new(KSI_CTX *ctx, KSI_ExtendResp **t);
int KSI_ExtendResp_getRequestId(const KSI_ExtendResp *t, KSI_Integer **requestId);
int KSI_ExtendResp_getStatus(const KSI_ExtendResp *t, KSI_Integer **status);
int KSI_ExtendResp_getErrorMsg(const KSI_ExtendResp *t, KSI_Utf8String **errorMsg);
int KSI_ExtendResp_getLastTime(const KSI_ExtendResp *t, KSI_Integer **lastTime);
int KSI_ExtendResp_getConfig(const KSI_ExtendResp *t, KSI_Config **config);
int KSI_ExtendResp_getCalendarHashChain(const KSI_ExtendResp *t, KSI_CalendarHashChain **calendarHashChain);
int KSI_ExtendResp_setRequestId(KSI_ExtendResp *t, KSI_Integer *requestId);
int KSI_ExtendResp_setStatus(KSI_ExtendResp *t, KSI_Integer *status);
int KSI_ExtendResp_setErrorMsg(KSI_ExtendResp *t, KSI_Utf8String *errorMsg);
int KSI_ExtendResp_setLastTime(KSI_ExtendResp *t, KSI_Integer *lastTime);
int KSI_ExtendResp_setConfig(KSI_ExtendResp *t, KSI_Config *config);
int KSI_ExtendResp_setCalendarHashChain(KSI_ExtendResp *t, KSI_CalendarHashChain *calendarHashChain);
int KSI_ExtendResp_fromTlv (KSI_TLV *tlv, KSI_ExtendResp **data);
int KSI_ExtendResp_toTlv (KSI_CTX *ctx, const KSI_ExtendResp *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);

/**
 * Verifies that the response is a correct response to the concrete request.
 * \param[in]	resp	Response to be verified.
 * \param[in]	req		Request to be used for verification.
 */
int KSI_ExtendResp_verifyWithRequest(const KSI_ExtendResp *resp, const KSI_ExtendReq *req);


/*
 * KSI_PKISignedData
 */
void KSI_PKISignedData_free(KSI_PKISignedData *t);
int KSI_PKISignedData_new(KSI_CTX *ctx, KSI_PKISignedData **t);
int KSI_PKISignedData_getSignatureValue(const KSI_PKISignedData *t, KSI_OctetString **signatureValue);
int KSI_PKISignedData_getCertId(const KSI_PKISignedData *t, KSI_OctetString **certId);
int KSI_PKISignedData_getCertRepositoryUri(const KSI_PKISignedData *t, KSI_Utf8String **certRepositoryUri);
int KSI_PKISignedData_getSigType(const KSI_PKISignedData *t, KSI_Utf8String **sigType);
int KSI_PKISignedData_setSignatureValue(KSI_PKISignedData *t, KSI_OctetString *signatureValue);
int KSI_PKISignedData_setCertId(KSI_PKISignedData *t, KSI_OctetString *certId);
int KSI_PKISignedData_setCertRepositoryUri(KSI_PKISignedData *t, KSI_Utf8String *certRepositoryUri);
int KSI_PKISignedData_setSigType(KSI_PKISignedData *t, KSI_Utf8String *sigType);

/*
 * KSI_PublicationsHeader
 */
void KSI_PublicationsHeader_free(KSI_PublicationsHeader *t);
int KSI_PublicationsHeader_new(KSI_CTX *ctx, KSI_PublicationsHeader **t);
int KSI_PublicationsHeader_getVersion(const KSI_PublicationsHeader *t, KSI_Integer **version);
int KSI_PublicationsHeader_getTimeCreated(const KSI_PublicationsHeader *t, KSI_Integer **timeCreated_s);
int KSI_PublicationsHeader_getRepositoryUri(const KSI_PublicationsHeader *t, KSI_Utf8String **repositoryUri);
int KSI_PublicationsHeader_setVersion(KSI_PublicationsHeader *t, KSI_Integer *version);
int KSI_PublicationsHeader_setTimeCreated(KSI_PublicationsHeader *t, KSI_Integer *timeCreated_s);
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
KSI_DEFINE_REF(KSI_AggregationAuthRec);
KSI_DEFINE_WRITE_BYTES(KSI_AggregationAuthRec);

/*
 * KSI_CalendarAuthRec
 */
void KSI_CalendarAuthRec_free(KSI_CalendarAuthRec *calAuth);
int KSI_CalendarAuthRec_new(KSI_CTX *ctx, KSI_CalendarAuthRec **out);

int KSI_CalendarAuthRec_getPublishedData(const KSI_CalendarAuthRec *rec, KSI_PublicationData **pubData);
int KSI_CalendarAuthRec_getSignatureAlgo(const KSI_CalendarAuthRec *rec, KSI_Utf8String **signatureAlgo);
int KSI_CalendarAuthRec_getSignatureData(const KSI_CalendarAuthRec *rec, KSI_PKISignedData **signatureData);

int KSI_CalendarAuthRec_setPublishedData(KSI_CalendarAuthRec *rec, KSI_PublicationData *pubData);
int KSI_CalendarAuthRec_setSignatureAlgo(KSI_CalendarAuthRec *rec, KSI_Utf8String *signatureAlgo);
int KSI_CalendarAuthRec_setSignatureData(KSI_CalendarAuthRec *rec, KSI_PKISignedData *signatureData);
KSI_DEFINE_REF(KSI_CalendarAuthRec);
KSI_DEFINE_WRITE_BYTES(KSI_CalendarAuthRec);
/**
 *	KSI_RFC3161
 */

void KSI_RFC3161_free(KSI_RFC3161 *rfc);
int KSI_RFC3161_new(KSI_CTX *ctx, KSI_RFC3161 **out);

int KSI_RFC3161_getAggregationTime (const KSI_RFC3161 *o, KSI_Integer **aggregationTime);
int KSI_RFC3161_getChainIndex (const KSI_RFC3161 *o, KSI_IntegerList **chainIndex);
int KSI_RFC3161_getInputHash (const KSI_RFC3161 *o, KSI_DataHash **inputHash);
int KSI_RFC3161_getTstInfoPrefix (const KSI_RFC3161 *o, KSI_OctetString **tstInfoPrefix);
int KSI_RFC3161_getTstInfoSuffix (const KSI_RFC3161 *o, KSI_OctetString **tstInfoSuffix);
int KSI_RFC3161_getTstInfoAlgo (const KSI_RFC3161 *o, KSI_Integer **tstInfoAlgo);
int KSI_RFC3161_getSigAttrPrefix (const KSI_RFC3161 *o, KSI_OctetString **sigAttrPrefix);
int KSI_RFC3161_getSigAttrSuffix (const KSI_RFC3161 *o, KSI_OctetString **sigAttrSuffix);
int KSI_RFC3161_getSigAttrAlgo (const KSI_RFC3161 *o, KSI_Integer **sigAttrAlgo);

int KSI_RFC3161_setAggregationTime (KSI_RFC3161 *o, KSI_Integer *aggregationTime);
int KSI_RFC3161_setChainIndex (KSI_RFC3161 *o, KSI_IntegerList *chainIndex);
int KSI_RFC3161_setInputHash (KSI_RFC3161 *o, KSI_DataHash *inputHash);
int KSI_RFC3161_setTstInfoPrefix (KSI_RFC3161 *o, KSI_OctetString *tstInfoPrefix);
int KSI_RFC3161_setTstInfoSuffix (KSI_RFC3161 *o, KSI_OctetString *tstInfoSuffix);
int KSI_RFC3161_setTstInfoAlgo (KSI_RFC3161 *o, KSI_Integer *tstInfoAlgo);
int KSI_RFC3161_setSigAttrPrefix (KSI_RFC3161 *o, KSI_OctetString *sigAttrPrefix);
int KSI_RFC3161_setSigAttrSuffix (KSI_RFC3161 *o, KSI_OctetString *sigAttrSuffix);
int KSI_RFC3161_setSigAttrAlgo (KSI_RFC3161 *o, KSI_Integer *sigAttrAlgo);
KSI_DEFINE_REF(KSI_RFC3161);
KSI_DEFINE_WRITE_BYTES(KSI_RFC3161);
/**
 * @}
 */
#ifdef __cplusplus
}
#endif


#endif
