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

#include <limits.h>
#include <string.h>
#include "internal.h"

#include "tlv.h"
#include "tlv_template.h"
#include "hashchain.h"
#include "pkitruststore.h"
#include "fast_tlv.h"

/* At the moment value 0xff should be enough for everyone (actually less than 10 is used). */
#define MAX_TEMPLATE_SIZE 0xff

#define KSI_CalAuthRecPKISignedData_new KSI_PKISignedData_new
#define KSI_CalAuthRecPKISignedData_free KSI_PKISignedData_free

#define KSI_AggrAuthRecPKISignedData_new KSI_PKISignedData_new
#define KSI_AggrAuthRecPKISignedData_free KSI_PKISignedData_free

#define KSI_Utf8StringNZ_new KSI_Utf8String_new
#define KSI_Utf8StringNZ_free KSI_Utf8String_free

#define KSI_CalendarHashChainLink_free KSI_HashChainLink_free

#define IS_FLAG_SET(tmpl, flg) (((tmpl).flags & flg) != 0)

struct tlv_track_s {
	unsigned tag;
	const char *desc;
};

static int extractGenerator(KSI_CTX *ctx, void *payload, void *generatorCtx, const KSI_TlvTemplate *tmpl, int (*generator)(void *, KSI_TLV **), struct tlv_track_s *tr, size_t tr_len, size_t tr_size);
static int extract(KSI_CTX *ctx, void *payload, KSI_TLV *tlv, const KSI_TlvTemplate *tmpl, struct tlv_track_s *tr, size_t tr_len, size_t tr_size);

KSI_DEFINE_TLV_TEMPLATE(KSI_CalAuthRecPKISignedData)
	KSI_TLV_UTF8_STRING(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PKISignedData_getSigType, KSI_PKISignedData_setSigType, "sign_data")
	KSI_TLV_OCTET_STRING(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PKISignedData_getSignatureValue, KSI_PKISignedData_setSignatureValue, "pki_signature")
	KSI_TLV_OCTET_STRING(0x03, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PKISignedData_getCertId, KSI_PKISignedData_setCertId, "cert_id")
	KSI_TLV_OBJECT(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_PKISignedData_getCertRepositoryUri, KSI_PKISignedData_setCertRepositoryUri, KSI_Utf8StringNZ_fromTlv, KSI_Utf8StringNZ_toTlv, KSI_Utf8String_free, "cert_rep_uri")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggrAuthRecPKISignedData)
	KSI_TLV_UTF8_STRING(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PKISignedData_getSigType, KSI_PKISignedData_setSigType, "sig_type")
	KSI_TLV_OCTET_STRING(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PKISignedData_getSignatureValue, KSI_PKISignedData_setSignatureValue, "signed_data")
	KSI_TLV_OCTET_STRING(0x03, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PKISignedData_getCertId, KSI_PKISignedData_setCertId, "cert_id")
	KSI_TLV_OBJECT(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_PKISignedData_getCertRepositoryUri, KSI_PKISignedData_setCertRepositoryUri, KSI_Utf8StringNZ_fromTlv, KSI_Utf8StringNZ_toTlv, KSI_Utf8String_free, "cert_rep_uri")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationsHeader)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationsHeader_getVersion, KSI_PublicationsHeader_setVersion, "version")
	KSI_TLV_TIME_S(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationsHeader_getTimeCreated, KSI_PublicationsHeader_setTimeCreated, "time_created")
	KSI_TLV_OBJECT(0x03, KSI_TLV_TMPL_FLG_NONE, KSI_PublicationsHeader_getRepositoryUri, KSI_PublicationsHeader_setRepositoryUri, KSI_Utf8StringNZ_fromTlv, KSI_Utf8StringNZ_toTlv, KSI_Utf8String_free, "rep_uri")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_CertificateRecord)
	KSI_TLV_OCTET_STRING(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_CertificateRecord_getCertId, KSI_CertificateRecord_setCertId, "cert_id")
	KSI_TLV_OBJECT(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_CertificateRecord_getCert, KSI_CertificateRecord_setCert, KSI_PKICertificate_fromTlv, KSI_PKICertificate_toTlv, KSI_PKICertificate_free, "cert")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationData)
	KSI_TLV_TIME_S(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationData_getTime, KSI_PublicationData_setTime, "pub_time")
	KSI_TLV_IMPRINT(0x04, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationData_getImprint, KSI_PublicationData_setImprint, "imprint")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationRecord)
	KSI_TLV_COMPOSITE(0x10, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationRecord_getPublishedData, KSI_PublicationRecord_setPublishedData, KSI_PublicationData, "pub_data")
	KSI_TLV_OBJECT_LIST(0x09, KSI_TLV_TMPL_FLG_NONE, KSI_PublicationRecord_getPublicationRefList, KSI_PublicationRecord_setPublicationRefList, KSI_Utf8StringNZ, "pub_ref")
	KSI_TLV_OBJECT_LIST(0x0a, KSI_TLV_TMPL_FLG_NONE, KSI_PublicationRecord_getRepositoryUriList, KSI_PublicationRecord_setRepositoryUriList, KSI_Utf8StringNZ, "uri")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_MetaDataElement)
	KSI_TLV_UTF8_STRING(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_MetaDataElement_getClientId, KSI_MetaDataElement_setClientId, "client_id")
	KSI_TLV_UTF8_STRING(0x02, KSI_TLV_TMPL_FLG_NONE, KSI_MetaDataElement_getMachineId, KSI_MetaDataElement_setMachineId, "machine_id")
	KSI_TLV_INTEGER(0x03, KSI_TLV_TMPL_FLG_NONE, KSI_MetaDataElement_getSequenceNr, KSI_MetaDataElement_setSequenceNr, "seq_nr")
	KSI_TLV_TIME_US(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_MetaDataElement_getRequestTimeInMicros, KSI_MetaDataElement_setRequestTimeInMicros, "req_time")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_HashChainLink)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_NONE, KSI_HashChainLink_getLevelCorrection, KSI_HashChainLink_setLevelCorrection, "level_correction")
	KSI_TLV_IMPRINT(0x02, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_HashChainLink_getImprint, KSI_HashChainLink_setImprint, "imprint")
	KSI_TLV_OBJECT(0x03, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_HashChainLink_getLegacyId, KSI_HashChainLink_setLegacyId, KSI_HashChainLink_LegacyId_fromTlv, KSI_HashChainLink_LegacyId_toTlv, KSI_OctetString_free, "legacy_id")
	KSI_TLV_COMPOSITE_OBJECT(0x04, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_HashChainLink_getMetaData, KSI_HashChainLink_setMetaData, KSI_MetaDataElement_fromTlv, KSI_MetaDataElement_toTlv, KSI_MetaDataElement_free, KSI_TLV_TEMPLATE(KSI_MetaDataElement), "meta_data")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_Header)
	KSI_TLV_UTF8_STRING(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Header_getLoginId, KSI_Header_setLoginId, "login_id")
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_NONE, KSI_Header_getInstanceId, KSI_Header_setInstanceId, "instance_id")
	KSI_TLV_INTEGER(0x03, KSI_TLV_TMPL_FLG_NONE, KSI_Header_getMessageId, KSI_Header_setMessageId, "message_id")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_Config)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Config_getMaxLevel, KSI_Config_setMaxLevel, "max_level")
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Config_getAggrAlgo, KSI_Config_setAggrAlgo, "aggr_algo")
	KSI_TLV_INTEGER(0x03, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Config_getAggrPeriod, KSI_Config_setAggrPeriod, "aggr_period")
	KSI_TLV_UTF8_STRING_LIST(0x04, KSI_TLV_TMPL_FLG_MANDATORY, KSI_Config_getParentUri, KSI_Config_setParentUri, "parent_uri")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationHashChain)
	KSI_TLV_TIME_S(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationHashChain_getAggregationTime, KSI_AggregationHashChain_setAggregationTime, "aggr_time")
	KSI_TLV_INTEGER_LIST(0x03, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationHashChain_getChainIndex, KSI_AggregationHashChain_setChainIndex, "chain_index")
	KSI_TLV_OCTET_STRING(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationHashChain_getInputData, KSI_AggregationHashChain_setInputData, "input_data")
	KSI_TLV_IMPRINT(0x05, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationHashChain_getInputHash, KSI_AggregationHashChain_setInputHash, "input_hash")
	KSI_TLV_INTEGER(0x06, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationHashChain_getAggrHashId, KSI_AggregationHashChain_setAggrHashId, "hash_id")
	KSI_TLV_OBJECT_LIST(0x07, KSI_TLV_TMPL_FLG_LEAST_ONE_G0, KSI_AggregationHashChain_getChain, KSI_AggregationHashChain_setChain, KSI_HashChainLink, "aggr_chain")
	KSI_TLV_OBJECT_LIST(0x08, KSI_TLV_TMPL_FLG_LEAST_ONE_G0 | KSI_TLV_TMPL_FLG_NO_SERIALIZE, KSI_AggregationHashChain_getChain, KSI_AggregationHashChain_setChain, KSI_HashChainLink, "aggr_chain")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_RFC3161)
	KSI_TLV_TIME_S(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RFC3161_getAggregationTime, KSI_RFC3161_setAggregationTime, "aggr_time")
	KSI_TLV_INTEGER_LIST(0x03, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RFC3161_getChainIndex, KSI_RFC3161_setChainIndex, "chain_index")
	KSI_TLV_IMPRINT(0x05, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RFC3161_getInputHash, KSI_RFC3161_setInputHash, "input_hash")

	KSI_TLV_OCTET_STRING(0x10, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RFC3161_getTstInfoPrefix, KSI_RFC3161_setTstInfoPrefix, "tst_info_prefix")
	KSI_TLV_OCTET_STRING(0x11, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RFC3161_getTstInfoSuffix, KSI_RFC3161_setTstInfoSuffix, "tst_info_suffix")
	KSI_TLV_INTEGER(0x12, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RFC3161_getTstInfoAlgo, KSI_RFC3161_setTstInfoAlgo, "tst_info_algo")

	KSI_TLV_OCTET_STRING(0x13, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RFC3161_getSigAttrPrefix, KSI_RFC3161_setSigAttrPrefix, "sig_attr_prefix")
	KSI_TLV_OCTET_STRING(0x14, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RFC3161_getSigAttrSuffix, KSI_RFC3161_setSigAttrSuffix, "sig_attr_suffix")
	KSI_TLV_INTEGER(0x15, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RFC3161_getSigAttrAlgo, KSI_RFC3161_setSigAttrAlgo, "sig_attr_algo")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationAuthRec)
	KSI_TLV_TIME_S(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationAuthRec_getAggregationTime, KSI_AggregationAuthRec_setAggregationTime, "aggr_time")
	KSI_TLV_INTEGER_LIST(0x03, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationAuthRec_getChainIndex, KSI_AggregationAuthRec_setChainIndex, "chain_index")
	KSI_TLV_IMPRINT(0x05, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationAuthRec_getInputHash, KSI_AggregationAuthRec_setInputHash, "input_hash")
	KSI_TLV_COMPOSITE(0x0b, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationAuthRec_getSigData, KSI_AggregationAuthRec_setSigData, KSI_AggrAuthRecPKISignedData, "signed_data")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_CalendarAuthRec)
	KSI_TLV_COMPOSITE_OBJECT(0x10, KSI_TLV_TMPL_FLG_FORWARD | KSI_TLV_TMPL_FLG_MANDATORY, KSI_CalendarAuthRec_getPublishedData, KSI_CalendarAuthRec_setPublishedData, KSI_PublicationData_fromTlv, KSI_PublicationData_toTlv, KSI_PublicationData_free, KSI_TLV_TEMPLATE(KSI_PublicationData), "pub_data")
	KSI_TLV_COMPOSITE(0x0b, KSI_TLV_TMPL_FLG_MANDATORY, KSI_CalendarAuthRec_getSignatureData, KSI_CalendarAuthRec_setSignatureData, KSI_CalAuthRecPKISignedData, "pki_signature")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationReq)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationReq_getRequestId, KSI_AggregationReq_setRequestId, "req_id")
	KSI_TLV_IMPRINT(0x02, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationReq_getRequestHash, KSI_AggregationReq_setRequestHash, "req_hash")
	KSI_TLV_INTEGER(0x03, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationReq_getRequestLevel, KSI_AggregationReq_setRequestLevel, "req_level")
	KSI_TLV_COMPOSITE(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationReq_getConfig, KSI_AggregationReq_setConfig, KSI_Config, "config")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_RequestAck)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RequestAck_getAggregationPeriod, KSI_RequestAck_setAggregationPeriod, "aggr_period")
	KSI_TLV_INTEGER(0x02, KSI_TLV_TMPL_FLG_MANDATORY, KSI_RequestAck_getAggregationDelay, KSI_RequestAck_setAggregationDelay, "aggr_delay")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_CalendarHashChain)
	KSI_TLV_TIME_S(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_CalendarHashChain_getPublicationTime, KSI_CalendarHashChain_setPublicationTime, "pub_time")
	KSI_TLV_TIME_S(0x02, KSI_TLV_TMPL_FLG_NONE, KSI_CalendarHashChain_getAggregationTime, KSI_CalendarHashChain_setAggregationTime, "aggr_time")
	KSI_TLV_IMPRINT(0x05, KSI_TLV_TMPL_FLG_MANDATORY, KSI_CalendarHashChain_getInputHash, KSI_CalendarHashChain_setInputHash, "input_hash")
	KSI_TLV_OBJECT_LIST(0x07, KSI_TLV_TMPL_FLG_LEAST_ONE_G0, KSI_CalendarHashChain_getHashChain, KSI_CalendarHashChain_setHashChain, KSI_CalendarHashChainLink, "chain")
	KSI_TLV_OBJECT_LIST(0x08, KSI_TLV_TMPL_FLG_LEAST_ONE_G0 | KSI_TLV_TMPL_FLG_NO_SERIALIZE, KSI_CalendarHashChain_getHashChain, KSI_CalendarHashChain_setHashChain, KSI_CalendarHashChainLink, "chain")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_ErrorPdu)
	KSI_TLV_INTEGER(0x04, KSI_TLV_TMPL_FLG_MANDATORY, KSI_ErrorPdu_getStatus, KSI_ErrorPdu_setStatus, "status")
	KSI_TLV_UTF8_STRING(0x05, KSI_TLV_TMPL_FLG_NONE, KSI_ErrorPdu_getErrorMessage, KSI_ErrorPdu_setErrorMessage, "err_message")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationResp)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_AggregationResp_getRequestId, KSI_AggregationResp_setRequestId, "req_id")
	KSI_TLV_INTEGER(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getStatus, KSI_AggregationResp_setStatus, "status")
	KSI_TLV_UTF8_STRING(0x05, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getErrorMsg, KSI_AggregationResp_setErrorMsg, "err_message")
	KSI_TLV_COMPOSITE(0x10, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getConfig, KSI_AggregationResp_setConfig, KSI_Config, "config")
	KSI_TLV_COMPOSITE(0x11, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getRequestAck, KSI_AggregationResp_setRequestAck, KSI_RequestAck, "req_ack")
	KSI_TLV_COMPOSITE_LIST(0x0801, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getAggregationChainList, KSI_AggregationResp_setAggregationChainList, KSI_AggregationHashChain, "aggr_chain")
	KSI_TLV_COMPOSITE(0x0802, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getCalendarChain, KSI_AggregationResp_setCalendarChain, KSI_CalendarHashChain, "cal_chain")
	KSI_TLV_COMPOSITE(0x0804, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getAggregationAuthRec, KSI_AggregationResp_setAggregationAuthRec, KSI_AggregationAuthRec, "aggr_auth_rec") /* TODO! Future work. */
	KSI_TLV_COMPOSITE(0x0805, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationResp_getCalendarAuthRec, KSI_AggregationResp_setCalendarAuthRec, KSI_CalendarAuthRec, "cal_auth_rec")

KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_AggregationPdu)
	KSI_TLV_OBJECT(0x01, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationPdu_getHeader, KSI_AggregationPdu_setHeader, KSI_Header_fromTlv, KSI_Header_toTlv, KSI_Header_free, "header")
	KSI_TLV_OBJECT(0x201, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_AggregationPdu_getRequest, KSI_AggregationPdu_setRequest, KSI_AggregationReq_fromTlv, KSI_AggregationReq_toTlv, KSI_AggregationReq_free, "aggr_req")
	KSI_TLV_OBJECT(0x202, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_AggregationPdu_getResponse, KSI_AggregationPdu_setResponse, KSI_AggregationResp_fromTlv, KSI_AggregationResp_toTlv, KSI_AggregationResp_free, "aggr_resp")
	KSI_TLV_COMPOSITE(0x203, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_AggregationPdu_getError, KSI_AggregationPdu_setError, KSI_ErrorPdu, "aggr_error_pdu")
	KSI_TLV_IMPRINT(0x1F, KSI_TLV_TMPL_FLG_NONE, KSI_AggregationPdu_getHmac, KSI_AggregationPdu_setHmac, "hmac")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_ExtendReq)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_ExtendReq_getRequestId, KSI_ExtendReq_setRequestId, "req_id")
	KSI_TLV_TIME_S(0x02, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendReq_getAggregationTime, KSI_ExtendReq_setAggregationTime, "aggr_time")
	KSI_TLV_TIME_S(0x03, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendReq_getPublicationTime, KSI_ExtendReq_setPublicationTime, "pub_time")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_ExtendResp)
	KSI_TLV_INTEGER(0x01, KSI_TLV_TMPL_FLG_MANDATORY, KSI_ExtendResp_getRequestId, KSI_ExtendResp_setRequestId, "req_id")
	KSI_TLV_INTEGER(0x04, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendResp_getStatus, KSI_ExtendResp_setStatus, "status")
	KSI_TLV_UTF8_STRING(0x05, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendResp_getErrorMsg, KSI_ExtendResp_setErrorMsg, "err_message")
	KSI_TLV_TIME_S(0x10, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendResp_getLastTime, KSI_ExtendResp_setLastTime, "last_time")
	KSI_TLV_COMPOSITE(0x802, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendResp_getCalendarHashChain, KSI_ExtendResp_setCalendarHashChain, KSI_CalendarHashChain, "cal_hash_chain")
KSI_END_TLV_TEMPLATE

KSI_DEFINE_TLV_TEMPLATE(KSI_ExtendPdu)
	KSI_TLV_COMPOSITE_OBJECT(0x01, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendPdu_getHeader, KSI_ExtendPdu_setHeader, KSI_Header_fromTlv, KSI_Header_toTlv, KSI_Header_free, KSI_TLV_TEMPLATE(KSI_Header), "header")
	KSI_TLV_COMPOSITE_OBJECT(0x301, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_ExtendPdu_getRequest, KSI_ExtendPdu_setRequest, KSI_ExtendReq_fromTlv, KSI_ExtendReq_toTlv, KSI_ExtendReq_free, KSI_TLV_TEMPLATE(KSI_ExtendReq), "ext_req")
	KSI_TLV_COMPOSITE_OBJECT(0x302, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_ExtendPdu_getResponse, KSI_ExtendPdu_setResponse, KSI_ExtendResp_fromTlv, KSI_ExtendResp_toTlv, KSI_ExtendResp_free, KSI_TLV_TEMPLATE(KSI_ExtendResp), "ext_resp")
	KSI_TLV_COMPOSITE(0x303, KSI_TLV_TMPL_FLG_MANTATORY_MOST_ONE_G0, KSI_ExtendPdu_getError, KSI_ExtendPdu_setError, KSI_ErrorPdu, "ext_error_resp")
	KSI_TLV_IMPRINT(0x1F, KSI_TLV_TMPL_FLG_NONE, KSI_ExtendPdu_getHmac, KSI_ExtendPdu_setHmac, "hmac")
KSI_END_TLV_TEMPLATE

static char *track_str(struct tlv_track_s *tr, size_t tr_len, size_t tr_size, char *buf, size_t buf_len) {
	size_t len = 0;
	size_t i;

	/* Make sure, the return value is null-terminated. */
	buf[0] = '\0';

	/* Generate the printable result string, by separating values with "->" */
	for (i = 0; i < tr_len && i < tr_size; i++) {
		if (i != 0) len += KSI_snprintf(buf + len, buf_len - len, "->");
		len += KSI_snprintf(buf + len, buf_len - len, "[0x%02x]%s", tr[i].tag, tr[i].desc != NULL ? tr[i].desc : "");
	}

	/* Just in case the buffer was too short, but in real life, this should not happen with correct KSI objects. */
	if (tr_len >= tr_size) {
		KSI_snprintf(buf + len, buf_len - len, "->...");
	}

	return buf;
}

static int storeObjectValue(KSI_CTX *ctx, const KSI_TlvTemplate *tmpl, void *payload, void *val) {
	int res = KSI_UNKNOWN_ERROR;
	void *list = NULL;
	void *listp = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || tmpl == NULL || payload == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* Verify the correctness of the template. */
	if (tmpl->setValue == NULL) {
		KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Invalid template - missing setValue function.");
		goto cleanup;
	}

	if (tmpl->listAppend != NULL) {
		if (tmpl->getValue == NULL) {
			KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Invalid template - missing getValue function.");
			goto cleanup;
		}
		res = tmpl->getValue(payload, &listp);
		if (res != KSI_OK) goto cleanup;

		if (listp == NULL) {
			/* Make sure we have required function pointers. */
			if (tmpl->listNew == NULL || tmpl->listFree == NULL) {
				KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Template does not have list constructor or destructor, but list itself does not exist.");
				goto cleanup;
			}
			res = tmpl->listNew(&list);
			if (res != KSI_OK) {
				KSI_pushError(ctx, res, NULL);
				goto cleanup;
			}

			listp = list;
		}

		res = tmpl->listAppend(listp, (void *) val);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		res = tmpl->setValue(payload, listp);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		list = NULL;

	} else {
		/* Regular value - store with the setter. */
		res = tmpl->setValue(payload, (void *) val);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	res = KSI_OK;

cleanup:

	KSI_nofree(listp);
	if (tmpl != NULL && tmpl->listFree != NULL) tmpl->listFree(list);

	return res;
}

typedef struct TLVListIterator_st {
	KSI_LIST(KSI_TLV) *list;
	size_t idx;
} TLVListIterator;

static int TLVListIterator_next(TLVListIterator *iter, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *next = NULL;

	if (iter == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (iter->idx < KSI_TLVList_length(iter->list)) {
		res = KSI_TLVList_elementAt(iter->list, iter->idx, &next);
		if (res != KSI_OK) goto cleanup;

		iter->idx++;
	}

	*tlv = next;

	res = KSI_OK;

cleanup:

	return res;
}

static int extract(KSI_CTX *ctx, void *payload, KSI_TLV *tlv, const KSI_TlvTemplate *tmpl, struct tlv_track_s *tr, size_t tr_len, size_t tr_size) {
	int res = KSI_UNKNOWN_ERROR;
	int tr_inc = 0;
	TLVListIterator iter;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || payload == NULL || tlv == NULL || tmpl == NULL || tr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_getNestedList(tlv, &iter.list);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	iter.idx = 0;

	/* When extracting second tlv there is no need to register it twice because it is mention in lower level. */
	if (tr_len == 0) {
		tr[tr_len].tag = KSI_TLV_getTag(tlv);
		tr[tr_len].desc = NULL;
		tr_inc = 1;
	}

	res = extractGenerator(ctx, payload, (void *)&iter, tmpl, (int (*)(void *, KSI_TLV **))TLVListIterator_next, tr, tr_len + tr_inc, tr_size);
	if (res != KSI_OK) {
		char buf[1024];
		KSI_LOG_debug(ctx, "Unable to parse TLV: %s", track_str(tr, tr_len, tr_size, buf, sizeof(buf)));
		KSI_pushError(ctx, res, buf);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;

}

int KSI_TlvTemplate_extract(KSI_CTX *ctx, void *payload, KSI_TLV *tlv, const KSI_TlvTemplate *tmpl) {
	int res = KSI_UNKNOWN_ERROR;
	struct tlv_track_s tr[0xf];

	res = extract(ctx, payload, tlv, tmpl, tr, 0, sizeof(tr));
	if (res != KSI_OK) {
		KSI_LOG_logTlv(ctx, KSI_LOG_DEBUG, "Parsed tlv at failure", tlv);
	}
	return res;
}

int KSI_TlvTemplate_parse(KSI_CTX *ctx, const unsigned char *raw, size_t raw_len, const KSI_TlvTemplate *tmpl, void *payload) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tlv = NULL;
	struct tlv_track_s tr[0xf];

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || raw == NULL || tmpl == NULL || payload == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_parseBlob2(ctx, (unsigned char *)raw, raw_len, 0, &tlv);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = extract(ctx, payload, tlv, tmpl, tr, 0, sizeof(tr));
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tlv);

	return res;
}

static size_t getTemplateLength(const KSI_TlvTemplate *tmpl) {
	const KSI_TlvTemplate *tmp = NULL;
	size_t len = 0;

	/* Count the number of templates. */
	tmp = tmpl;
	while (tmp != NULL && tmp++->tag) ++len;

	return len;
}

static int extractObject(KSI_CTX *ctx, const KSI_TlvTemplate *tmpl, void *payload, KSI_TLV *tlv) {
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *raw = NULL;
	size_t len;
	void *tmp = NULL;

	if (tmpl->fromTlv == NULL && tmpl->parser == NULL) {
		KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR,
				"Invalid template: no method for converting from tlv to object.");
		goto cleanup;
	}

	/* Parse the object. */
	if (tmpl->parser != NULL) {
		res = KSI_TLV_getRawValue(tlv, (const unsigned char **) &raw, &len);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		res = tmpl->parser(ctx, raw, len, tmpl->parser_opt, &tmp);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	} else {
		res = tmpl->fromTlv(tlv, &tmp);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	}

	res = storeObjectValue(ctx, tmpl, payload, tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp = NULL;

	res = KSI_OK;

cleanup:

	tmpl->destruct(tmp);

	return res;
}

static int extractComposite(KSI_CTX *ctx, const KSI_TlvTemplate *tmpl, void *payload, KSI_TLV *tlv, struct tlv_track_s *tr, size_t tr_len, size_t tr_size) {
	int res = KSI_UNKNOWN_ERROR;
	char buf[1024];
	void *tmp = NULL;

	res = tmpl->construct(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = extract(ctx, tmp, tlv, tmpl->subTemplate, tr, tr_len + 1, tr_size);
	if (res != KSI_OK) {
		KSI_LOG_debug(ctx, "Unable to parse composite TLV: %s", track_str(tr, tr_len, tr_size, buf, sizeof(buf)));
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = storeObjectValue(ctx, tmpl, payload, (void *)tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	tmp = NULL;

	res = KSI_OK;

cleanup:

	tmpl->destruct(tmp);

	return res;
}

static int extractGenerator(KSI_CTX *ctx, void *payload, void *generatorCtx, const KSI_TlvTemplate *tmpl, int (*generator)(void *, KSI_TLV **), struct tlv_track_s *tr, size_t tr_len, size_t tr_size) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tlv = NULL;
	char buf[1024];

	void *valuep = NULL;
	KSI_TLV *tlvVal = NULL;

	size_t template_len = 0;
	bool templateHit[MAX_TEMPLATE_SIZE];
	bool groupHit[2] = {false, false};
	bool oneOf[2] = {false, false};
	size_t i;
	size_t tmplStart = 0;
	size_t maxOrder = 0;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || payload == NULL || generatorCtx == NULL || tmpl == NULL || generator == NULL || tr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* Analyze the template. */
	template_len = getTemplateLength(tmpl);

	if (template_len == 0) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Empty template suggests invalid state.");
		goto cleanup;
	}

	/* Make sure there will be no buffer overflow. */
	if (template_len > MAX_TEMPLATE_SIZE) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Template too big");
		goto cleanup;
	}
	memset(templateHit, 0, sizeof(templateHit));

	for (;;) {
		int matchCount = 0;
		res = generator(generatorCtx, &tlv);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (tlv == NULL) break;

		if (tr_len < tr_size) {
			tr[tr_len].tag = KSI_TLV_getTag(tlv);
			tr[tr_len].desc = NULL;
		}

		for (i = tmplStart; i < template_len; i++) {
			if (tmpl[i].tag != KSI_TLV_getTag(tlv)) continue;
			if (i == tmplStart && !tmpl[i].multiple) tmplStart++;

			tr[tr_len].desc = tmpl[i].descr;

			matchCount++;
			templateHit[i] = true;
			if (IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_LEAST_ONE_G0)) groupHit[0] = true;
			if (IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_LEAST_ONE_G1)) groupHit[1] = true;
			if (IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_FIXED_ORDER)) {
				if (i < maxOrder) {
					KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Element at wrong position.");
					goto cleanup;
				}
				maxOrder = i;
			}

			if (IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_MOST_ONE_G0)) {
				if (oneOf[0]) {
					KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Mutually exclusive elements present within group 0.");
					goto cleanup;
				}
				oneOf[0] = true;
			}

			if (IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_MOST_ONE_G1)) {
				if (oneOf[1]) {
					KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Mutually exclusive elements present within group 0.");
					goto cleanup;
				}
				oneOf[1] = true;
			}

			valuep = NULL;
			if (tmpl[i].getValue != NULL) {
				/* Validate the value has not been set */
				res = tmpl[i].getValue(payload, (void **)&valuep);
				if (res != KSI_OK) {
					KSI_pushError(ctx, res, NULL);
					goto cleanup;
				}
			}

			if (valuep != NULL && !tmpl[i].multiple) {
				KSI_LOG_debug(ctx, "Multiple occurrences of a unique tag 0x%02x", tmpl[i].tag);
				KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "To avoid memory leaks, a value may not be set more than once while parsing.");
				goto cleanup;
			}
			/* Parse the current TLV */
			switch (tmpl[i].type) {
				case KSI_TLV_TEMPLATE_OBJECT:
					res = extractObject(ctx, &tmpl[i], payload, tlv);
					if (res != KSI_OK) {
						KSI_pushError(ctx, res, NULL);
						goto cleanup;
					}
					break;
				case KSI_TLV_TEMPLATE_COMPOSITE:

					res = extractComposite(ctx, &tmpl[i], payload, tlv, tr, tr_len, tr_size);
					if (res != KSI_OK) {
						KSI_pushError(ctx, res, NULL);
						goto cleanup;
					}
					break;
				default:
					KSI_LOG_error(ctx, "No template found - this might be caused by memory corruption.");
					/* Should not happen, but just in case. */
					KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Undefined template type");
					goto cleanup;
			}

			if ((tmpl[i].flags & KSI_TLV_TMPL_FLG_MORE_DEFS) == 0) break;
		}

		/* Check if a match was found, an raise an error if the TLV is marked as critical. */
		if (matchCount == 0 && !KSI_TLV_isNonCritical(tlv)) {
			char errm[1024];
			KSI_snprintf(errm, sizeof(errm), "Unknown critical tag: %s", track_str(tr, tr_len + 1, tr_size, buf, sizeof(buf)));
			KSI_LOG_debug(ctx, errm);
			KSI_pushError(ctx, res = KSI_INVALID_FORMAT, errm);
			goto cleanup;
		}
	}

	/* Check that every mandatory component was present. */
	for (i = 0; i < template_len; i++) {
		char errm[100];
		if ((tmpl[i].flags & KSI_TLV_TMPL_FLG_MANDATORY) != 0 && !templateHit[i]) {
			KSI_snprintf(errm, sizeof(errm), "Mandatory element missing: %s->[0x%x]%s", track_str(tr, tr_len, tr_size, buf, sizeof(buf)), tmpl[i].tag, tmpl[i].descr != NULL ? tmpl[i].descr : "");
			KSI_LOG_debug(ctx, "%s", errm);
			KSI_pushError(ctx, res = KSI_INVALID_FORMAT, errm);
			goto cleanup;
		}
		if (((tmpl[i].flags & KSI_TLV_TMPL_FLG_LEAST_ONE_G0) != 0 && !groupHit[0]) ||
				((tmpl[i].flags & KSI_TLV_TMPL_FLG_LEAST_ONE_G1) != 0 && !groupHit[1])) {
			KSI_snprintf(errm, sizeof(errm), "Mandatory group missing: %s->[0x%x]%s", track_str(tr, tr_len, tr_size, buf, sizeof(buf)), tmpl[i].tag, tmpl[i].descr != NULL ? tmpl[i].descr : "");
			KSI_LOG_debug(ctx, "%s", errm);
			KSI_pushError(ctx, res = KSI_INVALID_FORMAT, errm);
			goto cleanup;
		}
	}

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tlvVal);

	return res;
}

int KSI_TlvTemplate_extractGenerator(KSI_CTX *ctx, void *payload, void *generatorCtx, const KSI_TlvTemplate *tmpl, int (*generator)(void *, KSI_TLV **)) {
	struct tlv_track_s buf[0xf];
	return extractGenerator(ctx, payload, generatorCtx, tmpl, generator, buf, 0, sizeof(buf));
}

static int construct(KSI_CTX *ctx, KSI_TLV *tlv, const void *payload, const KSI_TlvTemplate *tmpl, struct tlv_track_s *tr, size_t tr_len, const size_t tr_size) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tmp = NULL;
	void *payloadp = NULL;
	int isNonCritical = 0;
	int isForward = 0;

	size_t template_len = 0;
	bool templateHit[MAX_TEMPLATE_SIZE];
	bool groupHit[2] = {false, false};
	bool oneOf[2] = {false, false};

	size_t i;
	char buf[1000];

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || tlv == NULL || payload == NULL || tmpl == NULL || tr == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* Calculate the template length. */
	template_len = getTemplateLength(tmpl);

	if (template_len == 0) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "A template may not be empty.");
		goto cleanup;
	}

	if (template_len > MAX_TEMPLATE_SIZE) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Template too big.");
		goto cleanup;
	}

	memset(templateHit, 0, sizeof(templateHit));


	for (i = 0; i < template_len; i++) {
		if (IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_NO_SERIALIZE)) continue;
		payloadp = NULL;

		res = tmpl[i].getValue(payload, &payloadp);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}

		if (payloadp != NULL) {
			/* Register for tracking. */
			if (tr_len < tr_size) {
				tr[tr_len].tag = tmpl[i].tag;
				tr[tr_len].desc = tmpl[i].descr;
			}

			templateHit[i] = true;

			if (IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_LEAST_ONE_G0)) {
				if (tmpl[i].listLength != NULL && tmpl[i].listLength(payloadp) == 0) {
					KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Mandatory list object is empty within group 0.");
					goto cleanup;
				}
				groupHit[0] = true;
			}
			if (IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_LEAST_ONE_G1)) {
				if (tmpl[i].listLength != NULL && tmpl[i].listLength(payloadp) == 0) {
					KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Mandatory list object is empty within group 1.");
					goto cleanup;
				}
				groupHit[1] = true;
			}

			if (IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_MOST_ONE_G0)) {
				if (oneOf[0]) {
					char errm[1000];
					KSI_snprintf(errm, sizeof(errm), "Mutually exclusive elements present within group 0 (%s).", track_str(tr, tr_len, tr_size, buf, sizeof(buf)));
					KSI_pushError(ctx, res = KSI_INVALID_FORMAT, errm);
					goto cleanup;
				}
				if ((tmpl[i].listLength == NULL) || (tmpl[i].listLength != NULL && tmpl[i].listLength(payloadp) > 0)) {
					oneOf[0] = true;
				}
			}
			if (IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_MOST_ONE_G1)) {
				if (oneOf[1]) {
					char errm[1000];
					KSI_snprintf(errm, sizeof(errm), "Mutually exclusive elements present within group 1 (%s).", track_str(tr, tr_len, tr_size, buf, sizeof(buf)));
					KSI_pushError(ctx, res = KSI_INVALID_FORMAT, errm);
					goto cleanup;
				}
				if ((tmpl[i].listLength == NULL) || (tmpl[i].listLength != NULL && tmpl[i].listLength(payloadp) > 0)) {
					oneOf[1] = true;
				}
			}

			isNonCritical = IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_NONCRITICAL);
			isForward = IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_FORWARD);

			switch (tmpl[i].type) {
				case KSI_TLV_TEMPLATE_OBJECT:
					if (tmpl[i].toTlv == NULL) {
						KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Invalid template: toTlv not set.");
						goto cleanup;
					}

					if (tmpl[i].listLength != NULL) {
						int j;
						for (j = 0; j < tmpl[i].listLength(payloadp); j++) {
							void *listElement = NULL;
							res = tmpl[i].listElementAt(payloadp, j, &listElement);
							if (res != KSI_OK) {
								KSI_pushError(ctx, res, NULL);
								goto cleanup;
							}

							res = tmpl[i].toTlv(ctx, listElement, tmpl[i].tag, isNonCritical, isForward != 0, &tmp);
							if (res != KSI_OK) {
								KSI_pushError(ctx, res, NULL);
								goto cleanup;
							}

							res = KSI_TLV_appendNestedTlv(tlv, tmp);
							if (res != KSI_OK) {
								KSI_pushError(ctx, res, NULL);
								goto cleanup;
							}

							tmp = NULL;
						}


					} else {
						res = tmpl[i].toTlv(ctx, payloadp, tmpl[i].tag, isNonCritical, isForward, &tmp);
						if (res != KSI_OK) {
							KSI_pushError(ctx, res, NULL);
							goto cleanup;
						}

						res = KSI_TLV_appendNestedTlv(tlv, tmp);
						if (res != KSI_OK) {
							KSI_pushError(ctx, res, NULL);
							goto cleanup;
						}
						tmp = NULL;
					}

					break;
				case KSI_TLV_TEMPLATE_COMPOSITE:
					if (tmpl[i].listLength != NULL) {
						int j;

						for (j = 0; j < tmpl[i].listLength(payloadp); j++) {
							void *listElement = NULL;

							res = KSI_TLV_new(ctx, tmpl[i].tag, isNonCritical, isForward, &tmp);
							if (res != KSI_OK) {
								KSI_pushError(ctx, res, NULL);
								goto cleanup;
							}

							res = tmpl[i].listElementAt(payloadp, j, &listElement);
							if (res != KSI_OK) {
								KSI_pushError(ctx, res, NULL);
								goto cleanup;
							}

							res = construct(ctx, tmp, listElement, tmpl[i].subTemplate, tr, tr_len + 1, tr_size);
							if (res != KSI_OK) {
								KSI_pushError(ctx, res, NULL);
								goto cleanup;
							}

							res = KSI_TLV_appendNestedTlv(tlv, tmp);
							if (res != KSI_OK) {
								KSI_pushError(ctx, res, NULL);
								goto cleanup;
							}
							tmp = NULL;
						}
					} else {
						res = KSI_TLV_new(ctx, tmpl[i].tag, isNonCritical, isForward, &tmp);
						if (res != KSI_OK) {
							KSI_pushError(ctx, res, NULL);
							goto cleanup;
						}

						res = construct(ctx, tmp, payloadp, tmpl[i].subTemplate, tr, tr_len + 1, tr_size);
						if (res != KSI_OK) {
							KSI_pushError(ctx, res, NULL);
							goto cleanup;
						}

						res = KSI_TLV_appendNestedTlv(tlv, tmp);
						if (res != KSI_OK) {
							KSI_pushError(ctx, res, NULL);
							goto cleanup;
						}
						tmp = NULL;
					}
					break;
				default:
					KSI_LOG_error(ctx, "Unimplemented template type: %d - possible MEMORY CURRUPTION.", tmpl[i].type);
					KSI_pushError(ctx, res = KSI_UNKNOWN_ERROR, "Unimplemented template type.");
					goto cleanup;
			}
		}
	}

	/* Check that every mandatory component was present. */
	for (i = 0; i < template_len; i++) {
		char errm[1000];
		if (IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_MANDATORY) && !templateHit[i]) {
			KSI_snprintf(errm, sizeof(errm), "Mandatory element missing: %s->[0x%02x]%s", track_str(tr, tr_len, tr_size, buf, sizeof(buf)), tmpl[i].tag, tmpl[i].descr == NULL ? "" : tmpl[i].descr);
			KSI_LOG_debug(ctx, "%s", errm);
			KSI_pushError(ctx, res = KSI_INVALID_FORMAT, errm);
			goto cleanup;
		}
		if ((IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_LEAST_ONE_G0) && !groupHit[0]) ||
				(IS_FLAG_SET(tmpl[i], KSI_TLV_TMPL_FLG_LEAST_ONE_G1) && !groupHit[1])) {
			KSI_snprintf(errm, sizeof(errm), "Mandatory group missing: %s->[0x%02x]%s", track_str(tr, tr_len, tr_size, buf, sizeof(buf)), tmpl[i].tag, tmpl[i].descr == NULL ? "" : tmpl[i].descr);
			KSI_LOG_debug(ctx, "%s", errm);
			KSI_pushError(ctx, res = KSI_INVALID_FORMAT, errm);
			goto cleanup;
		}
	}

	res = KSI_OK;

cleanup:

	KSI_nofree(payloadp);

	KSI_TLV_free(tmp);

	return res;
}

int KSI_TlvTemplate_construct(KSI_CTX *ctx, KSI_TLV *tlv, const void *payload, const KSI_TlvTemplate *tmpl) {
	struct tlv_track_s tr[0xf];
	return construct(ctx, tlv, payload, tmpl, tr, 0, sizeof(tr));
}

int KSI_TlvTemplate_serializeObject(KSI_CTX *ctx, const void *obj, unsigned tag, int isNc, int isFwd, const KSI_TlvTemplate *tmpl, unsigned char **raw, size_t *raw_len) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tlv = NULL;
	unsigned char *tmp = NULL;
	size_t tmp_len = 0;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || obj == NULL || tmpl == NULL || raw == NULL || raw_len == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* Create TLV for the PDU object. */
	res = KSI_TLV_new(ctx, tag, isNc, isFwd, &tlv);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Evaluate the TLV. */
	res = KSI_TlvTemplate_construct(ctx, tlv, obj, tmpl);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Serialize the TLV. */
	res = KSI_TLV_serialize(tlv, &tmp, &tmp_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*raw = tmp;
	tmp = NULL;
	*raw_len = tmp_len;

	res = KSI_OK;

cleanup:

	KSI_free(tmp);
	KSI_TLV_free(tlv);

	return res;
}

int KSI_TlvTemplate_writeBytes(KSI_CTX *ctx, const void *obj, unsigned tag, int isNc, int isFwd, const KSI_TlvTemplate *tmpl, unsigned char *raw, size_t raw_size, size_t *raw_len, int opt) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tlv = NULL;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || obj == NULL || tmpl == NULL || (raw == NULL && raw_size != 0) || raw_len == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	/* Create TLV for the PDU object. */
	res = KSI_TLV_new(ctx, tag, isNc, isFwd, &tlv);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Evaluate the TLV. */
	res = KSI_TlvTemplate_construct(ctx, tlv, obj, tmpl);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Serialize the TLV. */
	res = KSI_TLV_writeBytes(tlv, raw, raw_size, raw_len, opt);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tlv);

	return res;
}

