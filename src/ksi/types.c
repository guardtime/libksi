#include <string.h>

#include "internal.h"
#include "tlv.h"

KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationPdu)
KSI_IMPORT_TLV_TEMPLATE(KSI_Header);
KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendReq);
KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendResp);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationReq);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationResp);
KSI_IMPORT_TLV_TEMPLATE(KSI_MetaData);

struct KSI_MetaData_st {
	KSI_CTX *ctx;
	KSI_OctetString *raw;
	KSI_Utf8String *clientId;
	KSI_OctetString *machineId;
	KSI_Integer *sequenceNr;
	KSI_Integer *req_time_micros;
};

struct KSI_ExtendPdu_st {
	KSI_CTX *ctx;
	KSI_Header *header;
	KSI_ExtendReq *request;
	KSI_ExtendResp *response;
	KSI_DataHash *hmac;
	KSI_TLV *headerTLV;
	KSI_TLV *payloadTLV;
};

struct KSI_AggregationPdu_st {
	KSI_CTX *ctx;
	KSI_Header *header;
	KSI_AggregationReq *request;
	KSI_AggregationResp *response;
	KSI_DataHash *hmac;
	KSI_TLV *headerTLV;
	KSI_TLV *payloadTLV;
};

struct KSI_Header_st {
	KSI_CTX *ctx;
	KSI_Integer *instanceId;
	KSI_Integer *messageId;
	KSI_OctetString *loginId;
};

struct KSI_Config_st {
	KSI_CTX *ctx;
	KSI_Integer *maxLevel;
	KSI_Integer *aggrAlgo;
	KSI_Integer *aggrPeriod;
	KSI_LIST(KSI_Utf8String) *parentUri;
};

struct KSI_AggregationReq_st {
	KSI_CTX *ctx;
	KSI_Integer *requestId;
	KSI_DataHash *requestHash;
	KSI_Integer *requestLevel;
	KSI_Config *config;
};

struct KSI_RequestAck_st {
	KSI_CTX *ctx;
	KSI_Integer *aggregationPeriod;
	KSI_Integer *aggregationDelay;
};

struct KSI_AggregationResp_st {
	KSI_CTX *ctx;
	KSI_Integer *requestId;
	KSI_Integer *status;
	KSI_Utf8String *errorMsg;
	KSI_Config *config;
	KSI_RequestAck *requestAck;
	KSI_CalendarHashChain *calendarChain;
	KSI_LIST(KSI_AggregationHashChain) *aggregationChainList;
	KSI_CalendarAuthRec *calendarAuthRec;
	KSI_AggregationAuthRec *aggregationAuthRec;
	KSI_TLV *baseTlv;
};

struct KSI_ExtendReq_st {
	KSI_CTX *ctx;
	KSI_Integer *requestId;
	KSI_Integer *aggregationTime;
	KSI_Integer *publicationTime;
};

struct KSI_ExtendResp_st {
	KSI_CTX *ctx;
	KSI_Integer *requestId;
	KSI_Integer *status;
	KSI_Utf8String *errorMsg;
	KSI_Integer *lastTime;
	KSI_CalendarHashChain *calendarHashChain;
	KSI_TLV *baseTlv;
};

struct KSI_PKISignedData_st {
	KSI_CTX *ctx;
	KSI_OctetString *signatureValue;
	KSI_OctetString *certId;
	KSI_PKICertificate *cert;
	KSI_Utf8String *certRepositoryUri;
};

struct KSI_PublicationsHeader_st {
	KSI_CTX *ctx;
	KSI_Integer *version;
	KSI_Integer *timeCreated_s;
	KSI_Utf8String *repositoryUri;
};

struct KSI_CertificateRecord_st {
	KSI_CTX *ctx;
	KSI_OctetString *certId;
	KSI_PKICertificate *cert;
};

KSI_IMPLEMENT_LIST(KSI_MetaData, KSI_MetaData_free);
KSI_IMPLEMENT_LIST(KSI_ExtendPdu, KSI_ExtendPdu_free);
KSI_IMPLEMENT_LIST(KSI_AggregationPdu, KSI_AggregationPdu_free);
KSI_IMPLEMENT_LIST(KSI_Header, KSI_Header_free);
KSI_IMPLEMENT_LIST(KSI_Config, KSI_Config_free);
KSI_IMPLEMENT_LIST(KSI_AggregationReq, KSI_AggregationReq_free);
KSI_IMPLEMENT_LIST(KSI_RequestAck, KSI_RequestAck_free);
KSI_IMPLEMENT_LIST(KSI_AggregationResp, KSI_AggregationResp_free);
KSI_IMPLEMENT_LIST(KSI_ExtendReq, KSI_ExtendReq_free);
KSI_IMPLEMENT_LIST(KSI_ExtendResp, KSI_ExtendResp_free);
KSI_IMPLEMENT_LIST(KSI_PKISignedData, KSI_PKISignedData_free);
KSI_IMPLEMENT_LIST(KSI_PublicationsHeader, KSI_PublicationsHeader_free);
KSI_IMPLEMENT_LIST(KSI_CertificateRecord, KSI_CertificateRecord_free);

/**
 * KSI_MetaData
 */
void KSI_MetaData_free(KSI_MetaData *t) {
	if(t != NULL) {
		KSI_OctetString_free(t->raw);
		KSI_Utf8String_free(t->clientId);
		KSI_OctetString_free(t->machineId);
		KSI_Integer_free(t->sequenceNr);
		KSI_Integer_free(t->req_time_micros);
		KSI_free(t);
	}
}

int KSI_MetaData_new(KSI_CTX *ctx, KSI_MetaData **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MetaData *tmp = NULL;
	tmp = KSI_new(KSI_MetaData);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->raw = NULL;
	tmp->clientId = NULL;
	tmp->machineId = NULL;
	tmp->sequenceNr = NULL;
	tmp->req_time_micros = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_MetaData_free(tmp);
	return res;
}

int KSI_MetaData_toTlv(KSI_CTX *ctx, const KSI_MetaData *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	KSI_ERR err;
	int res;
	KSI_TLV *tmp = NULL;
	unsigned char *raw = NULL;
	unsigned int raw_len = 0;

	KSI_PRE(&err, data != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_TLV, tag, isNonCritical, isForward, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_construct(ctx, tmp, data, KSI_TLV_TEMPLATE(KSI_MetaData));
	KSI_CATCH(&err, res) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(raw);
	KSI_TLV_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_MetaData_fromTlv(KSI_TLV *tlv, KSI_MetaData **metaData) {
	KSI_ERR err;
	int res;
	KSI_MetaData *tmp = NULL;
	int isLeft = 0;
	unsigned char *tlvData = NULL;
	unsigned len;
	KSI_OctetString *raw = NULL;
	KSI_CTX *ctx = KSI_TLV_getCtx(tlv);
	
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, metaData != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	
	if(KSI_TLV_getTag(tlv) != 0x04){
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_MetaData_new(KSI_TLV_getCtx(tlv), &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TlvTemplate_extract(KSI_TLV_getCtx(tlv), tmp, tlv, KSI_TLV_TEMPLATE(KSI_MetaData));
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_TLV_serialize(tlv, &tlvData, &len);
	KSI_CATCH(&err, res) goto cleanup;
	
	res = KSI_OctetString_new(ctx, tlvData+2, len-2, &raw);
	KSI_CATCH(&err, res) goto cleanup;
			
	tmp->raw = raw;
	*metaData = tmp;
	
	raw = NULL;
	tmp = NULL;
	KSI_SUCCESS(&err);

cleanup:

	KSI_MetaData_free(tmp);
	KSI_free(tlvData);
	KSI_OctetString_free(raw);
	return KSI_RETURN(&err);
}

KSI_IMPLEMENT_GETTER(KSI_MetaData, KSI_OctetString*, raw, Raw);
KSI_IMPLEMENT_GETTER(KSI_MetaData, KSI_Utf8String*, clientId, ClientId);
KSI_IMPLEMENT_GETTER(KSI_MetaData, KSI_OctetString*, machineId, MachineId);
KSI_IMPLEMENT_GETTER(KSI_MetaData, KSI_Integer*, sequenceNr, SequenceNr);
KSI_IMPLEMENT_GETTER(KSI_MetaData, KSI_Integer*, req_time_micros, RequestTimeInMicros);

KSI_IMPLEMENT_SETTER(KSI_MetaData, KSI_OctetString*, raw, Raw);
KSI_IMPLEMENT_SETTER(KSI_MetaData, KSI_Utf8String*, clientId, ClientId);
KSI_IMPLEMENT_SETTER(KSI_MetaData, KSI_OctetString*, machineId, MachineId);
KSI_IMPLEMENT_SETTER(KSI_MetaData, KSI_Integer*, sequenceNr, SequenceNr);
KSI_IMPLEMENT_SETTER(KSI_MetaData, KSI_Integer*, req_time_micros, RequestTimeInMicros);

/**
 * KSI_ExtendPdu
 */
void KSI_ExtendPdu_free(KSI_ExtendPdu *t) {
	if(t != NULL) {
		KSI_Header_free(t->header);
		KSI_ExtendReq_free(t->request);
		KSI_ExtendResp_free(t->response);
		KSI_DataHash_free(t->hmac);
		KSI_TLV_free(t->headerTLV);
		KSI_TLV_free(t->payloadTLV);
		KSI_free(t);
	}
}

int KSI_ExtendPdu_new(KSI_CTX *ctx, KSI_ExtendPdu **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendPdu *tmp = NULL;
	tmp = KSI_new(KSI_ExtendPdu);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->header = NULL;
	tmp->request = NULL;
	tmp->response = NULL;
	tmp->hmac = NULL;
	tmp->headerTLV = NULL;
	tmp->payloadTLV = NULL;
	
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_ExtendPdu_free(tmp);
	return res;
}

int KSI_ExtendPdu_calculateHmac(KSI_ExtendPdu *t, int hashAlg, const char *key, KSI_DataHash **hmac){
	KSI_ERR err;
	int res;
	unsigned char *raw_header = NULL;
	unsigned header_len = 0;
	unsigned char *raw_payload = NULL;
	unsigned payload_len = 0;
	unsigned char *buf;
	KSI_DataHash *tmp = NULL;

	KSI_PRE(&err, t != NULL) goto cleanup;
	KSI_PRE(&err, key != NULL) goto cleanup;
	KSI_PRE(&err, hmac != NULL) goto cleanup;
	KSI_BEGIN(t->ctx, &err);
	
	if(t->headerTLV){
		res = KSI_TLV_serialize(t->headerTLV, &raw_header, &header_len);
		KSI_CATCH(&err, res) goto cleanup;
	}
	else{
		res = KSI_TlvTemplate_serializeObject(t->ctx, t->header, 0x01, 0, 0, KSI_TLV_TEMPLATE(KSI_Header), &raw_header, &header_len);
		KSI_CATCH(&err, res) goto cleanup;
	}
	
	if(t->payloadTLV){
		res = KSI_TLV_serialize(t->payloadTLV, &raw_payload, &payload_len);
		KSI_CATCH(&err, res) goto cleanup;
	}else{
		
		if(t->request){
			res = KSI_TlvTemplate_serializeObject(t->ctx, t->request, 0x0301, 0, 0, KSI_TLV_TEMPLATE(KSI_ExtendReq), &raw_payload, &payload_len);
			KSI_CATCH(&err, res) goto cleanup;
		}
		else if(t->response){
			res = KSI_TlvTemplate_serializeObject(t->ctx, t->response, 0x0302, 0, 0, KSI_TLV_TEMPLATE(KSI_ExtendResp), &raw_payload, &payload_len);
			KSI_CATCH(&err, res) goto cleanup;
		}
		else{
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
			goto cleanup;
		}
	}
	
	
	buf = KSI_malloc(payload_len+header_len);
	if(buf == NULL){
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	
	memcpy(buf, raw_header, header_len);
	memcpy(buf+header_len, raw_payload, payload_len);
	
	res = KSI_HMAC_create(t->ctx, hashAlg, key, buf, header_len+payload_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;
	
	*hmac = tmp;
	tmp = NULL;
	
	KSI_SUCCESS(&err);
	
cleanup:

	KSI_free(raw_header);
	KSI_free(raw_payload);
	KSI_free(buf);
	KSI_DataHash_free(tmp);
	
	return KSI_RETURN(&err);	
}

KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_TLV*, headerTLV, HeaderTlv);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_TLV*, payloadTLV, PayloadTlv);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_Header*, header, Header);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_ExtendReq*, request, Request);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_ExtendResp*, response, Response);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_DataHash*, hmac, Hmac);

KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_TLV*, headerTLV, HeaderTlv);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_TLV*, payloadTLV, PayloadTlv);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_Header*, header, Header);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_ExtendReq*, request, Request);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_ExtendResp*, response, Response);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_DataHash*, hmac, Hmac);

KSI_IMPLEMENT_OBJECT_PARSE(KSI_ExtendPdu, 0x300);
KSI_IMPLEMENT_OBJECT_SERIALIZE(KSI_ExtendPdu, 0x300, 0, 0)

/**
 * KSI_AggregationPdu
 */
void KSI_AggregationPdu_free(KSI_AggregationPdu *t) {
	if(t != NULL) {
		KSI_Header_free(t->header);
		KSI_AggregationReq_free(t->request);
		KSI_AggregationResp_free(t->response);
		KSI_DataHash_free(t->hmac);
		KSI_TLV_free(t->headerTLV);
		KSI_TLV_free(t->payloadTLV);
		KSI_free(t);
	}
}

int KSI_AggregationPdu_new(KSI_CTX *ctx, KSI_AggregationPdu **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationPdu *tmp = NULL;
	tmp = KSI_new(KSI_AggregationPdu);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->header = NULL;
	tmp->ctx = ctx;
	tmp->request = NULL;
	tmp->response = NULL;
	tmp->hmac = NULL;
	tmp->headerTLV = NULL;
	tmp->payloadTLV = NULL;
	
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_AggregationPdu_free(tmp);
	return res;
}

int KSI_AggregationPdu_calculateHmac(KSI_AggregationPdu *t, int hashAlg, const char *key, KSI_DataHash **hmac){
	KSI_ERR err;
	int res;
	unsigned char *raw_header = NULL;
	unsigned header_len = 0;
	unsigned char *raw_payload = NULL;
	unsigned payload_len = 0;
	unsigned char *buf = NULL;
	KSI_DataHash *tmp = NULL;

	KSI_PRE(&err, t != NULL) goto cleanup;
	KSI_PRE(&err, key != NULL) goto cleanup;
	KSI_BEGIN(t->ctx, &err);
	
	if(t->headerTLV){
		res = KSI_TLV_serialize(t->headerTLV, &raw_header, &header_len);
		KSI_CATCH(&err, res) goto cleanup;
	}
	else{
		res = KSI_TlvTemplate_serializeObject(t->ctx, t->header, 0x01, 0, 0, KSI_TLV_TEMPLATE(KSI_Header), &raw_header, &header_len);
		KSI_CATCH(&err, res) goto cleanup;
	}
	
	if(t->payloadTLV){
		res = KSI_TLV_serialize(t->payloadTLV, &raw_payload, &payload_len);
		KSI_CATCH(&err, res) goto cleanup;
	}
	else{
		if(t->request){
			res = KSI_TlvTemplate_serializeObject(t->ctx, t->request, 0x0201, 0, 0, KSI_TLV_TEMPLATE(KSI_AggregationReq), &raw_payload, &payload_len);
			KSI_CATCH(&err, res) goto cleanup;
		}
		else if(t->response){
			res = KSI_TlvTemplate_serializeObject(t->ctx, t->response, 0x0202, 0, 0, KSI_TLV_TEMPLATE(KSI_AggregationResp), &raw_payload, &payload_len);
			KSI_CATCH(&err, res) goto cleanup;
		}
		else{
			KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
			goto cleanup;
		}
	}
	
	
	
	
	buf = KSI_malloc(payload_len+header_len);
	if(buf == NULL){
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	
	memcpy(buf, raw_header, header_len);
	memcpy(buf+header_len, raw_payload, payload_len);
	
	res = KSI_HMAC_create(t->ctx, hashAlg, key, buf, header_len+payload_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;
	
	*hmac = tmp;
	tmp = NULL;
	
	KSI_SUCCESS(&err);
	
cleanup:

	KSI_free(raw_header);
	KSI_free(raw_payload);
	KSI_free(buf);
	KSI_DataHash_free(tmp);

	return KSI_RETURN(&err);	
}

KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_TLV*, headerTLV, HeaderTlv);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_TLV*, payloadTLV, PayloadTlv);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_Header*, header, Header);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_AggregationReq*, request, Request);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_AggregationResp*, response, Response);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_DataHash*, hmac, Hmac);

KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_TLV*, headerTLV, HeaderTlv);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_TLV*, payloadTLV, PayloadTlv);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_Header*, header, Header);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_AggregationReq*, request, Request);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_AggregationResp*, response, Response);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_DataHash*, hmac, Hmac);

KSI_IMPLEMENT_OBJECT_PARSE(KSI_AggregationPdu, 0x200);
KSI_IMPLEMENT_OBJECT_SERIALIZE(KSI_AggregationPdu, 0x200, 0, 0)

/**
 * KSI_Header
 */
void KSI_Header_free(KSI_Header *t) {
	if(t != NULL) {
		KSI_Integer_free(t->instanceId);
		KSI_Integer_free(t->messageId);
		KSI_OctetString_free(t->loginId);
		KSI_free(t);
	}
}

int KSI_Header_new(KSI_CTX *ctx, KSI_Header **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Header *tmp = NULL;
	tmp = KSI_new(KSI_Header);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->instanceId = NULL;
	tmp->messageId = NULL;
	tmp->loginId = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_Header_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_Header, KSI_Integer*, instanceId, InstanceId);
KSI_IMPLEMENT_GETTER(KSI_Header, KSI_Integer*, messageId, MessageId);
KSI_IMPLEMENT_GETTER(KSI_Header, KSI_OctetString*, loginId, LoginId);

KSI_IMPLEMENT_SETTER(KSI_Header, KSI_Integer*, instanceId, InstanceId);
KSI_IMPLEMENT_SETTER(KSI_Header, KSI_Integer*, messageId, MessageId);
KSI_IMPLEMENT_SETTER(KSI_Header, KSI_OctetString*, loginId, LoginId);


/**
 * KSI_Config
 */
void KSI_Config_free(KSI_Config *t) {
	if(t != NULL) {
		KSI_Integer_free(t->maxLevel);
		KSI_Integer_free(t->aggrAlgo);
		KSI_Integer_free(t->aggrPeriod);
		KSI_Utf8StringList_free(t->parentUri);
		KSI_free(t);
	}
}

int KSI_Config_new(KSI_CTX *ctx, KSI_Config **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Config *tmp = NULL;
	tmp = KSI_new(KSI_Config);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->maxLevel = NULL;
	tmp->aggrAlgo = NULL;
	tmp->aggrPeriod = NULL;
	tmp->parentUri = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_Config_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_Config, KSI_Integer*, maxLevel, MaxLevel);
KSI_IMPLEMENT_GETTER(KSI_Config, KSI_Integer*, aggrAlgo, AggrAlgo);
KSI_IMPLEMENT_GETTER(KSI_Config, KSI_Integer*, aggrPeriod, AggrPeriod);
KSI_IMPLEMENT_GETTER(KSI_Config, KSI_LIST(KSI_Utf8String)*, parentUri, ParentUri);

KSI_IMPLEMENT_SETTER(KSI_Config, KSI_Integer*, maxLevel, MaxLevel);
KSI_IMPLEMENT_SETTER(KSI_Config, KSI_Integer*, aggrAlgo, AggrAlgo);
KSI_IMPLEMENT_SETTER(KSI_Config, KSI_Integer*, aggrPeriod, AggrPeriod);
KSI_IMPLEMENT_SETTER(KSI_Config, KSI_LIST(KSI_Utf8String)*, parentUri, ParentUri);


/**
 * KSI_AggregationReq
 */
void KSI_AggregationReq_free(KSI_AggregationReq *t) {
	if(t != NULL) {
//		KSI_Header_free(t->header);
		KSI_Integer_free(t->requestId);
		KSI_DataHash_free(t->requestHash);
		KSI_Integer_free(t->requestLevel);
		KSI_Config_free(t->config);
		KSI_free(t);
	}
}

int KSI_AggregationReq_new(KSI_CTX *ctx, KSI_AggregationReq **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationReq *tmp = NULL;
	tmp = KSI_new(KSI_AggregationReq);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->requestId = NULL;
	tmp->requestHash = NULL;
	tmp->requestLevel = NULL;
	tmp->config = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_AggregationReq_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_AggregationReq, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_GETTER(KSI_AggregationReq, KSI_DataHash*, requestHash, RequestHash);
KSI_IMPLEMENT_GETTER(KSI_AggregationReq, KSI_Integer*, requestLevel, RequestLevel);
KSI_IMPLEMENT_GETTER(KSI_AggregationReq, KSI_Config*, config, Config);

KSI_IMPLEMENT_SETTER(KSI_AggregationReq, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_SETTER(KSI_AggregationReq, KSI_DataHash*, requestHash, RequestHash);
KSI_IMPLEMENT_SETTER(KSI_AggregationReq, KSI_Integer*, requestLevel, RequestLevel);
KSI_IMPLEMENT_SETTER(KSI_AggregationReq, KSI_Config*, config, Config);


/**
 * KSI_RequestAck
 */
void KSI_RequestAck_free(KSI_RequestAck *t) {
	if(t != NULL) {
		KSI_Integer_free(t->aggregationPeriod);
		KSI_Integer_free(t->aggregationDelay);
		KSI_free(t);
	}
}

int KSI_RequestAck_new(KSI_CTX *ctx, KSI_RequestAck **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RequestAck *tmp = NULL;
	tmp = KSI_new(KSI_RequestAck);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->aggregationPeriod = NULL;
	tmp->aggregationDelay = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_RequestAck_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_RequestAck, KSI_Integer*, aggregationPeriod, AggregationPeriod);
KSI_IMPLEMENT_GETTER(KSI_RequestAck, KSI_Integer*, aggregationDelay, AggregationDelay);

KSI_IMPLEMENT_SETTER(KSI_RequestAck, KSI_Integer*, aggregationPeriod, AggregationPeriod);
KSI_IMPLEMENT_SETTER(KSI_RequestAck, KSI_Integer*, aggregationDelay, AggregationDelay);


/**
 * KSI_AggregationResp
 */
void KSI_AggregationResp_free(KSI_AggregationResp *t) {
	if(t != NULL) {
		KSI_Integer_free(t->requestId);
		KSI_Integer_free(t->status);
		KSI_Utf8String_free(t->errorMsg);
		KSI_Config_free(t->config);
		KSI_RequestAck_free(t->requestAck);
		KSI_CalendarHashChain_free(t->calendarChain);
		KSI_AggregationHashChainList_free(t->aggregationChainList);
		KSI_CalendarAuthRec_free(t->calendarAuthRec);
		KSI_AggregationAuthRec_free(t->aggregationAuthRec);
		KSI_TLV_free(t->baseTlv);
		KSI_free(t);
	}
}

int KSI_AggregationResp_new(KSI_CTX *ctx, KSI_AggregationResp **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationResp *tmp = NULL;
	tmp = KSI_new(KSI_AggregationResp);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->requestId = NULL;
	tmp->status = NULL;
	tmp->errorMsg = NULL;
	tmp->config = NULL;
	tmp->requestAck = NULL;
	tmp->calendarChain = NULL;
	tmp->aggregationChainList = NULL;
	tmp->calendarAuthRec = NULL;
	tmp->aggregationAuthRec = NULL;
	tmp->baseTlv = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_AggregationResp_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_Integer*, status, Status);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_Utf8String*, errorMsg, ErrorMsg);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_Config*, config, Config);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_RequestAck*, requestAck, RequestAck);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_CalendarHashChain*, calendarChain, CalendarChain);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_LIST(KSI_AggregationHashChain)*, aggregationChainList, AggregationChainList);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_CalendarAuthRec*, calendarAuthRec, CalendarAuthRec);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_AggregationAuthRec*, aggregationAuthRec, AggregationAuthRec);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_TLV*, baseTlv, BaseTlv);

KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_Integer*, status, Status);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_Utf8String*, errorMsg, ErrorMsg);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_Config*, config, Config);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_RequestAck*, requestAck, RequestAck);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_CalendarHashChain*, calendarChain, CalendarChain);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_LIST(KSI_AggregationHashChain)*, aggregationChainList, AggregationChainList);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_CalendarAuthRec*, calendarAuthRec, CalendarAuthRec);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_AggregationAuthRec*, aggregationAuthRec, AggregationAuthRec);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_TLV*, baseTlv, BaseTlv);


/**
 * KSI_ExtendReq
 */
void KSI_ExtendReq_free(KSI_ExtendReq *t) {
	if(t != NULL) {
		KSI_Integer_free(t->requestId);
		KSI_Integer_free(t->aggregationTime);
		KSI_Integer_free(t->publicationTime);
		KSI_free(t);
	}
}

int KSI_ExtendReq_new(KSI_CTX *ctx, KSI_ExtendReq **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendReq *tmp = NULL;
	tmp = KSI_new(KSI_ExtendReq);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->requestId = NULL;
	tmp->aggregationTime = NULL;
	tmp->publicationTime = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_ExtendReq_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_Integer*, aggregationTime, AggregationTime);
KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_Integer*, publicationTime, PublicationTime);

KSI_IMPLEMENT_SETTER(KSI_ExtendReq, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_SETTER(KSI_ExtendReq, KSI_Integer*, aggregationTime, AggregationTime);
KSI_IMPLEMENT_SETTER(KSI_ExtendReq, KSI_Integer*, publicationTime, PublicationTime);


/**
 * KSI_ExtendResp
 */
void KSI_ExtendResp_free(KSI_ExtendResp *t) {
	if(t != NULL) {
		KSI_Integer_free(t->requestId);
		KSI_Integer_free(t->status);
		KSI_Utf8String_free(t->errorMsg);
		KSI_Integer_free(t->lastTime);
		KSI_CalendarHashChain_free(t->calendarHashChain);
		KSI_TLV_free(t->baseTlv);
		KSI_free(t);
	}
}

int KSI_ExtendResp_new(KSI_CTX *ctx, KSI_ExtendResp **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendResp *tmp = NULL;
	tmp = KSI_new(KSI_ExtendResp);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->requestId = NULL;
	tmp->status = NULL;
	tmp->errorMsg = NULL;
	tmp->lastTime = NULL;
	tmp->calendarHashChain = NULL;
	tmp->baseTlv = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_ExtendResp_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Integer*, status, Status);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Utf8String*, errorMsg, ErrorMsg);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Integer*, lastTime, LastTime);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_CalendarHashChain*, calendarHashChain, CalendarHashChain);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_TLV*, baseTlv, BaseTlv);

KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Integer*, status, Status);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Utf8String*, errorMsg, ErrorMsg);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Integer*, lastTime, LastTime);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_CalendarHashChain*, calendarHashChain, CalendarHashChain);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_TLV*, baseTlv, BaseTlv);

/**
 * KSI_PKISignedData
 */
void KSI_PKISignedData_free(KSI_PKISignedData *t) {
	if(t != NULL) {
		KSI_OctetString_free(t->signatureValue);
		KSI_OctetString_free(t->certId);
		KSI_Utf8String_free(t->certRepositoryUri);
		KSI_free(t);
	}
}

int KSI_PKISignedData_new(KSI_CTX *ctx, KSI_PKISignedData **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PKISignedData *tmp = NULL;
	tmp = KSI_new(KSI_PKISignedData);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->signatureValue = NULL;
	tmp->certId = NULL;
	tmp->cert = NULL;
	tmp->certRepositoryUri = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_PKISignedData_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_PKISignedData, KSI_OctetString*, signatureValue, SignatureValue);
KSI_IMPLEMENT_GETTER(KSI_PKISignedData, KSI_OctetString*, certId, CertId);
KSI_IMPLEMENT_GETTER(KSI_PKISignedData, KSI_PKICertificate*, cert, Certificate);
KSI_IMPLEMENT_GETTER(KSI_PKISignedData, KSI_Utf8String*, certRepositoryUri, CertRepositoryUri);

KSI_IMPLEMENT_SETTER(KSI_PKISignedData, KSI_OctetString*, signatureValue, SignatureValue);
KSI_IMPLEMENT_SETTER(KSI_PKISignedData, KSI_OctetString*, certId, CertId);
KSI_IMPLEMENT_SETTER(KSI_PKISignedData, KSI_PKICertificate*, cert, Certificate);
KSI_IMPLEMENT_SETTER(KSI_PKISignedData, KSI_Utf8String*, certRepositoryUri, CertRepositoryUri);


/**
 * KSI_PublicationsHeader
 */
void KSI_PublicationsHeader_free(KSI_PublicationsHeader *t) {
	if(t != NULL) {
		KSI_Integer_free(t->version);
		KSI_Integer_free(t->timeCreated_s);
		KSI_Utf8String_free(t->repositoryUri);
		KSI_free(t);
	}
}

int KSI_PublicationsHeader_new(KSI_CTX *ctx, KSI_PublicationsHeader **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationsHeader *tmp = NULL;
	tmp = KSI_new(KSI_PublicationsHeader);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->version = NULL;
	tmp->timeCreated_s = NULL;
	tmp->repositoryUri = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_PublicationsHeader_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_PublicationsHeader, KSI_Integer*, version, Version);
KSI_IMPLEMENT_GETTER(KSI_PublicationsHeader, KSI_Integer*, timeCreated_s, TimeCreated);
KSI_IMPLEMENT_GETTER(KSI_PublicationsHeader, KSI_Utf8String*, repositoryUri, RepositoryUri);

KSI_IMPLEMENT_SETTER(KSI_PublicationsHeader, KSI_Integer*, version, Version);
KSI_IMPLEMENT_SETTER(KSI_PublicationsHeader, KSI_Integer*, timeCreated_s, TimeCreated);
KSI_IMPLEMENT_SETTER(KSI_PublicationsHeader, KSI_Utf8String*, repositoryUri, RepositoryUri);


/**
 * KSI_CertificateRecord
 */
void KSI_CertificateRecord_free(KSI_CertificateRecord *t) {
	if(t != NULL) {
		KSI_OctetString_free(t->certId);
		KSI_PKICertificate_free(t->cert);
		KSI_free(t);
	}
}

int KSI_CertificateRecord_new(KSI_CTX *ctx, KSI_CertificateRecord **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CertificateRecord *tmp = NULL;
	tmp = KSI_new(KSI_CertificateRecord);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->certId = NULL;
	tmp->cert = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_CertificateRecord_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_CertificateRecord, KSI_OctetString*, certId, CertId);
KSI_IMPLEMENT_GETTER(KSI_CertificateRecord, KSI_PKICertificate*, cert, Cert);

KSI_IMPLEMENT_SETTER(KSI_CertificateRecord, KSI_OctetString*, certId, CertId);
KSI_IMPLEMENT_SETTER(KSI_CertificateRecord, KSI_PKICertificate*, cert, Cert);
