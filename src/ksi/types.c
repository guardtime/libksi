#include "internal.h"

KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationPdu)

struct KSI_MetaData_st {
	KSI_CTX *ctx;
	KSI_OctetString *raw;
	KSI_Utf8String *clientId;
	KSI_Integer *machineId;
	KSI_Integer *sequenceNr;
};

struct KSI_ExtendPdu_st {
	KSI_CTX *ctx;
	KSI_ExtendReq *request;
	KSI_ExtendResp *response;
};

struct KSI_AggregationPdu_st {
	KSI_CTX *ctx;
	KSI_AggregationReq *request;
	KSI_AggregationResp *response;
};

struct KSI_Header_st {
	KSI_CTX *ctx;
	KSI_Integer *instanceId;
	KSI_Integer *messageId;
	KSI_OctetString *clientId;
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
	KSI_Header *header;
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
	KSI_Header *header;
	KSI_Integer *requestId;
	KSI_Integer *status;
	KSI_Utf8String *errorMsg;
	KSI_Config *config;
	KSI_RequestAck *requestAck;
	KSI_CalendarHashChain *calendarChain;
	KSI_LIST(KSI_AggregationHashChain) *aggregationChainList;
	KSI_CalendarAuthRec *calendarAuthRec;
	KSI_AggregationAuthRec *aggregationAuthRec;
};

struct KSI_ExtendReq_st {
	KSI_CTX *ctx;
	KSI_Header *header;
	KSI_Integer *requestId;
	KSI_Integer *aggregationTime;
	KSI_Integer *publicationTime;
};

struct KSI_ExtendResp_st {
	KSI_CTX *ctx;
	KSI_Header *header;
	KSI_Integer *requestId;
	KSI_Integer *status;
	KSI_Utf8String *errorMsg;
	KSI_Integer *lastTime;
	KSI_CalendarHashChain *calendarHashChain;
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
	KSI_Integer *timeCreated;
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
		KSI_Integer_free(t->machineId);
		KSI_Integer_free(t->sequenceNr);
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
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_MetaData_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_MetaData, KSI_OctetString*, raw, Raw);
KSI_IMPLEMENT_GETTER(KSI_MetaData, KSI_Utf8String*, clientId, ClientId);
KSI_IMPLEMENT_GETTER(KSI_MetaData, KSI_Integer*, machineId, MachineId);
KSI_IMPLEMENT_GETTER(KSI_MetaData, KSI_Integer*, sequenceNr, SequenceNr);

KSI_IMPLEMENT_SETTER(KSI_MetaData, KSI_OctetString*, raw, Raw);
KSI_IMPLEMENT_SETTER(KSI_MetaData, KSI_Utf8String*, clientId, ClientId);
KSI_IMPLEMENT_SETTER(KSI_MetaData, KSI_Integer*, machineId, MachineId);
KSI_IMPLEMENT_SETTER(KSI_MetaData, KSI_Integer*, sequenceNr, SequenceNr);

/**
 * KSI_ExtendPdu
 */
void KSI_ExtendPdu_free(KSI_ExtendPdu *t) {
	if(t != NULL) {
		KSI_ExtendReq_free(t->request);
		KSI_ExtendResp_free(t->response);
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
	tmp->request = NULL;
	tmp->response = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_ExtendPdu_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_ExtendReq*, request, Request);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_ExtendResp*, response, Response);

KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_ExtendReq*, request, Request);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_ExtendResp*, response, Response);

KSI_IMPLEMENT_OBJECT_PARSE(KSI_ExtendPdu, 0x300);
KSI_IMPLEMENT_OBJECT_SERIALIZE(KSI_ExtendPdu, 0x300, 0, 0)

/**
 * KSI_AggregationPdu
 */
void KSI_AggregationPdu_free(KSI_AggregationPdu *t) {
	if(t != NULL) {
		KSI_AggregationReq_free(t->request);
		KSI_AggregationResp_free(t->response);
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

	tmp->ctx = ctx;
	tmp->request = NULL;
	tmp->response = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_AggregationPdu_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_AggregationReq*, request, Request);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_AggregationResp*, response, Response);

KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_AggregationReq*, request, Request);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_AggregationResp*, response, Response);

KSI_IMPLEMENT_OBJECT_PARSE(KSI_AggregationPdu, 0x200);
KSI_IMPLEMENT_OBJECT_SERIALIZE(KSI_AggregationPdu, 0x200, 0, 0)

/**
 * KSI_Header
 */
void KSI_Header_free(KSI_Header *t) {
	if(t != NULL) {
		KSI_Integer_free(t->instanceId);
		KSI_Integer_free(t->messageId);
		KSI_OctetString_free(t->clientId);
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
	tmp->clientId = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_Header_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_Header, KSI_Integer*, instanceId, InstanceId);
KSI_IMPLEMENT_GETTER(KSI_Header, KSI_Integer*, messageId, MessageId);
KSI_IMPLEMENT_GETTER(KSI_Header, KSI_OctetString*, clientId, ClientId);

KSI_IMPLEMENT_SETTER(KSI_Header, KSI_Integer*, instanceId, InstanceId);
KSI_IMPLEMENT_SETTER(KSI_Header, KSI_Integer*, messageId, MessageId);
KSI_IMPLEMENT_SETTER(KSI_Header, KSI_OctetString*, clientId, ClientId);


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
		KSI_Header_free(t->header);
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
	tmp->header = NULL;
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

KSI_IMPLEMENT_GETTER(KSI_AggregationReq, KSI_Header*, header, Header);
KSI_IMPLEMENT_GETTER(KSI_AggregationReq, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_GETTER(KSI_AggregationReq, KSI_DataHash*, requestHash, RequestHash);
KSI_IMPLEMENT_GETTER(KSI_AggregationReq, KSI_Integer*, requestLevel, RequestLevel);
KSI_IMPLEMENT_GETTER(KSI_AggregationReq, KSI_Config*, config, Config);

KSI_IMPLEMENT_SETTER(KSI_AggregationReq, KSI_Header*, header, Header);
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
		KSI_Header_free(t->header);
		KSI_Integer_free(t->requestId);
		KSI_Integer_free(t->status);
		KSI_Utf8String_free(t->errorMsg);
		KSI_Config_free(t->config);
		KSI_RequestAck_free(t->requestAck);
		KSI_CalendarHashChain_free(t->calendarChain);
		KSI_AggregationHashChainList_freeAll(t->aggregationChainList);
		KSI_CalendarAuthRec_free(t->calendarAuthRec);
		KSI_AggregationAuthRec_free(t->aggregationAuthRec);
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
	tmp->header = NULL;
	tmp->requestId = NULL;
	tmp->status = NULL;
	tmp->errorMsg = NULL;
	tmp->config = NULL;
	tmp->requestAck = NULL;
	tmp->calendarChain = NULL;
	tmp->aggregationChainList = NULL;
	tmp->calendarAuthRec = NULL;
	tmp->aggregationAuthRec = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_AggregationResp_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_Header*, header, Header);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_Integer*, status, Status);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_Utf8String*, errorMsg, ErrorMsg);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_Config*, config, Config);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_RequestAck*, requestAck, RequestAck);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_CalendarHashChain*, calendarChain, CalendarChain);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_LIST(KSI_AggregationHashChain)*, aggregationChainList, AggregationChainList);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_CalendarAuthRec*, calendarAuthRec, CalendarAuthRec);
KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_AggregationAuthRec*, aggregationAuthRec, AggregationAuthRec);

KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_Header*, header, Header);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_Integer*, status, Status);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_Utf8String*, errorMsg, ErrorMsg);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_Config*, config, Config);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_RequestAck*, requestAck, RequestAck);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_CalendarHashChain*, calendarChain, CalendarChain);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_LIST(KSI_AggregationHashChain)*, aggregationChainList, AggregationChainList);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_CalendarAuthRec*, calendarAuthRec, CalendarAuthRec);
KSI_IMPLEMENT_SETTER(KSI_AggregationResp, KSI_AggregationAuthRec*, aggregationAuthRec, AggregationAuthRec);


/**
 * KSI_ExtendReq
 */
void KSI_ExtendReq_free(KSI_ExtendReq *t) {
	if(t != NULL) {
		KSI_Header_free(t->header);
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
	tmp->header = NULL;
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

KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_Header*, header, Header);
KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_Integer*, aggregationTime, AggregationTime);
KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_Integer*, publicationTime, PublicationTime);

KSI_IMPLEMENT_SETTER(KSI_ExtendReq, KSI_Header*, header, Header);
KSI_IMPLEMENT_SETTER(KSI_ExtendReq, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_SETTER(KSI_ExtendReq, KSI_Integer*, aggregationTime, AggregationTime);
KSI_IMPLEMENT_SETTER(KSI_ExtendReq, KSI_Integer*, publicationTime, PublicationTime);


/**
 * KSI_ExtendResp
 */
void KSI_ExtendResp_free(KSI_ExtendResp *t) {
	if(t != NULL) {
		KSI_Header_free(t->header);
		KSI_Integer_free(t->requestId);
		KSI_Integer_free(t->status);
		KSI_Utf8String_free(t->errorMsg);
		KSI_Integer_free(t->lastTime);
		KSI_CalendarHashChain_free(t->calendarHashChain);
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
	tmp->header = NULL;
	tmp->requestId = NULL;
	tmp->status = NULL;
	tmp->errorMsg = NULL;
	tmp->lastTime = NULL;
	tmp->calendarHashChain = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_ExtendResp_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Header*, header, Header);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Integer*, status, Status);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Utf8String*, errorMsg, ErrorMsg);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Integer*, lastTime, LastTime);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_CalendarHashChain*, calendarHashChain, CalendarHashChain);

KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Header*, header, Header);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Integer*, status, Status);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Utf8String*, errorMsg, ErrorMsg);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Integer*, lastTime, LastTime);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_CalendarHashChain*, calendarHashChain, CalendarHashChain);


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
		KSI_Integer_free(t->timeCreated);
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
	tmp->timeCreated = NULL;
	tmp->repositoryUri = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_PublicationsHeader_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_PublicationsHeader, KSI_Integer*, version, Version);
KSI_IMPLEMENT_GETTER(KSI_PublicationsHeader, KSI_Integer*, timeCreated, TimeCreated);
KSI_IMPLEMENT_GETTER(KSI_PublicationsHeader, KSI_Utf8String*, repositoryUri, RepositoryUri);

KSI_IMPLEMENT_SETTER(KSI_PublicationsHeader, KSI_Integer*, version, Version);
KSI_IMPLEMENT_SETTER(KSI_PublicationsHeader, KSI_Integer*, timeCreated, TimeCreated);
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
