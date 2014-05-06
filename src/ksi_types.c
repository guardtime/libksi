#include "ksi_internal.h"

struct KSI_HashChainLink_st {
	KSI_CTX *ctx;
	int isLeft;
	int levelCorrection;
	KSI_MetaHash *metaHash;
	KSI_MetaData *metaData;
	KSI_DataHash *imprint;
};

struct KSI_CalendarHashChain_st {
	KSI_CTX *ctx;
	KSI_Integer *publicationTime;
	KSI_Integer *aggregationTime;
	KSI_DataHash *inputHash;
	KSI_LIST(KSI_HashChainLink) *hashChain;
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
	KSI_Utf8String *parentUri;
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
	KSI_LIST(KSI_TLV) *payload;
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


KSI_IMPLEMENT_LIST(KSI_HashChainLink, KSI_HashChainLink_free);

/**
 * KSI_HashChainLink
 */
void KSI_HashChainLink_free(KSI_HashChainLink *t) {
	if(t != NULL) {
		KSI_MetaHash_free(t->metaHash);
		KSI_MetaData_free(t->metaData);
		KSI_DataHash_free(t->imprint);
		KSI_free(t);
	}
}

int KSI_HashChainLink_new(KSI_CTX *ctx, KSI_HashChainLink **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_HashChainLink *tmp = NULL;
	tmp = KSI_new(KSI_HashChainLink);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->isLeft = 0;
	tmp->levelCorrection = 0;
	tmp->metaHash = NULL;
	tmp->metaData = NULL;
	tmp->imprint = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_HashChainLink_free(tmp);
	return res;
}

int KSI_HashChainLink_getIsLeft(const KSI_HashChainLink *t, int *isLeft) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || isLeft == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*isLeft = t->isLeft;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_HashChainLink_getLevelCorrection(const KSI_HashChainLink *t, int *levelCorrection) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || levelCorrection == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*levelCorrection = t->levelCorrection;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_HashChainLink_getMetaHash(const KSI_HashChainLink *t, KSI_MetaHash **metaHash) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || metaHash == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*metaHash = t->metaHash;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_HashChainLink_getMetaData(const KSI_HashChainLink *t, KSI_MetaData **metaData) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || metaData == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*metaData = t->metaData;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_HashChainLink_getImprint(const KSI_HashChainLink *t, KSI_DataHash **imprint) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || imprint == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*imprint = t->imprint;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_HashChainLink_setIsLeft(KSI_HashChainLink *t, int isLeft) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->isLeft = isLeft;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_HashChainLink_setLevelCorrection(KSI_HashChainLink *t, int levelCorrection) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->levelCorrection = levelCorrection;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_HashChainLink_setMetaHash(KSI_HashChainLink *t, KSI_MetaHash *metaHash) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->metaHash = metaHash;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_HashChainLink_setMetaData(KSI_HashChainLink *t, KSI_MetaData *metaData) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->metaData = metaData;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_HashChainLink_setImprint(KSI_HashChainLink *t, KSI_DataHash *imprint) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->imprint = imprint;
	res = KSI_OK;
cleanup:
	 return res;
}


/**
 * KSI_CalendarHashChain
 */
void KSI_CalendarHashChain_free(KSI_CalendarHashChain *t) {
	if(t != NULL) {
		KSI_Integer_free(t->publicationTime);
		KSI_Integer_free(t->aggregationTime);
		KSI_DataHash_free(t->inputHash);
		KSI_HashChainLinkList_free(t->hashChain);
		KSI_free(t);
	}
}

int KSI_CalendarHashChain_new(KSI_CTX *ctx, KSI_CalendarHashChain **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CalendarHashChain *tmp = NULL;
	tmp = KSI_new(KSI_CalendarHashChain);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->publicationTime = NULL;
	tmp->aggregationTime = NULL;
	tmp->inputHash = NULL;
	tmp->hashChain = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_CalendarHashChain_free(tmp);
	return res;
}

int KSI_CalendarHashChain_getPublicationTime(const KSI_CalendarHashChain *t, KSI_Integer **publicationTime) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || publicationTime == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*publicationTime = t->publicationTime;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_CalendarHashChain_getAggregationTime(const KSI_CalendarHashChain *t, KSI_Integer **aggregationTime) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || aggregationTime == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*aggregationTime = t->aggregationTime;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_CalendarHashChain_getInputHash(const KSI_CalendarHashChain *t, KSI_DataHash **inputHash) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || inputHash == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*inputHash = t->inputHash;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_CalendarHashChain_getHashChain(const KSI_CalendarHashChain *t, KSI_LIST(KSI_HashChainLink) **hashChain) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || hashChain == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*hashChain = t->hashChain;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_CalendarHashChain_setPublicationTime(KSI_CalendarHashChain *t, KSI_Integer *publicationTime) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->publicationTime = publicationTime;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_CalendarHashChain_setAggregationTime(KSI_CalendarHashChain *t, KSI_Integer *aggregationTime) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->aggregationTime = aggregationTime;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_CalendarHashChain_setInputHash(KSI_CalendarHashChain *t, KSI_DataHash *inputHash) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->inputHash = inputHash;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_CalendarHashChain_setHashChain(KSI_CalendarHashChain *t, KSI_LIST(KSI_HashChainLink) *hashChain) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->hashChain = hashChain;
	res = KSI_OK;
cleanup:
	 return res;
}


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

int KSI_ExtendPdu_getRequest(const KSI_ExtendPdu *t, KSI_ExtendReq **request) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || request == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*request = t->request;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendPdu_getResponse(const KSI_ExtendPdu *t, KSI_ExtendResp **response) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || response == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*response = t->response;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendPdu_setRequest(KSI_ExtendPdu *t, KSI_ExtendReq *request) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->request = request;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendPdu_setResponse(KSI_ExtendPdu *t, KSI_ExtendResp *response) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->response = response;
	res = KSI_OK;
cleanup:
	 return res;
}


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

int KSI_AggregationPdu_getRequest(const KSI_AggregationPdu *t, KSI_AggregationReq **request) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || request == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*request = t->request;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationPdu_getResponse(const KSI_AggregationPdu *t, KSI_AggregationResp **response) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || response == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*response = t->response;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationPdu_setRequest(KSI_AggregationPdu *t, KSI_AggregationReq *request) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->request = request;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationPdu_setResponse(KSI_AggregationPdu *t, KSI_AggregationResp *response) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->response = response;
	res = KSI_OK;
cleanup:
	 return res;
}


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

int KSI_Header_getInstanceId(const KSI_Header *t, KSI_Integer **instanceId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || instanceId == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*instanceId = t->instanceId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Header_getMessageId(const KSI_Header *t, KSI_Integer **messageId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || messageId == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*messageId = t->messageId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Header_getClientId(const KSI_Header *t, KSI_OctetString **clientId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || clientId == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*clientId = t->clientId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Header_setInstanceId(KSI_Header *t, KSI_Integer *instanceId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->instanceId = instanceId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Header_setMessageId(KSI_Header *t, KSI_Integer *messageId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->messageId = messageId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Header_setClientId(KSI_Header *t, KSI_OctetString *clientId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->clientId = clientId;
	res = KSI_OK;
cleanup:
	 return res;
}


/**
 * KSI_Config
 */
void KSI_Config_free(KSI_Config *t) {
	if(t != NULL) {
		KSI_Integer_free(t->maxLevel);
		KSI_Integer_free(t->aggrAlgo);
		KSI_Integer_free(t->aggrPeriod);
		KSI_Utf8String_free(t->parentUri);
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

int KSI_Config_getMaxLevel(const KSI_Config *t, KSI_Integer **maxLevel) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || maxLevel == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*maxLevel = t->maxLevel;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Config_getAggrAlgo(const KSI_Config *t, KSI_Integer **aggrAlgo) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || aggrAlgo == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*aggrAlgo = t->aggrAlgo;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Config_getAggrPeriod(const KSI_Config *t, KSI_Integer **aggrPeriod) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || aggrPeriod == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*aggrPeriod = t->aggrPeriod;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Config_getParentUri(const KSI_Config *t, KSI_Utf8String **parentUri) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || parentUri == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*parentUri = t->parentUri;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Config_setMaxLevel(KSI_Config *t, KSI_Integer *maxLevel) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->maxLevel = maxLevel;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Config_setAggrAlgo(KSI_Config *t, KSI_Integer *aggrAlgo) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->aggrAlgo = aggrAlgo;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Config_setAggrPeriod(KSI_Config *t, KSI_Integer *aggrPeriod) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->aggrPeriod = aggrPeriod;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_Config_setParentUri(KSI_Config *t, KSI_Utf8String *parentUri) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->parentUri = parentUri;
	res = KSI_OK;
cleanup:
	 return res;
}


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

int KSI_AggregationReq_getHeader(const KSI_AggregationReq *t, KSI_Header **header) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || header == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*header = t->header;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationReq_getRequestId(const KSI_AggregationReq *t, KSI_Integer **requestId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || requestId == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*requestId = t->requestId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationReq_getRequestHash(const KSI_AggregationReq *t, KSI_DataHash **requestHash) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || requestHash == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*requestHash = t->requestHash;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationReq_getRequestLevel(const KSI_AggregationReq *t, KSI_Integer **requestLevel) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || requestLevel == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*requestLevel = t->requestLevel;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationReq_getConfig(const KSI_AggregationReq *t, KSI_Config **config) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || config == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*config = t->config;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationReq_setHeader(KSI_AggregationReq *t, KSI_Header *header) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->header = header;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationReq_setRequestId(KSI_AggregationReq *t, KSI_Integer *requestId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->requestId = requestId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationReq_setRequestHash(KSI_AggregationReq *t, KSI_DataHash *requestHash) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->requestHash = requestHash;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationReq_setRequestLevel(KSI_AggregationReq *t, KSI_Integer *requestLevel) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->requestLevel = requestLevel;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationReq_setConfig(KSI_AggregationReq *t, KSI_Config *config) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->config = config;
	res = KSI_OK;
cleanup:
	 return res;
}


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

int KSI_RequestAck_getAggregationPeriod(const KSI_RequestAck *t, KSI_Integer **aggregationPeriod) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || aggregationPeriod == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*aggregationPeriod = t->aggregationPeriod;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_RequestAck_getAggregationDelay(const KSI_RequestAck *t, KSI_Integer **aggregationDelay) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || aggregationDelay == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*aggregationDelay = t->aggregationDelay;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_RequestAck_setAggregationPeriod(KSI_RequestAck *t, KSI_Integer *aggregationPeriod) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->aggregationPeriod = aggregationPeriod;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_RequestAck_setAggregationDelay(KSI_RequestAck *t, KSI_Integer *aggregationDelay) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->aggregationDelay = aggregationDelay;
	res = KSI_OK;
cleanup:
	 return res;
}


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
		KSI_TLVList_free(t->payload);
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
	tmp->payload = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_AggregationResp_free(tmp);
	return res;
}

int KSI_AggregationResp_getHeader(const KSI_AggregationResp *t, KSI_Header **header) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || header == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*header = t->header;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_getRequestId(const KSI_AggregationResp *t, KSI_Integer **requestId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || requestId == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*requestId = t->requestId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_getStatus(const KSI_AggregationResp *t, KSI_Integer **status) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || status == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*status = t->status;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_getErrorMsg(const KSI_AggregationResp *t, KSI_Utf8String **errorMsg) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || errorMsg == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*errorMsg = t->errorMsg;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_getConfig(const KSI_AggregationResp *t, KSI_Config **config) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || config == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*config = t->config;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_getRequestAck(const KSI_AggregationResp *t, KSI_RequestAck **requestAck) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || requestAck == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*requestAck = t->requestAck;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_getPayload(const KSI_AggregationResp *t, KSI_LIST(KSI_TLV) **payload) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || payload == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*payload = t->payload;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_setHeader(KSI_AggregationResp *t, KSI_Header *header) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->header = header;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_setRequestId(KSI_AggregationResp *t, KSI_Integer *requestId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->requestId = requestId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_setStatus(KSI_AggregationResp *t, KSI_Integer *status) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->status = status;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_setErrorMsg(KSI_AggregationResp *t, KSI_Utf8String *errorMsg) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->errorMsg = errorMsg;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_setConfig(KSI_AggregationResp *t, KSI_Config *config) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->config = config;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_setRequestAck(KSI_AggregationResp *t, KSI_RequestAck *requestAck) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->requestAck = requestAck;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_AggregationResp_setPayload(KSI_AggregationResp *t, KSI_LIST(KSI_TLV) *payload) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->payload = payload;
	res = KSI_OK;
cleanup:
	 return res;
}


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

int KSI_ExtendReq_getHeader(const KSI_ExtendReq *t, KSI_Header **header) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || header == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*header = t->header;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendReq_getRequestId(const KSI_ExtendReq *t, KSI_Integer **requestId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || requestId == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*requestId = t->requestId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendReq_getAggregationTime(const KSI_ExtendReq *t, KSI_Integer **aggregationTime) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || aggregationTime == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*aggregationTime = t->aggregationTime;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendReq_getPublicationTime(const KSI_ExtendReq *t, KSI_Integer **publicationTime) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || publicationTime == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*publicationTime = t->publicationTime;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendReq_setHeader(KSI_ExtendReq *t, KSI_Header *header) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->header = header;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendReq_setRequestId(KSI_ExtendReq *t, KSI_Integer *requestId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->requestId = requestId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendReq_setAggregationTime(KSI_ExtendReq *t, KSI_Integer *aggregationTime) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->aggregationTime = aggregationTime;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendReq_setPublicationTime(KSI_ExtendReq *t, KSI_Integer *publicationTime) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->publicationTime = publicationTime;
	res = KSI_OK;
cleanup:
	 return res;
}


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

int KSI_ExtendResp_getHeader(const KSI_ExtendResp *t, KSI_Header **header) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || header == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*header = t->header;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendResp_getRequestId(const KSI_ExtendResp *t, KSI_Integer **requestId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || requestId == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*requestId = t->requestId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendResp_getStatus(const KSI_ExtendResp *t, KSI_Integer **status) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || status == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*status = t->status;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendResp_getErrorMsg(const KSI_ExtendResp *t, KSI_Utf8String **errorMsg) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || errorMsg == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*errorMsg = t->errorMsg;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendResp_getLastTime(const KSI_ExtendResp *t, KSI_Integer **lastTime) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || lastTime == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*lastTime = t->lastTime;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendResp_getCalendarHashChain(const KSI_ExtendResp *t, KSI_CalendarHashChain **calendarHashChain) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || calendarHashChain == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*calendarHashChain = t->calendarHashChain;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendResp_setHeader(KSI_ExtendResp *t, KSI_Header *header) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->header = header;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendResp_setRequestId(KSI_ExtendResp *t, KSI_Integer *requestId) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->requestId = requestId;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendResp_setStatus(KSI_ExtendResp *t, KSI_Integer *status) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->status = status;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendResp_setErrorMsg(KSI_ExtendResp *t, KSI_Utf8String *errorMsg) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->errorMsg = errorMsg;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendResp_setLastTime(KSI_ExtendResp *t, KSI_Integer *lastTime) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->lastTime = lastTime;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_ExtendResp_setCalendarHashChain(KSI_ExtendResp *t, KSI_CalendarHashChain *calendarHashChain) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->calendarHashChain = calendarHashChain;
	res = KSI_OK;
cleanup:
	 return res;
}



