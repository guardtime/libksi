#include <string.h>

#include "ksi_internal.h"
#include "ksi_tlv_easy.h"

typedef struct calChainComponent_st CalChainComponent;
typedef struct aggrChainComponent_st AggChainComponent;
typedef struct headerComponent_st HeaderComponent;
typedef struct calAuthComponent_st CalAuthComponent;

struct calAuthComponent_st {
	KSI_Integer *publicationTime;
	KSI_DataHash *publicationHash;
	char *signatureAlgo;

};

struct aggrChainComponent_st {
	KSI_Integer *aggregationTime;
	KSI_Integer *chainIndex;
	unsigned char *inputData;
	int inputData_len;
	KSI_DataHash *inputHash;
	int aggrHashId;
	KSI_HashChain *chain;
};

struct calChainComponent_st {
	KSI_Integer *publicationTime;
	KSI_Integer *aggregationTime;
	KSI_DataHash *inputHash;
	KSI_HashChain *chain;
};

struct headerComponent_st {
	KSI_CTX *ctx;
	KSI_Integer *instanceId;
	KSI_Integer *messageId;
	unsigned char *clientId;
	int clientId_length;
};

/**
 * KSI Signature object
 */
struct KSI_Signature_st {
	KSI_CTX *ctx;

	/** Signed hash value */
	KSI_DataHash *signedHash;

	HeaderComponent *responseHeader;
	CalChainComponent *calendarChain;

	AggChainComponent **aggregationChain;
	int aggregationChain_count;

};

static void CalChainComponent_free(CalChainComponent *cal) {
	if (cal != NULL) {
		KSI_Integer_free(cal->aggregationTime);
		KSI_Integer_free(cal->publicationTime);
		KSI_HashChain_free(cal->chain);
		KSI_DataHash_free(cal->inputHash);
		KSI_free(cal);
	}
}

static void HeaderComponent_free(HeaderComponent *hdr) {
	if (hdr != NULL) {
		KSI_Integer_free(hdr->instanceId);
		KSI_Integer_free(hdr->messageId);
		KSI_free(hdr->clientId);
		KSI_free(hdr);
	}
}

static void AggrChainComponent_free(AggChainComponent *aggr) {
	if (aggr != NULL) {
		KSI_Integer_free(aggr->aggregationTime);
		KSI_Integer_free(aggr->chainIndex);
		KSI_free(aggr->inputData);
		KSI_DataHash_free(aggr->inputHash);
		KSI_HashChain_free(aggr->chain);
		KSI_free(aggr);
	}
}

static int AggrChainComponent_add(KSI_CTX *ctx, KSI_TLV *tlv, AggChainComponent *aggr) {
	int res = KSI_UNKNOWN_ERROR;
	int isLeft;
	uint8_t levelCorrection = 0;
	KSI_DataHash *siblingHash = NULL;
	KSI_DataHash *metaHash = NULL;
	KSI_HashChain *chainLink = NULL;

	switch (KSI_TLV_getTag(tlv)) {
		case 0x07:
			isLeft = 1;
			break;
		case 0x08:
			isLeft = 0;
			break;
		default:
			res = KSI_INVALID_ARGUMENT;
			goto cleanup;
	}

	KSI_TLV_PARSE_BEGIN(ctx, tlv)
		KSI_PARSE_TLV_ELEMENT_UINT8(0x01, &levelCorrection)
		KSI_PARSE_TLV_ELEMENT_IMPRINT(0x02, &siblingHash)
		default: printf("Unimplemented tag %d", KSI_TLV_getTag(__tlv));
	KSI_TLV_PARSE_END(res)
	if (res != KSI_OK) goto cleanup;

	res = KSI_HashChain_appendLink(ctx, siblingHash, isLeft, levelCorrection, &aggr->chain);
	if (res != KSI_OK) goto cleanup;

	siblingHash = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(siblingHash);
	KSI_DataHash_free(metaHash);

	return res;
}

static int CalChainComponent_add(KSI_CTX *ctx, KSI_TLV *tlv, CalChainComponent *cal) {
	int res;
	KSI_DataHash *hsh = NULL;
	unsigned char *imprint = NULL;
	int imprint_len = 0;
	int isLeft;

	/* Validate arguments. */
	switch (KSI_TLV_getTag(tlv)) {
		case 0x07:
			isLeft = 1;
			break;
		case 0x08:
			isLeft = 0;
			break;
		default:
			res = KSI_INVALID_ARGUMENT;
			goto cleanup;
	}

	res = KSI_TLV_cast(tlv, KSI_TLV_PAYLOAD_RAW);
	if (res != KSI_OK) goto cleanup;

	/* Extract the raw value from the tlv */
	res = KSI_TLV_getRawValue(tlv, &imprint, &imprint_len, 0);
	if (res != KSI_OK) goto cleanup;

	res = KSI_DataHash_fromImprint(ctx, imprint, imprint_len, &hsh);
	if (res != KSI_OK) goto cleanup;

	res = KSI_HashChain_appendLink(ctx, hsh, isLeft, 0, &cal->chain);
	if (res != KSI_OK) goto cleanup;

	hsh = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(imprint);
	KSI_DataHash_free(hsh);

	return res;
}

static int parseAggregationChain(KSI_CTX *ctx, KSI_TLV *tlv, KSI_Signature *sig) {
	KSI_ERR err;
	int res;
	int i;

	AggChainComponent *aggr = NULL;
	AggChainComponent **chainList = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);


	if (KSI_TLV_getTag(tlv) != 0x0801) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	aggr = KSI_new(AggChainComponent);
	if (aggr == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	aggr->aggrHashId = 0;
	aggr->aggregationTime = 0;
	aggr->chain = NULL;
	aggr->chainIndex = 0;
	aggr->inputData = NULL;
	aggr->inputData_len = 0;
	aggr->inputHash = NULL;

	KSI_TLV_PARSE_BEGIN(ctx, tlv)
		KSI_PARSE_TLV_ELEMENT_INTEGER	(0x02, &aggr->aggregationTime)
		KSI_PARSE_TLV_ELEMENT_INTEGER	(0x03, &aggr->chainIndex)
		KSI_PARSE_TLV_ELEMENT_RAW		(0x04, &aggr->inputData, &aggr->inputData_len)
		KSI_PARSE_TLV_ELEMENT_IMPRINT	(0x05, &aggr->inputHash)
		KSI_PARSE_TLV_ELEMENT_UINT8		(0x06, &aggr->aggrHashId)
		KSI_PARSE_TLV_ELEMENT_CB		(0x07, AggrChainComponent_add, aggr)
		KSI_PARSE_TLV_ELEMENT_CB		(0x08, AggrChainComponent_add, aggr)
	KSI_TLV_PARSE_END(res);

	KSI_CATCH(&err, res) goto cleanup;

	/* Create a new list, but do not change the existing list yet */
	chainList = KSI_calloc(sig->aggregationChain_count + 1, sizeof(AggChainComponent*));
	if (chainList == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	/* Copy pointers */
	for (i = 0; i < sig->aggregationChain_count; i++) {
		chainList[i] = sig->aggregationChain[i];
	}
	chainList[i] = aggr;
	aggr = NULL;

	/* Release old list and replace with new */
	KSI_free(sig->aggregationChain);
	sig->aggregationChain = chainList;
	sig->aggregationChain_count++;
	chainList = NULL;

	KSI_SUCCESS(&err);

cleanup:

	AggrChainComponent_free(aggr);
	KSI_free(chainList);

	return KSI_RETURN(&err);
}

static int KSI_Signature_new(KSI_CTX *ctx, KSI_Signature **sig) {
	KSI_ERR err;
	KSI_Signature *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(KSI_Signature);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->calendarChain = NULL;
	tmp->aggregationChain = NULL;
	tmp->aggregationChain_count = 0;

	*sig = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_Signature_free(tmp);

	return KSI_RETURN(&err);

}

static int CalChainComponent_new(KSI_CTX *ctx, CalChainComponent **cal) {
	KSI_ERR err;
	CalChainComponent *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(CalChainComponent);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->aggregationTime = 0;
	tmp->publicationTime = 0;
	tmp->chain = NULL;
	tmp->inputHash = NULL;

	*cal = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	CalChainComponent_free(tmp);

	return KSI_RETURN(&err);

}

static int HeaderComponent_new(KSI_CTX *ctx, HeaderComponent **hdr) {
	KSI_ERR err;
	HeaderComponent *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(HeaderComponent);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->clientId = NULL;
	tmp->clientId_length = 0;
	tmp->instanceId = NULL;
	tmp->messageId = NULL;

	*hdr = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	HeaderComponent_free(tmp);

	return KSI_RETURN(&err);

}


void KSI_Signature_free(KSI_Signature *sig) {
	int i;
	if (sig != NULL) {
		HeaderComponent_free(sig->responseHeader);
		CalChainComponent_free(sig->calendarChain);
		for (i = 0; i < sig->aggregationChain_count; i++) {
			AggrChainComponent_free(sig->aggregationChain[i]);
		}
		KSI_free(sig->aggregationChain);
		KSI_free(sig);
	}
}

int KSI_parseSignature(KSI_CTX *ctx, unsigned char *rawPdu, int rawPdu_len, KSI_Signature **signature) {
	KSI_ERR err;
	int res;

	uint32_t utc_time;
	KSI_Integer *status;
	KSI_Integer *requestId;
	char *errorMessage;

	KSI_Signature *sig = NULL;
	CalChainComponent *cal = NULL;
	HeaderComponent *hdr = NULL;


	KSI_BEGIN(ctx, &err);

	res = KSI_Signature_new(ctx, &sig);
	KSI_CATCH(&err, res) goto cleanup;

	res = CalChainComponent_new(ctx, &cal);
	KSI_CATCH(&err, res) goto cleanup;

	res = HeaderComponent_new(ctx, &hdr);
	KSI_CATCH(&err, res) goto cleanup;


	KSI_LOG_debug(ctx, "Starting to parse aggregation response.");

	KSI_TLV_PARSE_RAW_BEGIN(ctx, rawPdu, rawPdu_len)
		KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x200)
			KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x202)
				KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x01)
					KSI_PARSE_TLV_ELEMENT_INTEGER(0x05, &hdr->instanceId)
					KSI_PARSE_TLV_ELEMENT_INTEGER(0x06, &hdr->messageId)
					KSI_PARSE_TLV_ELEMENT_RAW(0x07, &hdr->clientId, &hdr->clientId_length);
				KSI_PARSE_TLV_NESTED_ELEMENT_END

				KSI_PARSE_TLV_ELEMENT_INTEGER(0x02, &requestId);
				KSI_PARSE_TLV_ELEMENT_INREGER(0x05, &status);
				KSI_PARSE_TLV_ELEMENT_UTF8STR(0x06, &errorMessage);

				KSI_PARSE_TLV_ELEMENT_CB(0x801, parseAggregationChain, sig) // Aggregation hash chain

				KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x802) // Calendar hash chain
					KSI_PARSE_TLV_ELEMENT_INTEGER(0x02, &cal->aggregationTime)
					KSI_PARSE_TLV_ELEMENT_INTEGER(0x01, &cal->publicationTime)
					KSI_PARSE_TLV_ELEMENT_IMPRINT(0x05, &cal->inputHash)
					KSI_PARSE_TLV_ELEMENT_CB(0x07, CalChainComponent_add, cal)
					KSI_PARSE_TLV_ELEMENT_CB(0x08, CalChainComponent_add, cal)
				KSI_PARSE_TLV_NESTED_ELEMENT_END

			KSI_PARSE_TLV_NESTED_ELEMENT_END
		KSI_PARSE_TLV_NESTED_ELEMENT_END
	KSI_TLV_PARSE_RAW_END(res);

	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashChain_getCalendarAggregationTime(cal->chain, cal->publicationTime, &utc_time);
	KSI_CATCH(&err, res) goto cleanup;

	if (!KSI_Integer_equalsUInt(cal->aggregationTime, utc_time)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Aggregation time mismatch.");
		goto cleanup;
	}

	sig->calendarChain = cal;
	cal = NULL;

	sig->responseHeader = hdr;
	hdr = NULL;

	KSI_LOG_debug(ctx, "aggr_time = %lld, pub_time = %lld", sig->calendarChain->aggregationTime, sig->calendarChain->publicationTime);

	KSI_DataHash *hsh1 = NULL;
	res = KSI_HashChain_aggregate(sig->aggregationChain[0]->chain, sig->aggregationChain[0]->inputHash,0, sig->aggregationChain[0]->aggrHashId, &hsh1);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Signed hash     ", sig->signedHash);
	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Aggr input  hash", sig->aggregationChain[0]->inputHash);
	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Aggr out hash   ", hsh1);
	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Cal input hash  ", sig->calendarChain->inputHash);

	KSI_DataHash *hsh2 = NULL;

	res = KSI_HashChain_aggregateCalendar(sig->calendarChain->chain, hsh1, &hsh2);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Cal out   hash  ", hsh2);
	KSI_DataHash_free(hsh1);
	KSI_DataHash_free(hsh2);


	KSI_LOG_debug(ctx, "Finished parsing successfully.");

	KSI_SUCCESS(&err);


	*signature = sig;
	sig = NULL;

cleanup:

	HeaderComponent_free(hdr);
	CalChainComponent_free(cal);
	KSI_Signature_free(sig);

	return KSI_RETURN(&err);
}

int KSI_Signature_getDataHash(KSI_Signature *sig, const KSI_DataHash **hsh) {
	KSI_ERR err;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);
	if (sig->signedHash == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	*hsh = sig->signedHash;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(h);

	return KSI_RETURN(&err);
}

int KSI_Signature_getSigningTime(KSI_Signature *sig, KSI_Integer *signTime) {
	KSI_ERR err;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	if (sig->calendarChain == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}
	signTime = sig->calendarChain->aggregationTime;

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_Signature_getSignerIdentity(KSI_Signature *sig, char ** identity) {
	*identity = "TODO!";
	return KSI_OK;
}

int KSI_Signature_getCalendarHash(KSI_Signature *sig, const KSI_DataHash **hsh) {
	KSI_ERR err;
	const KSI_DataHash *h = NULL;
	int res;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	if (sig->calendarChain == NULL || sig->calendarChain->chain == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

// TODO	res = KSI_HashNode_getDataHash(sig->calendarChain->chain, &h);
	KSI_CATCH(&err, res) goto cleanup;

	*hsh = h;
	h = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(h);

	return KSI_RETURN(&err);
}


