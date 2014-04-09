#include <string.h>

#include "ksi_internal.h"
#include "ksi_tlv_easy.h"

typedef struct calChainRec_st CalChainRec;
typedef struct aggrChainRec_st AggChainRec;
typedef struct headerRec_st HeaderRec;
typedef struct calAuthRec_st CalAuthRec;
typedef struct pubDataRec_st PubDataRec;
typedef struct sigDataRec_st SigDataRec;


struct calAuthRec_st {
	KSI_CTX *ctx;
	PubDataRec *pubData;
	char *sigAlgo;
	SigDataRec *sigData;
};

struct pubDataRec_st {
	KSI_CTX *ctx;
	KSI_Integer *pubTime;
	KSI_DataHash *pubHash;
};

struct sigDataRec_st {
	KSI_CTX *ctx;

	unsigned char *sigValue;
	int sigValue_len;

	unsigned char *cert;
	int cert_len;

	unsigned char *certId;
	int certId_len;

	char *certRepUri;
};

struct aggrChainRec_st {
	KSI_CTX *ctx;
	KSI_Integer *aggregationTime;
	KSI_Integer *chainIndex;
	unsigned char *inputData;
	int inputData_len;
	KSI_DataHash *inputHash;
	int aggrHashId;
	KSI_HashChain *chain;
};

struct calChainRec_st {
	KSI_Integer *publicationTime;
	KSI_Integer *aggregationTime;
	KSI_DataHash *inputHash;
	KSI_HashChain *chain;
};

struct headerRec_st {
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

	CalChainRec *calendarChain;

	AggChainRec **aggregationChain;
	int aggregationChain_count;

	CalAuthRec *calAuth;

};

static void PubDataRec_free (PubDataRec *pdc) {
	if (pdc != NULL) {
		KSI_Integer_free(pdc->pubTime);
		KSI_DataHash_free(pdc->pubHash);
		KSI_free(pdc);
	}
}

static void SigDataRec_free(SigDataRec *sdc) {
	if (sdc != NULL) {
		KSI_free(sdc->sigValue);
		KSI_free(sdc->cert);
		KSI_free(sdc->certId);
		KSI_free(sdc->certRepUri);
		KSI_free(sdc);
	}
}

static void CalAuthRec_free(CalAuthRec *calAuth) {
	if (calAuth != NULL) {
		PubDataRec_free(calAuth->pubData);
		KSI_free(calAuth->sigAlgo);
		SigDataRec_free(calAuth->sigData);

		KSI_free(calAuth);
	}
}

static void CalChainRec_free(CalChainRec *cal) {
	if (cal != NULL) {
		KSI_Integer_free(cal->aggregationTime);
		KSI_Integer_free(cal->publicationTime);
		KSI_HashChain_free(cal->chain);
		KSI_DataHash_free(cal->inputHash);
		KSI_free(cal);
	}
}

static void HeaderRec_free(HeaderRec *hdr) {
	if (hdr != NULL) {
		KSI_Integer_free(hdr->instanceId);
		KSI_Integer_free(hdr->messageId);
		KSI_free(hdr->clientId);
		KSI_free(hdr);
	}
}

static void AggrChainRec_free(AggChainRec *aggr) {
	if (aggr != NULL) {
		KSI_Integer_free(aggr->aggregationTime);
		KSI_Integer_free(aggr->chainIndex);
		KSI_free(aggr->inputData);
		KSI_DataHash_free(aggr->inputHash);
		KSI_HashChain_free(aggr->chain);
		KSI_free(aggr);
	}
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

static int CalChainRec_new(KSI_CTX *ctx, CalChainRec **cal) {
	KSI_ERR err;
	CalChainRec *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(CalChainRec);
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

	CalChainRec_free(tmp);

	return KSI_RETURN(&err);

}

static int HeaderRec_new(KSI_CTX *ctx, HeaderRec **hdr) {
	KSI_ERR err;
	HeaderRec *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	tmp = KSI_new(HeaderRec);
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

	HeaderRec_free(tmp);

	return KSI_RETURN(&err);

}

static int AggChainRec_new(KSI_CTX *ctx, AggChainRec **out) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	AggChainRec *tmp = NULL;
	tmp = KSI_new(AggChainRec);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->aggrHashId = 0;
	tmp->aggregationTime = NULL;
	tmp->chain = NULL;
	tmp->chainIndex = NULL;
	tmp->inputData = NULL;
	tmp->inputData_len = 0;
	tmp->inputHash = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	AggrChainRec_free(tmp);

	return KSI_RETURN(&err);
}

static int PubDataRed_new(KSI_CTX *ctx, PubDataRec **out) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	PubDataRec *tmp = NULL;
	tmp = KSI_new(PubDataRec);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->pubHash = NULL;
	tmp->pubTime = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	PubDataRec_free(tmp);

	return KSI_RETURN(&err);

}

static int CalAuthRec_new(KSI_CTX *ctx, CalAuthRec **out) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	CalAuthRec *tmp = NULL;
	tmp = KSI_new(CalAuthRec);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->pubData = NULL;
	tmp->sigAlgo = NULL;
	tmp->sigData = NULL;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	CalAuthRec_free(tmp);

	return KSI_RETURN(&err);

}

static int SigDataRec_new(KSI_CTX *ctx, SigDataRec **out) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	SigDataRec *tmp = NULL;
	tmp = KSI_new(SigDataRec);
	if (tmp == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->cert = NULL;
	tmp->certId = NULL;
	tmp->certId_len = 0;
	tmp->certRepUri = NULL;
	tmp->cert_len = 0;
	tmp->sigValue = NULL;
	tmp->sigValue_len = 0;

	*out = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	SigDataRec_free(tmp);

	return KSI_RETURN(&err);

}

static int AggrChainRec_addLink(KSI_CTX *ctx, KSI_TLV *tlv, AggChainRec *aggr) {
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

static int CalChainRec_addLink(KSI_CTX *ctx, KSI_TLV *tlv, CalChainRec *cal) {
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

static int parseAggregationChainRec(KSI_CTX *ctx, KSI_TLV *tlv, KSI_Signature *sig) {
	KSI_ERR err;
	int res;
	int i;

	AggChainRec *aggr = NULL;
	AggChainRec **chainList = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);


	if (KSI_TLV_getTag(tlv) != 0x0801) {
		KSI_FAIL(&err, KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = AggChainRec_new(ctx, &aggr);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_TLV_PARSE_BEGIN(ctx, tlv)
		KSI_PARSE_TLV_ELEMENT_INTEGER	(0x02, &aggr->aggregationTime)
		KSI_PARSE_TLV_ELEMENT_INTEGER	(0x03, &aggr->chainIndex)
		KSI_PARSE_TLV_ELEMENT_RAW		(0x04, &aggr->inputData, &aggr->inputData_len)
		KSI_PARSE_TLV_ELEMENT_IMPRINT	(0x05, &aggr->inputHash)
		KSI_PARSE_TLV_ELEMENT_UINT8		(0x06, &aggr->aggrHashId)
		KSI_PARSE_TLV_ELEMENT_CB		(0x07, AggrChainRec_addLink, aggr)
		KSI_PARSE_TLV_ELEMENT_CB		(0x08, AggrChainRec_addLink, aggr)
	KSI_TLV_PARSE_END(res);

	KSI_CATCH(&err, res) goto cleanup;

	/* Create a new list, but do not change the existing list yet */
	chainList = KSI_calloc(sig->aggregationChain_count + 1, sizeof(AggChainRec*));
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

	AggrChainRec_free(aggr);
	KSI_free(chainList);

	return KSI_RETURN(&err);
}

static int parsePublDataRecord(KSI_CTX *ctx, KSI_TLV *tlv, PubDataRec **pdr) {
	KSI_ERR err;
	int res;
	PubDataRec *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, pdr != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	res = PubDataRed_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;
	if (*pdr != NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Multiple publication data records.");
		goto cleanup;
	}

	KSI_TLV_PARSE_BEGIN(ctx, tlv)
		KSI_PARSE_TLV_ELEMENT_INTEGER(0x02, &tmp->pubTime)
		KSI_PARSE_TLV_ELEMENT_IMPRINT(0x04, &tmp->pubHash)
		KSI_PARSE_TLV_ELEMENT_UNKNOWN_LENIENT_IGNORE
	KSI_TLV_PARSE_END(res);
	KSI_CATCH(&err, res) goto cleanup;;

	if (tmp->pubTime == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Published Data: Missing publication time.");
		goto cleanup;

	}

	if (tmp->pubHash == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Published Data: Missing publication hash.");
		goto cleanup;

	}

	*pdr = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	PubDataRec_free(tmp);

	return KSI_RETURN(&err);
}

static int parseSigDataRecord(KSI_CTX *ctx, KSI_TLV *tlv, SigDataRec **sdr) {
	KSI_ERR err;
	int res;
	int count;
	SigDataRec *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, sdr != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	res = SigDataRec_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;
	if (*sdr != NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Multiple signature data records.");
		goto cleanup;
	}

	KSI_TLV_PARSE_BEGIN(ctx, tlv)
		KSI_PARSE_TLV_ELEMENT_RAW(0x01, &tmp->sigValue, &tmp->sigValue_len)
		KSI_PARSE_TLV_ELEMENT_RAW(0x02, &tmp->cert, &tmp->cert_len)
		KSI_PARSE_TLV_ELEMENT_RAW(0x03, &tmp->certId, &tmp->certId_len)
		KSI_PARSE_TLV_ELEMENT_UTF8STR(0x04, &tmp->certRepUri)
		KSI_PARSE_TLV_ELEMENT_UNKNOWN_LENIENT_IGNORE
	KSI_TLV_PARSE_END(res);
	KSI_CATCH(&err, res) goto cleanup;

	/* Check mandatory parameters. */
	if (tmp->sigValue == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signed Data: Missing signed value");
		goto cleanup;
	}

	/* Manual xor */
	count = 0 +
			(tmp->cert != NULL ? 1 : 0) +
			(tmp->certId != NULL ? 1 : 0) +
			(tmp->certRepUri != NULL ? 1 : 0);

	if (count == 0) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signed Data: Incomplete signed data.");
		goto cleanup;
	} else if (count != 1 ) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signed Data: More than one certificate specified.");
		goto cleanup;
	}

	*sdr = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	SigDataRec_free(tmp);

	return KSI_RETURN(&err);

}
static int parseCalAuthRec(KSI_CTX *ctx, KSI_TLV *tlv, CalAuthRec **car) {
	KSI_ERR err;
	int res;
	CalAuthRec *auth = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, car != NULL) goto cleanup;

	KSI_BEGIN(ctx, &err);

	if (*car != NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Multiple calendar auth records.");
		goto cleanup;
	}

	res = CalAuthRec_new(ctx, &auth);
	KSI_CATCH(&err, res);

	KSI_TLV_PARSE_BEGIN(ctx, tlv)
		KSI_PARSE_TLV_ELEMENT_CB(0x10, parsePublDataRecord, &auth->pubData)
		KSI_PARSE_TLV_ELEMENT_UTF8STR(0x0b, &auth->sigAlgo)
		KSI_PARSE_TLV_ELEMENT_CB(0x0c, parseSigDataRecord, &auth->sigData)
	KSI_TLV_PARSE_END(res);
	KSI_CATCH(&err, res) goto cleanup;

	/* Check mandatory parameters. */
	if (auth->pubData == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Calendar Auth Record: Missing publication data.");
		goto cleanup;
	}

	if (auth->sigAlgo == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Calendar Auth Record: Missing algorithm.");
		goto cleanup;
	}

	if (auth->sigData == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Calendar Auth Record: Missing signed data.");
		goto cleanup;
	}

	*car = auth;
	auth = NULL;

	KSI_SUCCESS(&err);

cleanup:

	CalAuthRec_free(auth);

	return KSI_RETURN(&err);
}

void KSI_Signature_free(KSI_Signature *sig) {
	int i;
	if (sig != NULL) {
		CalChainRec_free(sig->calendarChain);
		for (i = 0; i < sig->aggregationChain_count; i++) {
			AggrChainRec_free(sig->aggregationChain[i]);
		}
		KSI_free(sig->aggregationChain);
		CalAuthRec_free(sig->calAuth);
		KSI_free(sig);
	}
}

int KSI_parseSignature(KSI_CTX *ctx, unsigned char *rawPdu, int rawPdu_len, KSI_Signature **signature) {
	KSI_ERR err;
	int res;

	KSI_Integer *status = NULL;
	KSI_Integer *requestId = NULL;
	char *errorMessage;

	KSI_Signature *sig = NULL;
	CalChainRec *cal = NULL;
	HeaderRec *hdr = NULL;


	KSI_BEGIN(ctx, &err);

	res = KSI_Signature_new(ctx, &sig);
	KSI_CATCH(&err, res) goto cleanup;

	res = CalChainRec_new(ctx, &cal);
	KSI_CATCH(&err, res) goto cleanup;

	res = HeaderRec_new(ctx, &hdr);
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

				KSI_PARSE_TLV_ELEMENT_CB(0x801, parseAggregationChainRec, sig) // Aggregation hash chain

				KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x802) // Calendar hash chain
					KSI_PARSE_TLV_ELEMENT_INTEGER(0x02, &cal->aggregationTime)
					KSI_PARSE_TLV_ELEMENT_INTEGER(0x01, &cal->publicationTime)
					KSI_PARSE_TLV_ELEMENT_IMPRINT(0x05, &cal->inputHash)
					KSI_PARSE_TLV_ELEMENT_CB(0x07, CalChainRec_addLink, cal)
					KSI_PARSE_TLV_ELEMENT_CB(0x08, CalChainRec_addLink, cal)
				KSI_PARSE_TLV_NESTED_ELEMENT_END

				KSI_PARSE_TLV_ELEMENT_CB(0x0805, parseCalAuthRec, &sig->calAuth)

				KSI_PARSE_TLV_ELEMENT_UNKNOWN_LENIENT_IGNORE
			KSI_PARSE_TLV_NESTED_ELEMENT_END
			KSI_PARSE_TLV_ELEMENT_UNKNOWN_LENIENT_IGNORE
		KSI_PARSE_TLV_NESTED_ELEMENT_END
		KSI_PARSE_TLV_ELEMENT_UNKNOWN_LENIENT_IGNORE
	KSI_TLV_PARSE_RAW_END(res);
	KSI_CATCH(&err, res) goto cleanup;

	// TODO What else to do with message header ?
	KSI_LOG_debug(ctx, "Aggregation response: instanceId = %ld, messageId = %ld",
			(unsigned long long) KSI_Integer_getUInt64(hdr->instanceId),
			(unsigned long long) KSI_Integer_getUInt64(hdr->messageId));

	if (status != NULL && !KSI_Integer_equalsUInt(status, 0)) {
		char msg[1024];

		snprintf(msg, sizeof(msg), "Aggregation failed: %s", errorMessage);
		KSI_FAIL_EXT(&err, KSI_AGGREGATOR_ERROR, (unsigned long long)KSI_Integer_getUInt64(status), errorMessage);
		goto cleanup;
	}

	sig->calendarChain = cal;
	cal = NULL;

	res = KSI_Signature_validate(sig);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_LOG_debug(ctx, "Finished parsing successfully.");

	KSI_SUCCESS(&err);


	*signature = sig;
	sig = NULL;

cleanup:

	HeaderRec_free(hdr);
	CalChainRec_free(cal);
	KSI_Signature_free(sig);

	return KSI_RETURN(&err);
}

int KSI_Signature_getDataHash(KSI_Signature *sig, const KSI_DataHash **hsh) {
	KSI_ERR err;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	// TODO!

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

int KSI_Signature_validateInternal(KSI_Signature *sig) {
	KSI_ERR err;
	KSI_DataHash *hsh = NULL;
	uint32_t utc_time;
	int i;
	int res;
	int level;

	KSI_PRE(&err, sig != NULL) goto cleanup;
	KSI_BEGIN(sig->ctx, &err);

	if (sig->aggregationChain == NULL || sig->aggregationChain_count == 0) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signature does not contain any aggregation chains.");
		goto cleanup;
	}

	if (sig->calendarChain == NULL) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signature does not contain a calendar chain.");
		goto cleanup;
	}

	if (sig->calAuth == NULL) { // Add aggr auth
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Signature does not contain any authentication record.");
		goto cleanup;
	}

	/* Validate aggregation time */
	res = KSI_HashChain_getCalendarAggregationTime(sig->calendarChain->chain, sig->calendarChain->publicationTime, &utc_time);
	KSI_CATCH(&err, res) goto cleanup;

	if (!KSI_Integer_equalsUInt(sig->calendarChain->aggregationTime, utc_time)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Aggregation time mismatch.");
		goto cleanup;
	}

	/* Aggregate aggregation chains. */
	hsh = NULL;
	level = 0;
	for (i = 0; i < sig->aggregationChain_count; i++) {
		AggChainRec* aggregationChain = sig->aggregationChain[i];
		KSI_DataHash *tmpHash = NULL;

		if (hsh != NULL) {
			/* Validate input hash */
			if (!KSI_DataHash_equals(hsh, aggregationChain->inputHash)) {
				KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Aggregation chain mismatch,");
			}
		}

		res = KSI_HashChain_aggregate(aggregationChain->chain, aggregationChain->inputHash, level, aggregationChain->aggrHashId, &level, &tmpHash);
		KSI_CATCH(&err, res) {
			KSI_FAIL(&err, res, "Failed to calculate aggregation chain.");
			goto cleanup;
		}

		if (hsh != NULL) {
			KSI_DataHash_free(hsh);
		}
		hsh = tmpHash;
	}

	/* Validate calendar input hash */
	if (!KSI_DataHash_equals(hsh, sig->calendarChain->inputHash)) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Calendar chain input hash mismatch.");
		goto cleanup;
	}

	KSI_DataHash_free(hsh);
	hsh = NULL;

	/* Aggregate calendar chain */
	res = KSI_HashChain_aggregateCalendar(sig->calendarChain->chain, sig->calendarChain->inputHash, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	/* Validate calendar root hash */
	if (!KSI_DataHash_equals(hsh, sig->calAuth->pubData->pubHash)) {
		KSI_FAIL(&err, KSI_INVALID_SIGNATURE, "Calendar chain root hash mismatch.");
		goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_DataHash_free(hsh);

	return KSI_RETURN(&err);
}

int KSI_Signature_validate(KSI_Signature *sig) {
	int res;
	res = KSI_Signature_validateInternal(sig);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

