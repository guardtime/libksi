#include "ksi_internal.h"
#include "ksi_tlv.h"
#include "ksi_tlv_easy.h"

void KSI_Signature_free(KSI_Signature *sig) {
	if (sig != NULL) {
		KSI_free(sig->errorMessage);
		KSI_Header_free(sig->responseHeader);
		KSI_CalendarChain_free(sig->calendarChain);
		KSI_AggregationChain_free(sig->aggregationChain);
		KSI_free(sig);
	}
}

void KSI_CalendarChain_free(KSI_CalendarChain *cal) {
	if (cal != NULL) {
		KSI_HashNode_free(cal->chain);
		KSI_free(cal);
	}
}

void KSI_Header_free(KSI_Header *hdr) {
	if (hdr != NULL) {
		KSI_free(hdr->clientId);
		KSI_free(hdr);
	}
}

void KSI_AggregationChain_free(KSI_AggregationChain *aggr) {
	if (aggr != NULL) {
		KSI_free(aggr->inputData);
		KSI_DataHash_free(aggr->inputHash);
		KSI_free(aggr);
	}
}

static int calendarChain_add(KSI_CTX *ctx, KSI_TLV *tlv, KSI_HashNode **chainRoot) {
	int res;
	KSI_DataHash *hsh = NULL;
	unsigned char *imprint = NULL;
	int imprint_len = 0;
	int tlvTag;

	/* Validate arguments. */
	tlvTag = KSI_TLV_getTag(tlv);
	switch (tlvTag) {
		case 0x05:
			if (*chainRoot != NULL) {
				res = KSI_INVALID_FORMAT;
				goto cleanup;
			}
			break;
		case 0x07:
		case 0x08:
			if (*chainRoot == NULL) {
				res = KSI_INVALID_FORMAT;
				goto cleanup;
			}
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

	res = KSI_DataHash_fromImprint(tlv->ctx, imprint, imprint_len, &hsh);
	if (res != KSI_OK) goto cleanup;

	res = KSI_HashNode_buildCalendar(ctx, hsh, KSI_TLV_getTag(tlv) == 0x08, chainRoot);
	if (res != KSI_OK) goto cleanup;

cleanup:

	KSI_nofree(imprint);
	KSI_DataHash_free(hsh);

	return res;
}

int KSI_parseSignature(KSI_CTX *ctx, unsigned char *rawPdu, int rawPdu_len, KSI_Signature **signature) {
	KSI_ERR err;
	int res;

	uint32_t utc_time;

	KSI_Signature *sig = NULL;
	KSI_CalendarChain *cal = NULL;
	KSI_AggregationChain *aggr = NULL;
	KSI_Header *hdr = NULL;


	KSI_BEGIN(ctx, &err);

	sig = KSI_new(KSI_Signature);
	if (sig == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	sig->requestId = 0;
	sig->status = 0;
	sig->errorMessage = NULL;

	sig->calendarChain = NULL;
	sig->aggregationChain = NULL;

	cal = KSI_new(KSI_CalendarChain);
	if (cal == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	cal->aggregationTime = 0;
	cal->publicationTime = 0;
	cal->chain = NULL;
	cal->inputHash = NULL;

	hdr = KSI_new(KSI_Header);
	if (cal == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	hdr->clientId = NULL;
	hdr->clientId_length = 0;
	hdr->instanceId = 0;
	hdr->messageId = 0;

	aggr = KSI_new(KSI_AggregationChain);
	if (aggr == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	aggr->inputData = NULL;
	aggr->inputHash = NULL;

	KSI_LOG_debug(ctx, "Starting to parse aggregation response.");

	TLV_PDU_BEGIN(ctx, rawPdu, rawPdu_len)
		KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x202)
			KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x01)
				KSI_PARSE_TLV_ELEMENT_UINT32(0x05, &hdr->instanceId)
				KSI_PARSE_TLV_ELEMENT_UINT32(0x06, &hdr->messageId)
				KSI_PARSE_TLV_ELEMENT_RAW(0x07, &hdr->clientId, &hdr->clientId_length);
			KSI_PARSE_TLV_NESTED_ELEMENT_END

			KSI_PARSE_TLV_ELEMENT_UINT32(0x02, &sig->requestId);
			KSI_PARSE_TLV_ELEMENT_UINT32(0x05, &sig->status);
			KSI_PARSE_TLV_ELEMENT_UTF8STR(0x06, &sig->errorMessage);

			KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x801)
				KSI_PARSE_TLV_ELEMENT_UINT32(0x02, &aggr->aggregationTime)
				KSI_PARSE_TLV_ELEMENT_UINT32(0x03, &aggr->chainIndex)
				KSI_PARSE_TLV_ELEMENT_RAW(0x04, &aggr->inputData, &aggr->inputData_len)
				TLV_ELEMENT_IMPRINT(0x05, &aggr->inputHash)
				KSI_PARSE_TLV_ELEMENT_UINT8(0x06, &aggr->aggrHashId)


			KSI_PARSE_TLV_NESTED_ELEMENT_END

			KSI_PARSE_TLV_NESTED_ELEMENT_BEGIN(0x802)
				KSI_PARSE_TLV_ELEMENT_UINT32(0x02, &cal->aggregationTime)
				KSI_PARSE_TLV_ELEMENT_UINT32(0x01, &cal->publicationTime)
				TLV_ELEMENT_CB(0x05, calendarChain_add, &cal->chain)
				TLV_ELEMENT_CB(0x07, calendarChain_add, &cal->chain)
				TLV_ELEMENT_CB(0x08, calendarChain_add, &cal->chain)
			KSI_PARSE_TLV_NESTED_ELEMENT_END

		KSI_PARSE_TLV_NESTED_ELEMENT_END
	TLV_PDU_END(res);

	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_HashNode_getCalendarAggregationTime(cal->chain, cal->publicationTime, &utc_time);
	KSI_CATCH(&err, res) goto cleanup;

	if (utc_time != cal->aggregationTime) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Aggregation time mismatch.");
		goto cleanup;
	}

	sig->calendarChain = cal;
	cal = NULL;

	sig->responseHeader = hdr;
	hdr = NULL;

	sig->aggregationChain = aggr;
	aggr = NULL;

	KSI_LOG_debug(ctx, "status = %d, aggr_time = %lld, pub_time = %lld", sig->status, sig->calendarChain->aggregationTime, sig->calendarChain->publicationTime);


	KSI_LOG_debug(ctx, "Finished parsing successfully.");

	KSI_SUCCESS(&err);


	*signature = sig;
	sig = NULL;

cleanup:

	KSI_Header_free(hdr);
	KSI_AggregationChain_free(aggr);
	KSI_CalendarChain_free(cal);
	KSI_Signature_free(sig);

	return KSI_RETURN(&err);
}
