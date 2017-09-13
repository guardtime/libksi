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

#include <string.h>

#include "internal.h"
#include "tlv.h"
#include "hmac.h"
#include "tlv_template.h"
#include "hashchain.h"
#include "ctx_impl.h"
#include "pkitruststore.h"
#include "net.h"
#include "net_async.h"
#include "tlv_element.h"
#include "impl/meta_data_impl.h"
#include "impl/meta_data_element_impl.h"

KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendReqPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendRespPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationReqPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationRespPdu);
KSI_IMPORT_TLV_TEMPLATE(KSI_Header);
KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendReq);
KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendResp);
KSI_IMPORT_TLV_TEMPLATE(KSI_ExtendResp_v2);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationReq);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationReq_v2);
KSI_IMPORT_TLV_TEMPLATE(KSI_ConfigReq);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationConf);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationResp);
KSI_IMPORT_TLV_TEMPLATE(KSI_AggregationResp_v2);

struct KSI_ErrorPdu_st{
	KSI_CTX *ctx;
	KSI_Integer *status;
	KSI_Utf8String *errorMsg;
};

struct KSI_ExtendPdu_st {
	KSI_CTX *ctx;
	KSI_Header *header;
	KSI_ExtendReq *request;
	KSI_ExtendResp *response;
	KSI_Config *confRequest;
	KSI_Config *confResponse;
	KSI_ErrorPdu *error;
	KSI_DataHash *hmac;
	KSI_OctetString *raw;
};

struct KSI_AggregationPdu_st {
	KSI_CTX *ctx;
	KSI_Header *header;
	KSI_AggregationReq *request;
	KSI_AggregationResp *response;
	KSI_Config *confRequest;
	KSI_Config *confResponse;
	KSI_RequestAck *ackRequest;
	KSI_RequestAck *ackResponse;
	KSI_ErrorPdu *error;
	KSI_DataHash *hmac;
	KSI_OctetString *raw;
};

struct KSI_Header_st {
	KSI_CTX *ctx;
	KSI_Integer *instanceId;
	KSI_Integer *messageId;
	KSI_Utf8String *loginId;
	KSI_OctetString *raw;
};

struct KSI_Config_st {
	size_t ref;

	KSI_CTX *ctx;
	KSI_Integer *maxLevel;
	KSI_Integer *aggrAlgo;
	KSI_Integer *aggrPeriod;
	KSI_Integer *maxRequests;
	KSI_Integer *calendarFirstTime;
	KSI_Integer *calendarLastTime;
	KSI_LIST(KSI_Utf8String) *parentUri;
};

struct KSI_AggregationReq_st {
	size_t ref;
	KSI_CTX *ctx;
	KSI_Integer *requestId;
	KSI_DataHash *requestHash;
	KSI_Integer *requestLevel;
	KSI_Config *config;
	KSI_OctetString *raw;
};

struct KSI_RequestAck_st {
	KSI_CTX *ctx;
	KSI_Integer *requestTime;
	KSI_Integer *receiptTime;
	KSI_Integer *acknowledgeTime;
	KSI_Integer *aggregationPeriod;
	KSI_Integer *aggregationDelay;
	KSI_Integer *aggregationDrift;
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
	KSI_OctetString *raw;
};

struct KSI_ExtendReq_st {
	size_t ref;
	KSI_CTX *ctx;
	KSI_Integer *requestId;
	KSI_Integer *aggregationTime;
	KSI_Integer *publicationTime;
	KSI_Config *config;
	KSI_OctetString *raw;
};

struct KSI_ExtendResp_st {
	KSI_CTX *ctx;
	KSI_Integer *requestId;
	KSI_Integer *status;
	KSI_Utf8String *errorMsg;
	KSI_Config *config;
	KSI_Integer *lastTime;
	KSI_CalendarHashChain *calendarHashChain;
	KSI_TLV *baseTlv;
	KSI_OctetString *raw;
};

struct KSI_PKISignedData_st {
	KSI_CTX *ctx;
	KSI_Utf8String *sig_type;
	KSI_OctetString *signatureValue;
	KSI_OctetString *certId;
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

KSI_IMPLEMENT_LIST(KSI_MetaDataElement, KSI_MetaDataElement_free);
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
KSI_IMPLEMENT_LIST(KSI_RequestHandle, KSI_RequestHandle_free);
KSI_IMPLEMENT_LIST(KSI_AsyncHandle, KSI_AsyncHandle_free);

KSI_IMPLEMENT_REF(KSI_MetaDataElement);
KSI_IMPLEMENT_REF(KSI_MetaData);
/**
 * KSI_MetaData
 */
void KSI_MetaDataElement_free(KSI_MetaDataElement *t) {
	if (t != NULL && --t->ref == 0) {
		KSI_TlvElement_free(t->impl);
		KSI_Utf8String_free(t->DEPRECATED_clientId);
		KSI_Utf8String_free(t->DEPRECATED_machineId);
		KSI_Integer_free(t->DEPRECATED_reqTimeInMicros);
		KSI_Integer_free(t->DEPRECATED_sequenceNr);
		KSI_free(t);
	}
}

int KSI_MetaDataElement_new(KSI_CTX *ctx, KSI_MetaDataElement **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MetaDataElement *tmp = NULL;
	tmp = KSI_new(KSI_MetaDataElement);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;
	tmp->impl = NULL;

	tmp->DEPRECATED_clientId = NULL;
	tmp->DEPRECATED_machineId = NULL;
	tmp->DEPRECATED_reqTimeInMicros = NULL;
	tmp->DEPRECATED_sequenceNr = NULL;

	res = KSI_TlvElement_new(&tmp->impl);
	if (res != KSI_OK) goto cleanup;

	tmp->impl->ftlv.tag = 0x04;

	*t = tmp;
	tmp = NULL;

	res = KSI_OK;
cleanup:

	KSI_MetaDataElement_free(tmp);
	return res;
}

int KSI_MetaDataElement_getClientId(KSI_MetaDataElement *o, KSI_Utf8String** clientId) {
	int res = KSI_UNKNOWN_ERROR;

	if (o == NULL || clientId == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (o->DEPRECATED_clientId == NULL) {
		res = KSI_TlvElement_getUtf8String(o->impl, o->ctx, 0x01, &o->DEPRECATED_clientId);
		if (res != KSI_OK) goto cleanup;
	}

	*clientId = o->DEPRECATED_clientId;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MetaDataElement_getMachineId(KSI_MetaDataElement *o, KSI_Utf8String** machineId) {
	int res = KSI_UNKNOWN_ERROR;

	if (o == NULL || machineId == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (o->DEPRECATED_machineId == NULL) {
		res = KSI_TlvElement_getUtf8String(o->impl, o->ctx, 0x02, &o->DEPRECATED_machineId);
		if (res != KSI_OK) goto cleanup;
	}

	*machineId = o->DEPRECATED_machineId;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MetaDataElement_getSequenceNr(KSI_MetaDataElement *o, KSI_Integer** sequenceNr) {
	int res = KSI_UNKNOWN_ERROR;

	if (o == NULL || sequenceNr == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (o->DEPRECATED_sequenceNr == NULL) {
		res = KSI_TlvElement_getInteger(o->impl, o->ctx, 0x03, &o->DEPRECATED_sequenceNr);
		if (res != KSI_OK) goto cleanup;
	}

	*sequenceNr = o->DEPRECATED_sequenceNr;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MetaDataElement_getRequestTimeInMicros(KSI_MetaDataElement *o, KSI_Integer** reqTimeInMicros) {
	int res = KSI_UNKNOWN_ERROR;

	if (o == NULL || reqTimeInMicros == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (o->DEPRECATED_reqTimeInMicros == NULL) {
		res = KSI_TlvElement_getInteger(o->impl, o->ctx, 0x04, &o->DEPRECATED_reqTimeInMicros);
		if (res != KSI_OK) goto cleanup;
	}

	*reqTimeInMicros = o->DEPRECATED_reqTimeInMicros;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MetaDataElement_setClientId(KSI_MetaDataElement *o, KSI_Utf8String*  clientId) {
	int res = KSI_UNKNOWN_ERROR;
	res = KSI_TlvElement_setUtf8String(o->impl, 0x01, clientId);
	if (res != KSI_OK) goto cleanup;

	o->DEPRECATED_clientId = clientId;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MetaDataElement_setMachineId(KSI_MetaDataElement *o, KSI_Utf8String*  machineId) {
	int res = KSI_UNKNOWN_ERROR;
	res =  KSI_TlvElement_setUtf8String(o->impl, 0x02, machineId);
	if (res != KSI_OK) goto cleanup;

	o->DEPRECATED_machineId = machineId;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MetaDataElement_setSequenceNr(KSI_MetaDataElement *o, KSI_Integer*  sequenceNr) {
	int res = KSI_UNKNOWN_ERROR;
	res = KSI_TlvElement_setInteger(o->impl, 0x03, sequenceNr);
	if (res != KSI_OK) goto cleanup;

	o->DEPRECATED_sequenceNr = sequenceNr;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MetaDataElement_setRequestTimeInMicros(KSI_MetaDataElement *o, KSI_Integer*  reqTimeInMicros) {
	int res = KSI_UNKNOWN_ERROR;
	res =  KSI_TlvElement_setInteger(o->impl, 0x04, reqTimeInMicros);
	if (res != KSI_OK) goto cleanup;

	o->DEPRECATED_reqTimeInMicros = reqTimeInMicros;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_MetaDataElement_toTlv(KSI_CTX *ctx, const KSI_MetaDataElement *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_TLV *tmp = NULL;
	unsigned char buf[0xffff + 4];
	size_t len;
	KSI_TlvElement *el = NULL;

	if (ctx == NULL || data == NULL || tlv == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Make sure the required elements are present. */
	res = KSI_TlvElement_getElement(data->impl, 0x01, &el);
	if (res != KSI_OK || el == NULL) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	/* Serialize the tlv. */
	res = KSI_TlvElement_serialize(data->impl, buf, sizeof(buf), &len, KSI_TLV_OPT_NO_HEADER);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TLV_new(ctx, data->impl->ftlv.tag, data->impl->ftlv.is_nc, data->impl->ftlv.is_fwd, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TLV_setRawValue(tmp, buf, len);
	if (res != KSI_OK) goto cleanup;

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TlvElement_free(el);
	KSI_TLV_free(tmp);

	return res;
}

int KSI_MetaDataElement_fromTlv(KSI_TLV *tlv, KSI_MetaDataElement **metaData) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MetaDataElement *tmp = NULL;
	unsigned char *ptr = NULL;
	size_t len;
	KSI_TlvElement *el = NULL;

	if (tlv == NULL || metaData == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_MetaDataElement_new(KSI_TLV_getCtx(tlv), &tmp);
	if (res != KSI_OK) goto cleanup;

	tmp->impl->ftlv.tag = KSI_TLV_getTag(tlv);
	tmp->impl->ftlv.is_fwd = KSI_TLV_isForward(tlv);
	tmp->impl->ftlv.is_nc = KSI_TLV_isNonCritical(tlv);

	/* Cast is safe, as we are not about to change the value. */
	res = KSI_TLV_getRawValue(tlv, (const unsigned char **)&ptr, &len);
	if (res != KSI_OK) goto cleanup;

	tmp->impl->ptr = ptr;
	tmp->impl->ftlv.dat_len = len;

	/* Detach the element. */
	res = KSI_TlvElement_detach(tmp->impl);
	if (res != KSI_OK) goto cleanup;

	/* Make sure the required elements are present. */
	res = KSI_TlvElement_getElement(tmp->impl, 0x01, &el);
	if (res != KSI_OK || el == NULL) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	*metaData = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TlvElement_free(el);
	KSI_MetaDataElement_free(tmp);

	return res;
}

static int KSI_MetaData_toMetaDataElement(const KSI_MetaData *in, KSI_MetaDataElement **out) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MetaDataElement *tmp = NULL;
	unsigned char buf[0xffff + 4];
	size_t len;

	if (in == NULL || out == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_MetaDataElement_new(in->ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = in->serializePayload(in, buf, sizeof(buf), &len);
	if (res != KSI_OK) goto cleanup;

	tmp->impl->ptr = buf;
	tmp->impl->ftlv.dat_len = len;

	res = KSI_TlvElement_detach(tmp->impl);
	if (res != KSI_OK) goto cleanup;

	*out = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_MetaDataElement_free(tmp);

	return res;
}

static int KSI_MetaData_serializePayload(const KSI_MetaData *t, unsigned char *buf, size_t buf_size, size_t *buf_len) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MetaDataElement *mdEl = NULL;
	KSI_TlvElement *padding = NULL;
	size_t len;
	static unsigned char padEven[] = { 0x01, 0x01 };
	static unsigned char padOdd[] = { 0x01 };

	if (t == NULL || (buf == NULL && buf_size != 0)) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_MetaDataElement_new(t->ctx, &mdEl);
	if (res != KSI_OK) goto cleanup;

	res = KSI_TlvElement_new(&padding);
	if (res != KSI_OK) goto cleanup;

	padding->ftlv.tag = 0x1e;
	padding->ftlv.is_fwd = 1;
	padding->ftlv.is_nc = 1;

	/* Add the padding as the first element. */
	res = KSI_TlvElement_appendElement(mdEl->impl, padding);
	if (res != KSI_OK) goto cleanup;

	/* Add the values to the meta-data element. */
	if (t->clientId != NULL) {
		KSI_Utf8String *ref = NULL;
		res = KSI_MetaDataElement_setClientId(mdEl, ref = KSI_Utf8String_ref(t->clientId));
		if (res != KSI_OK) {
			/* Cleanup the reference. */
			KSI_Utf8String_free(ref);

			goto cleanup;
		}
	}

	if (t->machineId != NULL) {
		KSI_Utf8String *ref = NULL;

		res = KSI_MetaDataElement_setMachineId(mdEl, ref = KSI_Utf8String_ref(t->machineId));

		if (res != KSI_OK) {
			/* Cleanup the reference. */
			KSI_Utf8String_free(ref);

			goto cleanup;
		}
	}

	if (t->sequenceNr != NULL) {
		KSI_Integer *ref = NULL;

		res = KSI_MetaDataElement_setSequenceNr(mdEl, ref = KSI_Integer_ref(t->sequenceNr));

		if (res != KSI_OK) {
			/* Cleanup the reference. */
			KSI_Integer_free(ref);

			goto cleanup;
		}
	}

	if (t->reqTimeInMicros) {
		KSI_Integer *ref = NULL;

		res = KSI_MetaDataElement_setRequestTimeInMicros(mdEl, ref = KSI_Integer_ref(t->reqTimeInMicros));
		if (res != KSI_OK) {
			/* Cleanup the reference. */
			KSI_Integer_free(ref);

			goto cleanup;
		}
	}

	/* Calculate the length of the payload. */
	res = KSI_TlvElement_serialize(mdEl->impl, NULL, 0, &len, KSI_TLV_OPT_NO_HEADER);
	if (res != KSI_OK) goto cleanup;

	if (len % 2 == 0) {
		padding->ptr = padEven;
		padding->ftlv.dat_len = sizeof(padEven);
	} else {
		padding->ptr = padOdd;
		padding->ftlv.dat_len = sizeof(padOdd);
	}

	res = KSI_TlvElement_serialize(mdEl->impl, buf, buf_size, buf_len, KSI_TLV_OPT_NO_HEADER);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	KSI_MetaDataElement_free(mdEl);
	KSI_TlvElement_free(padding);
	return res;
}

void KSI_MetaData_free(KSI_MetaData *t) {
	if (t != NULL && --t->ref == 0) {
		KSI_Utf8String_free(t->clientId);
		KSI_Utf8String_free(t->machineId);
		KSI_Integer_free(t->reqTimeInMicros);
		KSI_Integer_free(t->sequenceNr);
		KSI_free(t);
	}
}

int KSI_MetaData_new(KSI_CTX *ctx, KSI_MetaData **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_MetaData *tmp = NULL;

	if (ctx == NULL || t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = KSI_new(KSI_MetaData);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->clientId = NULL;
	tmp->ctx = ctx;
	tmp->machineId = NULL;
	tmp->ref = 1;
	tmp->reqTimeInMicros = NULL;
	tmp->sequenceNr = NULL;
	tmp->toMetaDataElement = KSI_MetaData_toMetaDataElement;
	tmp->serializePayload = KSI_MetaData_serializePayload;

	*t = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_MetaData_free(tmp);

	return res;
}

static int voidSetter(void **p, void *val, void (*val_free)(void *), void *(*val_ref)(void *)) {
	int res = KSI_UNKNOWN_ERROR;

	if (p == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	val_free(*p);
	*p = val_ref(val);

	res = KSI_OK;

cleanup:

	return res;
}

#define VOID_SETTER(var, val, typ) voidSetter((void **)&var, val, (void (*)(void *))typ##_free, (void *(*)(void *))typ##_ref)

int KSI_MetaData_setClientId(KSI_MetaData *t, KSI_Utf8String *clientId) {
	return VOID_SETTER(t->clientId, clientId, KSI_Utf8String);
}

int KSI_MetaData_setMachineId(KSI_MetaData *t, KSI_Utf8String *machineId) {
	return VOID_SETTER(t->machineId, machineId, KSI_Utf8String);
}
int KSI_MetaData_setSequenceNr(KSI_MetaData *t, KSI_Integer *sequenceNr) {
	return VOID_SETTER(t->sequenceNr, sequenceNr, KSI_Integer);
}
int KSI_MetaData_setRequestTimeInMicros(KSI_MetaData *t, KSI_Integer *reqTime) {
	return VOID_SETTER(t->reqTimeInMicros, reqTime, KSI_Integer);
}

void KSI_ErrorPdu_free(KSI_ErrorPdu *t) {
	if (t != NULL) {
		KSI_Integer_free(t->status);
		KSI_Utf8String_free(t->errorMsg);
		KSI_free(t);
	}
}

int KSI_ErrorPdu_new(KSI_CTX *ctx, KSI_ErrorPdu **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ErrorPdu *tmp = NULL;
	tmp = KSI_new(KSI_ErrorPdu);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->status = NULL;
	tmp->errorMsg = NULL;

	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_ErrorPdu_free(tmp);
	return res;
}


KSI_IMPLEMENT_GETTER(KSI_ErrorPdu, KSI_Integer*, status, Status);
KSI_IMPLEMENT_GETTER(KSI_ErrorPdu, KSI_Utf8String*, errorMsg, ErrorMessage);

KSI_IMPLEMENT_SETTER(KSI_ErrorPdu, KSI_Integer*, status, Status);
KSI_IMPLEMENT_SETTER(KSI_ErrorPdu, KSI_Utf8String*, errorMsg, ErrorMessage);


/**
 * KSI_ExtendPdu
 */
void KSI_ExtendPdu_free(KSI_ExtendPdu *t) {
	if (t != NULL) {
		KSI_Header_free(t->header);
		KSI_ExtendReq_free(t->request);
		KSI_ExtendResp_free(t->response);
		KSI_ExtendConf_free(t->confRequest);
		KSI_ExtendConf_free(t->confResponse);
		KSI_ErrorPdu_free(t->error);
		KSI_DataHash_free(t->hmac);
		KSI_OctetString_free(t->raw);
		KSI_free(t);
	}
}

int KSI_ExtendPdu_new(KSI_CTX *ctx, KSI_ExtendPdu **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendPdu *tmp = NULL;
	tmp = KSI_new(KSI_ExtendPdu);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->header = NULL;
	tmp->request = NULL;
	tmp->response = NULL;
	tmp->confRequest = NULL;
	tmp->confResponse = NULL;
	tmp->error = NULL;
	tmp->hmac = NULL;
	tmp->raw = NULL;

	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_ExtendPdu_free(tmp);
	return res;
}

static KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_OctetString*, raw, Raw);
static KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_OctetString*, raw, Raw);
static KSI_IMPLEMENT_GETTER(KSI_AggregationReq, KSI_OctetString*, raw, Raw);
static KSI_IMPLEMENT_GETTER(KSI_AggregationResp, KSI_OctetString*, raw, Raw);
static KSI_IMPLEMENT_GETTER(KSI_Header, KSI_OctetString*, raw, Raw);
static KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_OctetString*, raw, Raw);
static KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_OctetString*, raw, Raw);

static int getObjectsRawValue(KSI_CTX* ctx, const void* obj, int (*getRaw)(const void*, KSI_OctetString**), const KSI_TlvTemplate *template, int tag, const unsigned char **data, size_t *len, bool* mustBeFreed){
	int res = KSI_OK;
	KSI_OctetString *raw = NULL;
	*mustBeFreed = false;
	if (ctx && obj) {
		getRaw(obj, &raw);
		if (raw){
			res = KSI_OctetString_extract(raw, data, len);
			if (res != KSI_OK) goto cleanup;
		} else{
			res = KSI_TlvTemplate_serializeObject(ctx, obj, tag, 0, 0, template, (unsigned char **)data, len);
			if (res != KSI_OK) goto cleanup;
			*mustBeFreed = true;
		}
	} else {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

cleanup:

	return res;
}

int pdu_verifyHmac(KSI_CTX *ctx, const KSI_DataHash *hmac, const char *key, KSI_HashAlgorithm conf_alg,
		int (*calculateHmac)(const void*, int, const char*, KSI_DataHash**), void *pdu){
	int res;
	KSI_DataHash *actualHmac = NULL;
	KSI_HashAlgorithm algo_id;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || hmac == NULL || key == NULL || calculateHmac == NULL || pdu == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_getHashAlg(hmac, &algo_id);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* If configured, check if HMAC algorithm matches. */
	if (conf_alg != KSI_HASHALG_INVALID && algo_id != conf_alg)	{
		KSI_LOG_debug(ctx, "HMAC algorithm mismatch. Expected %s, received %s",
				KSI_getHashAlgorithmName(conf_alg), KSI_getHashAlgorithmName(algo_id));
		KSI_pushError(ctx, res = KSI_HMAC_ALGORITHM_MISMATCH, "HMAC algorithm mismatch.");
		goto cleanup;
	}

	res = calculateHmac(pdu, algo_id, key, &actualHmac);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Check HMAC. */
	if (!KSI_DataHash_equals(hmac, actualHmac)){
		KSI_LOG_debug(ctx, "Verifying HMAC failed.");
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "Calculated HMAC", actualHmac);
		KSI_LOG_logDataHash(ctx, KSI_LOG_DEBUG, "HMAC from response", hmac);
		KSI_pushError(ctx, res = KSI_HMAC_MISMATCH, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(actualHmac);

	return res;
}

static int pdu_calculateHmac(KSI_CTX* ctx, const void* pdu,
		int (*getHeader)(const void*, KSI_Header**),
		int (*getResponse)(const void*, void**),
		int (*getResponse_raw)(const void*, KSI_OctetString**),
		int (*getRequest)(const void*, void**),
		int (*getRequest_raw)(const void*, KSI_OctetString**),
		int reqTag,	int respTag,
		const KSI_TlvTemplate *reqTemplate, const KSI_TlvTemplate *respTemplate,
		KSI_HashAlgorithm algo_id, const char *key, KSI_DataHash **hmac) {
	int res;
	KSI_Header *header = NULL;
	const unsigned char *raw_header = NULL;
	size_t header_len;
	const unsigned char *raw_payload = NULL;
	size_t payload_len;
	void *request = NULL;
	void *response = NULL;
	unsigned char *buf = NULL;
	KSI_DataHash *tmp = NULL;

	bool freeRawHeader = false;
	bool freeRawPayload = false;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || pdu == NULL || key == NULL || hmac == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (getHeader == NULL || getResponse == NULL || getResponse_raw == NULL ||
			getRequest == NULL || getRequest_raw == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Function pointers not initialized.");
		goto cleanup;
	}

	res = getHeader(pdu, &header);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (header == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Missing header from pdu.");
		goto cleanup;
	}

	res = getObjectsRawValue(ctx, header, (int (*)(const void*, KSI_OctetString**))KSI_Header_getRaw, KSI_TLV_TEMPLATE(KSI_Header), 0x01, &raw_header, &header_len, &freeRawHeader);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = getRequest(pdu, &request);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = getResponse(pdu, &response);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (request != NULL) {
		res = getObjectsRawValue(ctx, request, getRequest_raw, reqTemplate, reqTag, &raw_payload, &payload_len, &freeRawPayload);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	} else if (response != NULL) {
		res = getObjectsRawValue(ctx, response, getResponse_raw, respTemplate, respTag, &raw_payload, &payload_len, &freeRawPayload);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	} else {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Missing payload.");
		goto cleanup;
	}

	buf = KSI_malloc(payload_len + header_len);
	if (buf == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	memcpy(buf, raw_header, header_len);
	memcpy(buf+header_len, raw_payload, payload_len);

	res = KSI_HMAC_create(header->ctx, algo_id, key, buf, header_len + payload_len, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*hmac = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	if (freeRawHeader) KSI_free((void *)raw_header);
	if (freeRawPayload)	KSI_free((void *)raw_payload);
	KSI_free(buf);
	KSI_DataHash_free(tmp);

	return res;
}

static int pdu_calculateHmac_v2(KSI_CTX* ctx, const void* pdu,
		int (*getHeader)(const void*, KSI_Header**),
		int (*getResponse)(const void*, void**),
		int (*getResponse_raw)(const void*, KSI_OctetString**),
		int (*getRequest)(const void*, void**),
		int (*getRequest_raw)(const void*, KSI_OctetString**),
		int reqTag,	int respTag,
		const KSI_TlvTemplate *reqTemplate, const KSI_TlvTemplate *respTemplate,
		KSI_HashAlgorithm algo_id, const char *key, KSI_DataHash **hmac) {
	int res;
	KSI_Header *header = NULL;
	size_t payload_len;
	const unsigned char *raw_payload = NULL;
	void *request = NULL;
	void *response = NULL;
	KSI_DataHash *tmp = NULL;
	bool freeRawPayload = false;

	KSI_ERR_clearErrors(ctx);
	if (ctx == NULL || pdu == NULL || key == NULL || hmac == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	if (getHeader == NULL || getResponse == NULL || getResponse_raw == NULL ||
			getRequest == NULL || getRequest_raw == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Function pointers not initialized.");
		goto cleanup;
	}

	res = getHeader(pdu, &header);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (header == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Missing header from pdu.");
		goto cleanup;
	}

	res = getRequest(pdu, &request);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = getResponse(pdu, &response);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (request != NULL) {
		res = getObjectsRawValue(ctx, pdu, getRequest_raw, reqTemplate, reqTag, &raw_payload, &payload_len, &freeRawPayload);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	} else if (response != NULL) {
		res = getObjectsRawValue(ctx, pdu, getResponse_raw, respTemplate, respTag, &raw_payload, &payload_len, &freeRawPayload);
		if (res != KSI_OK) {
			KSI_pushError(ctx, res, NULL);
			goto cleanup;
		}
	} else {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, "Missing payload.");
		goto cleanup;
	}

	res = KSI_HMAC_create(ctx, algo_id, key, raw_payload, payload_len - KSI_getHashLength(algo_id), &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, "Failed to calculate HMAC from serialized PDU.");
		goto cleanup;
	}

	*hmac = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	if (freeRawPayload) KSI_free((void *)raw_payload);
	KSI_DataHash_free(tmp);

	return res;
}

int KSI_ExtendPdu_verifyHmac(const KSI_ExtendPdu *pdu, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *respHmac = NULL;

	res = KSI_ExtendPdu_getHmac(pdu, &respHmac);
	if (res != KSI_OK) {
		KSI_pushError(pdu->ctx, res, NULL);
		goto cleanup;
	}

	res = pdu_verifyHmac(pdu->ctx, respHmac, pass,
			(KSI_HashAlgorithm)pdu->ctx->options[KSI_OPT_EXT_HMAC_ALGORITHM],
			(int (*)(const void*, int, const char*, KSI_DataHash**))KSI_ExtendPdu_calculateHmac,
			(void*)pdu);
	if (res != KSI_OK) {
		KSI_pushError(pdu->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_ExtendPdu_calculateHmac(const KSI_ExtendPdu *t, KSI_HashAlgorithm algo_id, const char *key, KSI_DataHash **hmac){
	int res = KSI_OK;
	if (t == NULL || t->ctx == NULL)
		return KSI_INVALID_ARGUMENT;

	if (t->ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_1) {
		res = pdu_calculateHmac(t->ctx, (const void*)t,
				(int (*)(const void*, KSI_Header**))KSI_ExtendPdu_getHeader,
				(int (*)(const void*, void**))KSI_ExtendPdu_getResponse,
				(int (*)(const void*, KSI_OctetString**))KSI_ExtendResp_getRaw,
				(int (*)(const void*, void**))KSI_ExtendPdu_getRequest,
				(int (*)(const void*, KSI_OctetString**))KSI_ExtendReq_getRaw,
				0x301,0x302, KSI_TLV_TEMPLATE(KSI_ExtendReq),KSI_TLV_TEMPLATE(KSI_ExtendResp),
				algo_id, key, hmac);
	} else if (t->ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_2) {
		if (t->confRequest || t->confResponse) {
			res = pdu_calculateHmac_v2(t->ctx, (const void*)t,
					(int (*)(const void*, KSI_Header**))KSI_ExtendPdu_getHeader,
					(int (*)(const void*, void**))KSI_ExtendPdu_getConfResponse,
					(int (*)(const void*, KSI_OctetString**))KSI_ExtendPdu_getRaw,
					(int (*)(const void*, void**))KSI_ExtendPdu_getConfRequest,
					(int (*)(const void*, KSI_OctetString**))KSI_ExtendPdu_getRaw,
					0x320,0x321, KSI_TLV_TEMPLATE(KSI_ExtendReqPdu), KSI_TLV_TEMPLATE(KSI_ExtendRespPdu),
					algo_id, key, hmac);
		} else {
			res = pdu_calculateHmac_v2(t->ctx, (const void*)t,
					(int (*)(const void*, KSI_Header**))KSI_ExtendPdu_getHeader,
					(int (*)(const void*, void**))KSI_ExtendPdu_getResponse,
					(int (*)(const void*, KSI_OctetString**))KSI_ExtendPdu_getRaw,
					(int (*)(const void*, void**))KSI_ExtendPdu_getRequest,
					(int (*)(const void*, KSI_OctetString**))KSI_ExtendPdu_getRaw,
					0x320,0x321, KSI_TLV_TEMPLATE(KSI_ExtendReqPdu), KSI_TLV_TEMPLATE(KSI_ExtendRespPdu),
					algo_id, key, hmac);
		}
	} else {
		res = KSI_INVALID_FORMAT;
	}

	return res;
}

int KSI_ExtendPdu_updateHmac(KSI_ExtendPdu *pdu, KSI_HashAlgorithm algo_id, const char *key) {
	int res;
	KSI_DataHash *hmac = NULL;

	if (pdu == NULL || pdu->ctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(pdu->ctx);

	res = KSI_ExtendPdu_calculateHmac(pdu, algo_id, key, &hmac);
	if (res != KSI_OK) {
		KSI_pushError(pdu->ctx, res, NULL);
		goto cleanup;
	}

	if (pdu->hmac != NULL) {
		KSI_DataHash_free(pdu->hmac);
	}

	pdu->hmac = hmac;
	hmac = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(hmac);

	return res;
}

int KSI_ExtendReq_enclose(KSI_ExtendReq *req, const char *loginId, const char *key, KSI_ExtendPdu **pdu) {
	int res;
	KSI_ExtendPdu *tmp = NULL;
	KSI_Header *hdr = NULL;
	KSI_DataHash *hash = NULL;
	size_t loginLen;
	KSI_HashAlgorithm alg_id;

	if (req == NULL || loginId == NULL || key == NULL || pdu == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	loginLen = strlen(loginId);
	if (loginLen > UINT_MAX){
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Create the pdu */
	res = KSI_ExtendPdu_new(req->ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	/* Create header and initialize it with the loginId provided. */
	res = KSI_Header_new(req->ctx, &hdr);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Utf8String_new(req->ctx, loginId, (unsigned)loginLen + 1, &hdr->loginId);
	if (res != KSI_OK) goto cleanup;

	tmp->header = hdr;
	hdr = NULL;
	/* Every request must have a header, and at this point, this is guaranteed. */
	if (req->ctx->requestHeaderCB != NULL) {
		res = req->ctx->requestHeaderCB(tmp->header);
		if (res != KSI_OK) goto cleanup;
	}

	/* Add request. */
	if (req->config != NULL && req->ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_2) {
		tmp->confRequest = KSI_Config_ref(req->config);
	} else {
		tmp->request = req;
	}

	/* Get HMAC algorithm ID. */
	alg_id = (KSI_HashAlgorithm)req->ctx->options[KSI_OPT_EXT_HMAC_ALGORITHM];

	/* Create and append initial empty HMAC. */
	res = KSI_DataHash_createZero(req->ctx, alg_id, &hash);
	if (res != KSI_OK) goto cleanup;

	tmp->hmac = hash;
	hash = NULL;

	/* Calculate the HMAC using the provided key and the default hash algorithm. */
	res = KSI_ExtendPdu_updateHmac(tmp, alg_id, key);
	if (res != KSI_OK) goto cleanup;

	*pdu = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	/* Make sure we won't free the request. */
	KSI_ExtendPdu_setRequest(tmp, NULL);
	KSI_ExtendPdu_free(tmp);
	KSI_Header_free(hdr);

	return res;
}

int KSI_ExtendPdu_parse(KSI_CTX *ctx, const unsigned char *raw, size_t len, KSI_ExtendPdu **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_FTLV tlv;
	KSI_ExtendPdu *tmp = NULL;
	KSI_OctetString *tmpRaw = NULL;

	if (ctx == NULL || t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_FTLV_memRead(raw, len, &tlv);
	if (res != KSI_OK) goto cleanup;

	if (tlv.hdr_len + tlv.dat_len != len) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	res = KSI_ExtendPdu_new(ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	if (tlv.tag == 0x300) {
		if (ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_2) {
			res = KSI_SERVICE_EXTENDER_PDU_V1_RESPONSE_TO_PDU_V2_REQUEST;
		} else {
			res = KSI_TlvTemplate_parse(ctx, raw, len, KSI_TLV_TEMPLATE(KSI_ExtendPdu), tmp);
		}
	} else if (tlv.tag == 0x320) {
		if (ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_1) {
			res = KSI_SERVICE_EXTENDER_PDU_V2_RESPONSE_TO_PDU_V1_REQUEST;
		} else {
			res = KSI_TlvTemplate_parse(ctx, raw, len, KSI_TLV_TEMPLATE(KSI_ExtendReqPdu), tmp);
		}
	} else if (tlv.tag == 0x321) {
		if (ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_1) {
			res = KSI_SERVICE_EXTENDER_PDU_V2_RESPONSE_TO_PDU_V1_REQUEST;
		} else {
			res = KSI_TlvTemplate_parse(ctx, raw, len, KSI_TLV_TEMPLATE(KSI_ExtendRespPdu), tmp);
		}
	} else {
		res = KSI_INVALID_FORMAT;
	}

	if (res != KSI_OK) goto cleanup;

	res = KSI_OctetString_new(ctx, raw, len, &tmpRaw);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->raw = tmpRaw;
	tmpRaw = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_OctetString_free(tmpRaw);
	KSI_ExtendPdu_free(tmp);

	return res;
}

int KSI_ExtendPdu_serialize(const KSI_ExtendPdu *t, unsigned char **raw, size_t *len) {
	int res = KSI_UNKNOWN_ERROR;
	if (t == NULL || t->ctx == NULL || raw == NULL || len == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (t->ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_1) {
		res = KSI_TlvTemplate_serializeObject(t->ctx, t, 0x300, 0, 0, KSI_TLV_TEMPLATE(KSI_ExtendPdu), raw, len);
	} else if (t->ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_2) {
		if (t->request != NULL || t->confRequest != NULL) {
			res = KSI_TlvTemplate_serializeObject(t->ctx, t, 0x320, 0, 0, KSI_TLV_TEMPLATE(KSI_ExtendReqPdu), raw, len);
		} else if (t->response != NULL || t->confResponse != NULL || t->error != NULL) {
			res = KSI_TlvTemplate_serializeObject(t->ctx, t, 0x321, 0, 0, KSI_TLV_TEMPLATE(KSI_ExtendRespPdu), raw, len);
		} else {
			res = KSI_INVALID_FORMAT;
		}
	} else {
		res = KSI_INVALID_FORMAT;
	}

	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_Header*, header, Header);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_ExtendReq*, request, Request);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_ExtendResp*, response, Response);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_Config*, confRequest, ConfRequest);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_Config*, confResponse, ConfResponse);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_DataHash*, hmac, Hmac);
KSI_IMPLEMENT_GETTER(KSI_ExtendPdu, KSI_ErrorPdu*, error, Error);

KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_Header*, header, Header);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_ExtendReq*, request, Request);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_ExtendResp*, response, Response);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_Config*, confRequest, ConfRequest);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_Config*, confResponse, ConfResponse);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_DataHash*, hmac, Hmac);
KSI_IMPLEMENT_SETTER(KSI_ExtendPdu, KSI_ErrorPdu*, error, Error);

/**
 * KSI_AggregationPdu
 */
void KSI_AggregationPdu_free(KSI_AggregationPdu *t) {
	if (t != NULL) {
		KSI_Header_free(t->header);
		KSI_AggregationReq_free(t->request);
		KSI_AggregationResp_free(t->response);
		KSI_ErrorPdu_free(t->error);
		KSI_AggregationConf_free(t->confRequest);
		KSI_AggregationConf_free(t->confResponse);
		KSI_AggregationAckReq_free(t->ackRequest);
		KSI_AggregationAck_free(t->ackResponse);
		KSI_DataHash_free(t->hmac);
		KSI_OctetString_free(t->raw);
		KSI_free(t);
	}
}

int KSI_AggregationPdu_new(KSI_CTX *ctx, KSI_AggregationPdu **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationPdu *tmp = NULL;
	tmp = KSI_new(KSI_AggregationPdu);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->header = NULL;
	tmp->ctx = ctx;
	tmp->request = NULL;
	tmp->response = NULL;
	tmp->error = NULL;
	tmp->confRequest = NULL;
	tmp->confResponse = NULL;
	tmp->ackRequest = NULL;
	tmp->ackResponse = NULL;
	tmp->hmac = NULL;
	tmp->raw = NULL;

	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_AggregationPdu_free(tmp);
	return res;
}

int KSI_AggregationPdu_verifyHmac(const KSI_AggregationPdu *pdu, const char *pass) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_DataHash *respHmac = NULL;

	res = KSI_AggregationPdu_getHmac(pdu, &respHmac);
	if (res != KSI_OK) {
		KSI_pushError(pdu->ctx, res, NULL);
		goto cleanup;
	}

	res = pdu_verifyHmac(pdu->ctx, respHmac, pass,
			(KSI_HashAlgorithm)pdu->ctx->options[KSI_OPT_AGGR_HMAC_ALGORITHM],
			(int (*)(const void*, int, const char*, KSI_DataHash**))KSI_AggregationPdu_calculateHmac,
			(void*)pdu);
	if (res != KSI_OK) {
		KSI_pushError(pdu->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;
cleanup:
	return res;
}

int KSI_AggregationPdu_calculateHmac(const KSI_AggregationPdu *t, KSI_HashAlgorithm algo_id, const char *key, KSI_DataHash **hmac){
	int res = KSI_OK;
	if (t == NULL || t->ctx == NULL)
		return KSI_INVALID_ARGUMENT;

	if (t->ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_1) {
		res = pdu_calculateHmac(t->ctx, (const void*)t,
				(int (*)(const void*, KSI_Header**))KSI_AggregationPdu_getHeader,
				(int (*)(const void*, void**))KSI_AggregationPdu_getResponse,
				(int (*)(const void*, KSI_OctetString**))KSI_AggregationResp_getRaw,
				(int (*)(const void*, void**))KSI_AggregationPdu_getRequest,
				(int (*)(const void*, KSI_OctetString**))KSI_AggregationReq_getRaw,
				0x201,0x202, KSI_TLV_TEMPLATE(KSI_AggregationReq),KSI_TLV_TEMPLATE(KSI_AggregationResp),
				algo_id, key, hmac);
	} else if (t->ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_2) {
		if (t->confRequest || t->confResponse) {
			res = pdu_calculateHmac_v2(t->ctx, (const void*)t,
					(int (*)(const void*, KSI_Header**))KSI_AggregationPdu_getHeader,
					(int (*)(const void*, void**))KSI_AggregationPdu_getConfResponse,
					(int (*)(const void*, KSI_OctetString**))KSI_AggregationPdu_getRaw,
					(int (*)(const void*, void**))KSI_AggregationPdu_getConfRequest,
					(int (*)(const void*, KSI_OctetString**))KSI_AggregationPdu_getRaw,
					0x220,0x221, KSI_TLV_TEMPLATE(KSI_AggregationReqPdu), KSI_TLV_TEMPLATE(KSI_AggregationReqPdu),
					algo_id, key, hmac);
		} else {
			res = pdu_calculateHmac_v2(t->ctx, (const void*)t,
					(int (*)(const void*, KSI_Header**))KSI_AggregationPdu_getHeader,
					(int (*)(const void*, void**))KSI_AggregationPdu_getResponse,
					(int (*)(const void*, KSI_OctetString**))KSI_AggregationPdu_getRaw,
					(int (*)(const void*, void**))KSI_AggregationPdu_getRequest,
					(int (*)(const void*, KSI_OctetString**))KSI_AggregationPdu_getRaw,
					0x220,0x221, KSI_TLV_TEMPLATE(KSI_AggregationReqPdu), KSI_TLV_TEMPLATE(KSI_AggregationReqPdu),
					algo_id, key, hmac);
		}
	} else {
		res = KSI_INVALID_FORMAT;
	}

	return res;
}

int KSI_AggregationPdu_updateHmac(KSI_AggregationPdu *pdu, KSI_HashAlgorithm algo_id, const char *key) {
	int res;
	KSI_DataHash *hmac = NULL;

	if (pdu == NULL || pdu->ctx == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(pdu->ctx);

	res = KSI_AggregationPdu_calculateHmac(pdu, algo_id, key, &hmac);
	if (res != KSI_OK) {
		KSI_pushError(pdu->ctx, res, NULL);
		goto cleanup;
	}

	if (pdu->hmac != NULL) {
		KSI_DataHash_free(pdu->hmac);
	}

	pdu->hmac = hmac;
	hmac = NULL;

	res = KSI_OK;

cleanup:

	KSI_DataHash_free(hmac);

	return res;
}

int KSI_AggregationReq_encloseWithHeader(KSI_AggregationReq *req, KSI_Header *hdr, const char *key, KSI_AggregationPdu **pdu) {
	int res;
	KSI_AggregationPdu *tmp = NULL;
	KSI_DataHash *hash = NULL;
	KSI_HashAlgorithm alg_id;

	if (req == NULL || hdr == NULL || key == NULL || pdu == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Create the pdu */
	res = KSI_AggregationPdu_new(req->ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	/* Set header*/
	res = KSI_AggregationPdu_setHeader(tmp, hdr);
	if (res != KSI_OK) goto cleanup;

	/* Add request. */
	if (req->config != NULL && req->ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_2) {
		tmp->confRequest = KSI_Config_ref(req->config);
	} else {
		tmp->request = req;
	}

	/* Get HMAC algorithm ID. */
	alg_id = (KSI_HashAlgorithm)req->ctx->options[KSI_OPT_AGGR_HMAC_ALGORITHM];

	/* Create and append initial empty HMAC. */
	res = KSI_DataHash_createZero(req->ctx, alg_id, &hash);
	if (res != KSI_OK) goto cleanup;

	tmp->hmac = hash;
	hash = NULL;

	/* Calculate the HMAC using the provided key and the default hash algorithm. */
	res = KSI_AggregationPdu_updateHmac(tmp, alg_id, key);
	if (res != KSI_OK) goto cleanup;

	*pdu = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	/* Make sure we won't free input parameters on failure. */
	if (tmp != NULL) {
		KSI_AggregationPdu_setHeader(tmp, NULL);
		KSI_AggregationPdu_setRequest(tmp, NULL);
	}
	KSI_AggregationPdu_free(tmp);

	return res;
}

int KSI_AggregationReq_enclose(KSI_AggregationReq *req, const char *loginId, const char *key, KSI_AggregationPdu **pdu) {
	int res;
	KSI_Header *tmp = NULL;
	size_t loginLen;

	if (req == NULL || loginId == NULL || key == NULL || pdu == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	loginLen = strlen(loginId);
	if (loginLen > UINT_MAX){
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	/* Create header and initialize it with the loginId provided. */
	res = KSI_Header_new(req->ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Utf8String_new(req->ctx, loginId, (unsigned)loginLen + 1, &tmp->loginId);
	if (res != KSI_OK) goto cleanup;

	/* Every request must have a header, and at this point, this is guaranteed. */
	if (req->ctx->requestHeaderCB != NULL) {
		res = req->ctx->requestHeaderCB(tmp);
		if (res != KSI_OK) goto cleanup;
	}

	res = KSI_AggregationReq_encloseWithHeader(req, tmp, key, pdu);
	if (res != KSI_OK) goto cleanup;
	tmp = NULL;

	res = KSI_OK;

cleanup:
	KSI_Header_free(tmp);

	return res;
}

int KSI_AggregationPdu_parse(KSI_CTX *ctx, const unsigned char *raw, size_t len, KSI_AggregationPdu **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_FTLV tlv;
	KSI_AggregationPdu *tmp = NULL;
	KSI_OctetString *tmpRaw = NULL;

	if (ctx == NULL || t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = KSI_FTLV_memRead(raw, len, &tlv);
	if (res != KSI_OK) goto cleanup;

	if (tlv.hdr_len + tlv.dat_len != len) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	res = KSI_AggregationPdu_new(ctx, &tmp);
	if (res != KSI_OK) goto cleanup;

	if (tlv.tag == 0x200) {
		if (ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_2) {
			res = KSI_SERVICE_AGGR_PDU_V1_RESPONSE_TO_PDU_V2_REQUEST;
		} else {
			res = KSI_TlvTemplate_parse(ctx, raw, len, KSI_TLV_TEMPLATE(KSI_AggregationPdu), tmp);
		}
	} else if (tlv.tag == 0x220) {
		if (ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_1) {
			res = KSI_SERVICE_AGGR_PDU_V2_RESPONSE_TO_PDU_V1_REQUEST;
		} else {
			res = KSI_TlvTemplate_parse(ctx, raw, len, KSI_TLV_TEMPLATE(KSI_AggregationReqPdu), tmp);
		}
	} else if (tlv.tag == 0x221) {
		if (ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_1) {
			res = KSI_SERVICE_AGGR_PDU_V2_RESPONSE_TO_PDU_V1_REQUEST;
		} else {
			res = KSI_TlvTemplate_parse(ctx, raw, len, KSI_TLV_TEMPLATE(KSI_AggregationRespPdu), tmp);
		}
	} else {
		res = KSI_INVALID_FORMAT;
	}
	if (res != KSI_OK) goto cleanup;

	res = KSI_OctetString_new(ctx, raw, len, &tmpRaw);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->raw = tmpRaw;
	tmpRaw = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_OctetString_free(tmpRaw);
	KSI_AggregationPdu_free(tmp);

	return res;
}

int KSI_AggregationPdu_serialize(const KSI_AggregationPdu *t, unsigned char **raw, size_t *len) {
	int res = KSI_UNKNOWN_ERROR;
	if (t == NULL || t->ctx == NULL || raw == NULL || len == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (t->ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_1) {
		res = KSI_TlvTemplate_serializeObject(t->ctx, t, 0x200, 0, 0, KSI_TLV_TEMPLATE(KSI_AggregationPdu), raw, len);
	} else if (t->ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_2) {
		if (t->request != NULL || t->confRequest != NULL || t->ackRequest != NULL) {
			res = KSI_TlvTemplate_serializeObject(t->ctx, t, 0x220, 0, 0, KSI_TLV_TEMPLATE(KSI_AggregationReqPdu), raw, len);
		} else if (t->response != NULL || t->confResponse != NULL || t->ackResponse != NULL) {
			res = KSI_TlvTemplate_serializeObject(t->ctx, t, 0x221, 0, 0, KSI_TLV_TEMPLATE(KSI_AggregationRespPdu), raw, len);
		} else {
			res = KSI_INVALID_FORMAT;
		}
	} else {
		res = KSI_INVALID_FORMAT;
	}

	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}

KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_Header*, header, Header);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_AggregationReq*, request, Request);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_AggregationResp*, response, Response);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_DataHash*, hmac, Hmac);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_ErrorPdu*, error, Error);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_Config*, confRequest, ConfRequest);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_Config*, confResponse, ConfResponse);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_RequestAck*, ackRequest, AckRequest);
KSI_IMPLEMENT_GETTER(KSI_AggregationPdu, KSI_RequestAck*, ackResponse, AckResponse);

KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_Header*, header, Header);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_AggregationReq*, request, Request);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_AggregationResp*, response, Response);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_DataHash*, hmac, Hmac);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_ErrorPdu*, error, Error);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_Config*, confRequest, ConfRequest);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_Config*, confResponse, ConfResponse);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_RequestAck*, ackRequest, AckRequest);
KSI_IMPLEMENT_SETTER(KSI_AggregationPdu, KSI_RequestAck*, ackResponse, AckResponse);

/**
 * KSI_Header
 */
void KSI_Header_free(KSI_Header *t) {
	if (t != NULL) {
		KSI_Integer_free(t->instanceId);
		KSI_Integer_free(t->messageId);
		KSI_Utf8String_free(t->loginId);
		KSI_OctetString_free(t->raw);
		KSI_free(t);
	}
}

int KSI_Header_new(KSI_CTX *ctx, KSI_Header **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Header *tmp = NULL;
	tmp = KSI_new(KSI_Header);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->instanceId = NULL;
	tmp->messageId = NULL;
	tmp->loginId = NULL;
	tmp->raw = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_Header_free(tmp);
	return res;
}
KSI_IMPLEMENT_FROMTLV(KSI_Header, 0x01, FROMTLV_ADD_RAW(raw, 0););
KSI_IMPLEMENT_TOTLV(KSI_Header);

KSI_IMPLEMENT_GETTER(KSI_Header, KSI_Integer*, instanceId, InstanceId);
KSI_IMPLEMENT_GETTER(KSI_Header, KSI_Integer*, messageId, MessageId);
KSI_IMPLEMENT_GETTER(KSI_Header, KSI_Utf8String*, loginId, LoginId);

KSI_IMPLEMENT_SETTER(KSI_Header, KSI_Integer*, instanceId, InstanceId);
KSI_IMPLEMENT_SETTER(KSI_Header, KSI_Integer*, messageId, MessageId);
KSI_IMPLEMENT_SETTER(KSI_Header, KSI_Utf8String*, loginId, LoginId);

KSI_IMPLEMENT_GET_CTX(KSI_Header);

/**
 * KSI_Config
 */
void KSI_Config_free(KSI_Config *t) {
	if (t != NULL && --t->ref == 0) {
		KSI_Integer_free(t->maxLevel);
		KSI_Integer_free(t->aggrAlgo);
		KSI_Integer_free(t->aggrPeriod);
		KSI_Integer_free(t->maxRequests);
		KSI_Integer_free(t->calendarFirstTime);
		KSI_Integer_free(t->calendarLastTime);
		KSI_Utf8StringList_free(t->parentUri);
		KSI_free(t);
	}
}

int KSI_Config_new(KSI_CTX *ctx, KSI_Config **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Config *tmp = NULL;
	tmp = KSI_new(KSI_Config);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}
	tmp->ref = 1;

	tmp->ctx = ctx;
	tmp->maxLevel = NULL;
	tmp->aggrAlgo = NULL;
	tmp->aggrPeriod = NULL;
	tmp->maxRequests = NULL;
	tmp->calendarFirstTime = NULL;
	tmp->calendarLastTime = NULL;
	tmp->parentUri = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_Config_free(tmp);
	return res;
}

KSI_IMPLEMENT_REF(KSI_Config);

KSI_IMPLEMENT_GETTER(KSI_Config, KSI_Integer*, maxLevel, MaxLevel);
KSI_IMPLEMENT_GETTER(KSI_Config, KSI_Integer*, aggrAlgo, AggrAlgo);
KSI_IMPLEMENT_GETTER(KSI_Config, KSI_Integer*, aggrPeriod, AggrPeriod);
KSI_IMPLEMENT_GETTER(KSI_Config, KSI_Integer*, maxRequests, MaxRequests);
KSI_IMPLEMENT_GETTER(KSI_Config, KSI_LIST(KSI_Utf8String)*, parentUri, ParentUri);
KSI_IMPLEMENT_GETTER(KSI_Config, KSI_Integer*, calendarFirstTime, CalendarFirstTime);
KSI_IMPLEMENT_GETTER(KSI_Config, KSI_Integer*, calendarLastTime, CalendarLastTime);

KSI_IMPLEMENT_SETTER(KSI_Config, KSI_Integer*, maxLevel, MaxLevel);
KSI_IMPLEMENT_SETTER(KSI_Config, KSI_Integer*, aggrAlgo, AggrAlgo);
KSI_IMPLEMENT_SETTER(KSI_Config, KSI_Integer*, aggrPeriod, AggrPeriod);
KSI_IMPLEMENT_SETTER(KSI_Config, KSI_Integer*, maxRequests, MaxRequests);
KSI_IMPLEMENT_SETTER(KSI_Config, KSI_LIST(KSI_Utf8String)*, parentUri, ParentUri);
KSI_IMPLEMENT_SETTER(KSI_Config, KSI_Integer*, calendarFirstTime, CalendarFirstTime);
KSI_IMPLEMENT_SETTER(KSI_Config, KSI_Integer*, calendarLastTime, CalendarLastTime);


/**
 * KSI_AggregationReq
 */
void KSI_AggregationReq_free(KSI_AggregationReq *t) {
	if (t != NULL && --t->ref == 0) {
		KSI_Integer_free(t->requestId);
		KSI_DataHash_free(t->requestHash);
		KSI_Integer_free(t->requestLevel);
		KSI_Config_free(t->config);
		KSI_OctetString_free(t->raw);
		KSI_free(t);
	}
}

int KSI_AggregationReq_new(KSI_CTX *ctx, KSI_AggregationReq **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationReq *tmp = NULL;
	tmp = KSI_new(KSI_AggregationReq);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;
	tmp->requestId = NULL;
	tmp->requestHash = NULL;
	tmp->requestLevel = NULL;
	tmp->config = NULL;
	tmp->raw = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_AggregationReq_free(tmp);
	return res;
}

int KSI_AggregationReq_fromTlv(KSI_TLV *tlv, KSI_AggregationReq **data) {
	int res;
	KSI_AggregationReq *tmp = NULL;
	unsigned char *tlvData = NULL;
	KSI_OctetString *raw = NULL;
	KSI_CTX *ctx = KSI_TLV_getCtx(tlv);

	if (tlv == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;\
	}

	KSI_ERR_clearErrors(ctx);

	if (data == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_AggregationReq_new(KSI_TLV_getCtx(tlv), &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (KSI_TLV_getTag(tlv) == 0x201) {
		res = KSI_TlvTemplate_extract(KSI_TLV_getCtx(tlv), tmp, tlv, KSI_TLV_TEMPLATE(KSI_AggregationReq));
	} else if (KSI_TLV_getTag(tlv) == 0x02) {
		res = KSI_TlvTemplate_extract(KSI_TLV_getCtx(tlv), tmp, tlv, KSI_TLV_TEMPLATE(KSI_AggregationReq_v2));
	} else {
		res = KSI_INVALID_FORMAT;
	}

	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	FROMTLV_ADD_RAW(raw, 0);
	*data = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_AggregationReq_free(tmp);
	KSI_free(tlvData);
	KSI_OctetString_free(raw);
	return res;
}

int KSI_AggregationReq_toTlv(KSI_CTX *ctx, const KSI_AggregationReq *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res;
	KSI_TLV *tmp = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || data == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_new(ctx, tag, isNonCritical, isForward, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_1) {
		res = KSI_TlvTemplate_construct(ctx, tmp, data, KSI_TLV_TEMPLATE(KSI_AggregationReq));
	} else if (ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_2) {
		res = KSI_TlvTemplate_construct(ctx, tmp, data, (data->config == NULL) ?
				KSI_TLV_TEMPLATE(KSI_AggregationReq_v2) : KSI_TLV_TEMPLATE(KSI_ConfigReq));
	} else {
		res = KSI_INVALID_FORMAT;
	}

	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tmp);

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

KSI_IMPLEMENT_REF(KSI_AggregationReq)

/**
 * KSI_RequestAck
 */
void KSI_RequestAck_free(KSI_RequestAck *t) {
	if (t != NULL) {
		KSI_Integer_free(t->requestTime);
		KSI_Integer_free(t->receiptTime);
		KSI_Integer_free(t->acknowledgeTime);
		KSI_Integer_free(t->aggregationPeriod);
		KSI_Integer_free(t->aggregationDelay);
		KSI_Integer_free(t->aggregationDrift);
		KSI_free(t);
	}
}

int KSI_RequestAck_new(KSI_CTX *ctx, KSI_RequestAck **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_RequestAck *tmp = NULL;
	tmp = KSI_new(KSI_RequestAck);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->requestTime = NULL;
	tmp->receiptTime = NULL;
	tmp->acknowledgeTime = NULL;
	tmp->aggregationPeriod = NULL;
	tmp->aggregationDelay = NULL;
	tmp->aggregationDrift = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_RequestAck_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_RequestAck, KSI_Integer*, requestTime, RequestTime);
KSI_IMPLEMENT_GETTER(KSI_RequestAck, KSI_Integer*, receiptTime, ReceiptTime);
KSI_IMPLEMENT_GETTER(KSI_RequestAck, KSI_Integer*, acknowledgeTime, AcknowledgeTime);
KSI_IMPLEMENT_GETTER(KSI_RequestAck, KSI_Integer*, aggregationPeriod, AggregationPeriod);
KSI_IMPLEMENT_GETTER(KSI_RequestAck, KSI_Integer*, aggregationDelay, AggregationDelay);
KSI_IMPLEMENT_GETTER(KSI_RequestAck, KSI_Integer*, aggregationDrift, AggregationDrift);

KSI_IMPLEMENT_SETTER(KSI_RequestAck, KSI_Integer*, requestTime, RequestTime);
KSI_IMPLEMENT_SETTER(KSI_RequestAck, KSI_Integer*, receiptTime, ReceiptTime);
KSI_IMPLEMENT_SETTER(KSI_RequestAck, KSI_Integer*, acknowledgeTime, AcknowledgeTime);
KSI_IMPLEMENT_SETTER(KSI_RequestAck, KSI_Integer*, aggregationPeriod, AggregationPeriod);
KSI_IMPLEMENT_SETTER(KSI_RequestAck, KSI_Integer*, aggregationDelay, AggregationDelay);
KSI_IMPLEMENT_SETTER(KSI_RequestAck, KSI_Integer*, aggregationDrift, AggregationDrift);


/**
 * KSI_AggregationResp
 */
void KSI_AggregationResp_free(KSI_AggregationResp *t) {
	if (t != NULL) {
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
		KSI_OctetString_free(t->raw);
		KSI_free(t);
	}
}

int KSI_AggregationResp_new(KSI_CTX *ctx, KSI_AggregationResp **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_AggregationResp *tmp = NULL;
	tmp = KSI_new(KSI_AggregationResp);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->raw = NULL;
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

int KSI_AggregationResp_verifyWithRequest(const KSI_AggregationResp *resp, const KSI_AggregationReq *req) {
	int res = KSI_UNKNOWN_ERROR;

	if (resp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(resp->ctx);

	if (req == NULL) {
		KSI_pushError(resp->ctx, res = KSI_INVALID_ARGUMENT, "A non-NULL response may not originate from a NULL request."); // TODO! Declare new error code
		goto cleanup;
	}

	if (!KSI_Integer_equals(resp->requestId, req->requestId)) {
		KSI_pushError(resp->ctx, res = KSI_REQUEST_ID_MISMATCH, "Request id's mismatch.");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_AggregationResp_fromTlv(KSI_TLV *tlv, KSI_AggregationResp **data) {
	int res;
	KSI_AggregationResp *tmp = NULL;
	unsigned char *tlvData = NULL;
	KSI_OctetString *raw = NULL;
	KSI_CTX *ctx = KSI_TLV_getCtx(tlv);

	if (tlv == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;\
	}

	KSI_ERR_clearErrors(ctx);

	if (data == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_AggregationResp_new(KSI_TLV_getCtx(tlv), &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	KSI_LOG_debug(ctx, "AggregationResp_fromTlv: %d", KSI_TLV_getTag(tlv));
	if (KSI_TLV_getTag(tlv) == 0x202) {
		res = KSI_TlvTemplate_extract(KSI_TLV_getCtx(tlv), tmp, tlv, KSI_TLV_TEMPLATE(KSI_AggregationResp));
	} else if (KSI_TLV_getTag(tlv) == 0x02) {
		res = KSI_TlvTemplate_extract(KSI_TLV_getCtx(tlv), tmp, tlv, KSI_TLV_TEMPLATE(KSI_AggregationResp_v2));
	} else {
		res = KSI_INVALID_FORMAT;
	}

	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	FROMTLV_ADD_RAW(raw, 0);
	FROMTLV_ADD_BASETLV(baseTlv);
	*data = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_AggregationResp_free(tmp);
	KSI_free(tlvData);
	KSI_OctetString_free(raw);
	return res;
}

int KSI_AggregationResp_toTlv(KSI_CTX *ctx, const KSI_AggregationResp *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res;
	KSI_TLV *tmp = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || data == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_new(ctx, tag, isNonCritical, isForward, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_1) {
		res = KSI_TlvTemplate_construct(ctx, tmp, data, KSI_TLV_TEMPLATE(KSI_AggregationResp));
	} else if (ctx->options[KSI_OPT_AGGR_PDU_VER] == KSI_PDU_VERSION_2) {
		res = KSI_TlvTemplate_construct(ctx, tmp, data, KSI_TLV_TEMPLATE(KSI_AggregationResp_v2));
	} else {
		res = KSI_INVALID_FORMAT;
	}

	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tmp);

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

KSI_IMPLEMENT_GET_CTX(KSI_AggregationResp);

/**
 * KSI_ExtendReq
 */
void KSI_ExtendReq_free(KSI_ExtendReq *t) {
	if (t != NULL && --t->ref == 0) {
		KSI_Integer_free(t->requestId);
		KSI_Integer_free(t->aggregationTime);
		KSI_Integer_free(t->publicationTime);
		KSI_Config_free(t->config);
		KSI_OctetString_free(t->raw);
		KSI_free(t);
	}
}

int KSI_ExtendReq_new(KSI_CTX *ctx, KSI_ExtendReq **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendReq *tmp = NULL;
	tmp = KSI_new(KSI_ExtendReq);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->ref = 1;
	tmp->requestId = NULL;
	tmp->aggregationTime = NULL;
	tmp->publicationTime = NULL;
	tmp->config = NULL;
	tmp->raw = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_ExtendReq_free(tmp);
	return res;
}

int KSI_ExtendReq_fromTlv(KSI_TLV *tlv, KSI_ExtendReq **data) {
	int res;
	KSI_ExtendReq *tmp = NULL;
	unsigned char *tlvData = NULL;
	KSI_OctetString *raw = NULL;
	KSI_CTX *ctx = KSI_TLV_getCtx(tlv);

	if (tlv == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;\
	}

	KSI_ERR_clearErrors(ctx);

	if (data == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_ExtendReq_new(KSI_TLV_getCtx(tlv), &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (KSI_TLV_getTag(tlv) == 0x301 || KSI_TLV_getTag(tlv) == 0x02) {
		res = KSI_TlvTemplate_extract(KSI_TLV_getCtx(tlv), tmp, tlv, KSI_TLV_TEMPLATE(KSI_ExtendReq));
	} else {
		res = KSI_INVALID_FORMAT;
	}

	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	FROMTLV_ADD_RAW(raw, 0);
	*data = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_ExtendReq_free(tmp);
	KSI_free(tlvData);
	KSI_OctetString_free(raw);
	return res;
}

int KSI_ExtendReq_toTlv(KSI_CTX *ctx, const KSI_ExtendReq *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res;
	KSI_TLV *tmp = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || data == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_new(ctx, tag, isNonCritical, isForward, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_1) {
		res = KSI_TlvTemplate_construct(ctx, tmp, data, KSI_TLV_TEMPLATE(KSI_ExtendReq));
	} else if (ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_2) {
		res = KSI_TlvTemplate_construct(ctx, tmp, data, (data->config == NULL) ?
				KSI_TLV_TEMPLATE(KSI_ExtendReq) : KSI_TLV_TEMPLATE(KSI_ConfigReq));
	} else {
		res = KSI_INVALID_FORMAT;
	}

	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tmp);

	return res;
}

KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_Integer*, aggregationTime, AggregationTime);
KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_Integer*, publicationTime, PublicationTime);
KSI_IMPLEMENT_GETTER(KSI_ExtendReq, KSI_Config*, config, Config);

KSI_IMPLEMENT_SETTER(KSI_ExtendReq, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_SETTER(KSI_ExtendReq, KSI_Integer*, aggregationTime, AggregationTime);
KSI_IMPLEMENT_SETTER(KSI_ExtendReq, KSI_Integer*, publicationTime, PublicationTime);
KSI_IMPLEMENT_SETTER(KSI_ExtendReq, KSI_Config*, config, Config);

KSI_IMPLEMENT_REF(KSI_ExtendReq)

/**
 * KSI_ExtendResp
 */
void KSI_ExtendResp_free(KSI_ExtendResp *t) {
	if (t != NULL) {
		KSI_Integer_free(t->requestId);
		KSI_Integer_free(t->status);
		KSI_Utf8String_free(t->errorMsg);
		KSI_Config_free(t->config);
		KSI_Integer_free(t->lastTime);
		KSI_CalendarHashChain_free(t->calendarHashChain);
		KSI_TLV_free(t->baseTlv);
		KSI_OctetString_free(t->raw);
		KSI_free(t);
	}
}

int KSI_ExtendResp_new(KSI_CTX *ctx, KSI_ExtendResp **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_ExtendResp *tmp = NULL;
	tmp = KSI_new(KSI_ExtendResp);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->requestId = NULL;
	tmp->status = NULL;
	tmp->errorMsg = NULL;
	tmp->config = NULL;
	tmp->lastTime = NULL;
	tmp->calendarHashChain = NULL;
	tmp->baseTlv = NULL;
	tmp->raw = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_ExtendResp_free(tmp);
	return res;
}

int KSI_ExtendResp_verifyWithRequest(const KSI_ExtendResp *resp, const KSI_ExtendReq *req) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_Integer *tm = NULL;
	time_t aggrTm = 0;

	if (resp == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(resp->ctx);

	if (req == NULL) {
		KSI_pushError(resp->ctx, res = KSI_INVALID_ARGUMENT, "A non-NULL response may not originate from a NULL request."); // TODO! Declare new error code
		goto cleanup;
	}

	if (!KSI_Integer_equalsUInt(resp->status, 0)) {
		res = KSI_convertExtenderStatusCode(resp->status);
		goto cleanup;
	}

	if (!KSI_Integer_equals(resp->requestId, req->requestId)) {
		KSI_pushError(resp->ctx, res = KSI_REQUEST_ID_MISMATCH, "Request id's mismatch.");
		goto cleanup;
	}

	/* Verify publication time. */
	res = KSI_CalendarHashChain_getPublicationTime(resp->calendarHashChain, &tm);
	if (res != KSI_OK) {
		KSI_pushError(resp->ctx, res, NULL);
		goto cleanup;
	}

	if (req->publicationTime != NULL) {

		if (!KSI_Integer_equals(tm, req->publicationTime)) {
			KSI_pushError(resp->ctx, res = KSI_INVALID_ARGUMENT, "Publication time mismatch.");
			goto cleanup;
		}

		KSI_nofree(tm);
	}

	/* Verify aggregation time. */
	res = KSI_CalendarHashChain_getAggregationTime(resp->calendarHashChain, &tm);
	if (res != KSI_OK) {
		KSI_pushError(resp->ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_Integer_equals(tm, req->aggregationTime)) {
		KSI_pushError(resp->ctx, res = KSI_INVALID_ARGUMENT, "Aggregation time mismatch.");
		goto cleanup;
	}


	/* Verify the shape of the response. */
	res = KSI_CalendarHashChain_calculateAggregationTime(resp->calendarHashChain, &aggrTm);
	if (res != KSI_OK) {
		KSI_pushError(resp->ctx, res, NULL);
		goto cleanup;
	}

	if (!KSI_Integer_equalsUInt(tm, aggrTm)) {
		KSI_pushError(resp->ctx, res = KSI_INVALID_ARGUMENT, "Aggregation time does not match with the shape of the calendar hash chain.");
		goto cleanup;
	}

cleanup:

	return res;
}

int KSI_ExtendResp_fromTlv(KSI_TLV *tlv, KSI_ExtendResp **data) {
	int res;
	KSI_ExtendResp *tmp = NULL;
	unsigned char *tlvData = NULL;
	KSI_OctetString *raw = NULL;
	KSI_CTX *ctx = KSI_TLV_getCtx(tlv);

	if (tlv == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;\
	}

	KSI_ERR_clearErrors(ctx);

	if (data == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_ExtendResp_new(KSI_TLV_getCtx(tlv), &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (KSI_TLV_getTag(tlv) == 0x302) {
		res = KSI_TlvTemplate_extract(KSI_TLV_getCtx(tlv), tmp, tlv, KSI_TLV_TEMPLATE(KSI_ExtendResp));
	} else if (KSI_TLV_getTag(tlv) == 0x02) {
		res = KSI_TlvTemplate_extract(KSI_TLV_getCtx(tlv), tmp, tlv, KSI_TLV_TEMPLATE(KSI_ExtendResp_v2));
	} else {
		res = KSI_INVALID_FORMAT;
	}

	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}
	FROMTLV_ADD_RAW(raw, 0);
	*data = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_ExtendResp_free(tmp);
	KSI_free(tlvData);
	KSI_OctetString_free(raw);
	return res;
}

int KSI_ExtendResp_toTlv(KSI_CTX *ctx, const KSI_ExtendResp *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res;
	KSI_TLV *tmp = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || data == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_TLV_new(ctx, tag, isNonCritical, isForward, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_1) {
		res = KSI_TlvTemplate_construct(ctx, tmp, data, KSI_TLV_TEMPLATE(KSI_ExtendResp));
	} else if (ctx->options[KSI_OPT_EXT_PDU_VER] == KSI_PDU_VERSION_2) {
		res = KSI_TlvTemplate_construct(ctx, tmp, data, KSI_TLV_TEMPLATE(KSI_ExtendResp_v2));
	} else {
		res = KSI_INVALID_FORMAT;
	}

	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_TLV_free(tmp);

	return res;
}

KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Integer*, status, Status);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Utf8String*, errorMsg, ErrorMsg);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Integer*, lastTime, LastTime);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_Config*, config, Config);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_CalendarHashChain*, calendarHashChain, CalendarHashChain);
KSI_IMPLEMENT_GETTER(KSI_ExtendResp, KSI_TLV*, baseTlv, BaseTlv);

KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Integer*, requestId, RequestId);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Integer*, status, Status);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Utf8String*, errorMsg, ErrorMsg);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Integer*, lastTime, LastTime);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_Config*, config, Config);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_CalendarHashChain*, calendarHashChain, CalendarHashChain);
KSI_IMPLEMENT_SETTER(KSI_ExtendResp, KSI_TLV*, baseTlv, BaseTlv);

/**
 * KSI_PKISignedData
 */
void KSI_PKISignedData_free(KSI_PKISignedData *t) {
	if (t != NULL) {
		KSI_OctetString_free(t->signatureValue);
		KSI_OctetString_free(t->certId);
		KSI_Utf8String_free(t->certRepositoryUri);
		KSI_Utf8String_free(t->sig_type);
		KSI_free(t);
	}
}

int KSI_PKISignedData_new(KSI_CTX *ctx, KSI_PKISignedData **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PKISignedData *tmp = NULL;
	tmp = KSI_new(KSI_PKISignedData);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->signatureValue = NULL;
	tmp->certId = NULL;
	tmp->certRepositoryUri = NULL;
	tmp->sig_type = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_PKISignedData_free(tmp);
	return res;
}

KSI_IMPLEMENT_GETTER(KSI_PKISignedData, KSI_OctetString*, signatureValue, SignatureValue);
KSI_IMPLEMENT_GETTER(KSI_PKISignedData, KSI_OctetString*, certId, CertId);
KSI_IMPLEMENT_GETTER(KSI_PKISignedData, KSI_Utf8String*, certRepositoryUri, CertRepositoryUri);
KSI_IMPLEMENT_GETTER(KSI_PKISignedData, KSI_Utf8String*, sig_type, SigType);

KSI_IMPLEMENT_SETTER(KSI_PKISignedData, KSI_OctetString*, signatureValue, SignatureValue);
KSI_IMPLEMENT_SETTER(KSI_PKISignedData, KSI_OctetString*, certId, CertId);
KSI_IMPLEMENT_SETTER(KSI_PKISignedData, KSI_Utf8String*, certRepositoryUri, CertRepositoryUri);
KSI_IMPLEMENT_SETTER(KSI_PKISignedData, KSI_Utf8String*, sig_type, SigType);


/**
 * KSI_PublicationsHeader
 */
void KSI_PublicationsHeader_free(KSI_PublicationsHeader *t) {
	if (t != NULL) {
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
	if (tmp == NULL) {
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
	if (t != NULL) {
		KSI_OctetString_free(t->certId);
		KSI_PKICertificate_free(t->cert);
		KSI_free(t);
	}
}

int KSI_CertificateRecord_new(KSI_CTX *ctx, KSI_CertificateRecord **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_CertificateRecord *tmp = NULL;
	tmp = KSI_new(KSI_CertificateRecord);
	if (tmp == NULL) {
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
