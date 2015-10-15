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

#include "internal.h"
#include "pkitruststore.h"
#include "tlv.h"
#include "crc32.h"


int KSI_PKISignature_fromTlv(KSI_TLV *tlv, KSI_PKISignature **sig) {
	int res;
	KSI_CTX *ctx = NULL;

	KSI_PKISignature *tmp = NULL;
	const unsigned char *raw = NULL;
	size_t raw_len = 0;

	if (tlv == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = KSI_TLV_getCtx(tlv);
	KSI_ERR_clearErrors(ctx);

	if (sig == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PKISignature_new(ctx, raw, raw_len, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*sig = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(raw);

	KSI_PKISignature_free(tmp);

	return res;
}

int KSI_PKISignature_toTlv(KSI_CTX *ctx, KSI_PKISignature *sig, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res;
	KSI_TLV *tmp = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || sig == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PKISignature_serialize(sig, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_setRawValue(tmp, raw, raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(raw);
	KSI_TLV_free(tmp);

	return res;
}

int KSI_PKICertificate_fromTlv(KSI_TLV *tlv, KSI_PKICertificate **cert) {
	KSI_CTX *ctx = NULL;
	int res;

	KSI_PKICertificate *tmp = NULL;
	const unsigned char *raw = NULL;
	size_t raw_len = 0;


	if (tlv == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = KSI_TLV_getCtx(tlv);
	KSI_ERR_clearErrors(ctx);

	if (cert == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_TLV_getRawValue(tlv, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PKICertificate_new(ctx, raw, raw_len, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*cert = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_nofree(raw);

	KSI_PKICertificate_free(tmp);

	return res;
}

int KSI_PKICertificate_toTlv(KSI_CTX *ctx, KSI_PKICertificate *cert, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res;
	KSI_TLV *tmp = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;

	KSI_ERR_clearErrors(ctx);

	if (cert == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_TLV_new(ctx, KSI_TLV_PAYLOAD_RAW, tag, isNonCritical, isForward, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PKICertificate_serialize(cert, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_TLV_setRawValue(tmp, raw, raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*tlv = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(raw);
	KSI_TLV_free(tmp);

	return res;
}

char* KSI_PKICertificate_toString(KSI_PKICertificate *cert, char *buf, size_t buf_len){
	int res;
	char *ret = NULL;
	char subjectName[1024];
	char issuerName[1024];
	char ID[1024];
	char date_before[64];
	char date_after[64];
	KSI_uint64_t int_notBefore;
	KSI_uint64_t int_notAfter;
	KSI_Integer *notBefore = NULL;
	KSI_Integer *notAfter = NULL;
	KSI_CTX *ctx = NULL;
	long serial_number;
	KSI_OctetString *crc32 = NULL;

	if (cert == NULL || buf == NULL || buf_len == 0) {
		return NULL;
	}

	ctx = KSI_PKICertificate_getCtx(cert);
	if (ctx == NULL){
		return NULL;
	}

	if (KSI_PKICertificate_issuerToString(cert, issuerName, sizeof(issuerName)) == NULL) {
		goto cleanup;
	}

	if (KSI_PKICertificate_subjectToString(cert, subjectName, sizeof(subjectName)) == NULL) {
		goto cleanup;
	}

	res = KSI_PKICertificate_getValidityNotBefore(cert, &int_notBefore);
	if (res != KSI_OK) goto cleanup;

	res = KSI_PKICertificate_getValidityNotAfter(cert, &int_notAfter);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(ctx, int_notBefore, &notBefore);
	if (res != KSI_OK) goto cleanup;

	res = KSI_Integer_new(ctx, int_notAfter, &notAfter);
	if (res != KSI_OK) goto cleanup;

	if (KSI_Integer_toDateString(notBefore, date_before, sizeof(date_before)) == NULL) goto cleanup;
	if (KSI_Integer_toDateString(notAfter, date_after, sizeof(date_after)) == NULL) goto cleanup;

	res = KSI_PKICertificate_calculateCRC32(cert, &crc32);
	if (res != KSI_OK) goto cleanup;

	res = KSI_PKICertificate_getSerialNumber(cert, &serial_number);
	if (res != KSI_OK) goto cleanup;

	if (KSI_OctetString_toString(crc32, ':', ID, sizeof(ID)) == NULL) {
		goto cleanup;
	}

	KSI_snprintf(buf, buf_len, "PKI Certificate (%s):\n"
			"  * Issued to: %s\n"
			"  * Issuer by '%s'\n"
			"  * Valid from %s to %s\n"
			"  * Serial Number: 0x%02x\n",
		ID,subjectName, issuerName, date_before, date_after, serial_number);

	ret = buf;

cleanup:

	KSI_Integer_free(notAfter);
	KSI_Integer_free(notBefore);
	KSI_OctetString_free(crc32);

	return ret;
}

int KSI_PKICertificate_calculateCRC32(KSI_PKICertificate *cert, KSI_OctetString **crc) {
	int res;
	KSI_OctetString *tmp = NULL;
	unsigned long ID;
	unsigned char buf[4];
	unsigned char *raw = NULL;
	size_t raw_len;
	KSI_CTX *ctx = NULL;

	if (cert == NULL || crc == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	ctx = KSI_PKICertificate_getCtx(cert);
	if (ctx == NULL) {
		res = KSI_UNKNOWN_ERROR;
		goto cleanup;
	}

	res = KSI_PKICertificate_serialize(cert, &raw, &raw_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, "Unable to serialize PKI certificate.");
		goto cleanup;
	}

	ID = KSI_crc32(raw, raw_len, 0);

	buf[0] = 0xff & (ID >> 24);
	buf[1] = 0xff & (ID >> 16);
	buf[2] = 0xff & (ID >> 8);
	buf[3] = 0xff & (ID >> 0);

	res = KSI_OctetString_new(ctx, buf, sizeof(buf), &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*crc = tmp;
	tmp = NULL;
	res = KSI_OK;

cleanup:

	KSI_free(raw);
	KSI_OctetString_free(tmp);

	return res;
}