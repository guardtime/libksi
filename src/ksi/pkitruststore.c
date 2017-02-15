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
#include "pkitruststore.h"
#include "tlv.h"


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

int KSI_PKISignature_toTlv(KSI_CTX *ctx, const KSI_PKISignature *sig, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res;
	KSI_TLV *tmp = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || sig == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_TLV_new(ctx, tag, isNonCritical, isForward, &tmp);
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

int KSI_PKICertificate_toTlv(KSI_CTX *ctx, const KSI_PKICertificate *cert, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv) {
	int res;
	KSI_TLV *tmp = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;

	KSI_ERR_clearErrors(ctx);

	if (cert == NULL || tlv == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_TLV_new(ctx, tag, isNonCritical, isForward, &tmp);
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
