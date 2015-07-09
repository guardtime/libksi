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
#include <stdio.h>
#include <time.h>

#include "base32.h"
#include "crc32.h"
#include "internal.h"
#include "io.h"
#include "publicationsfile_impl.h"
#include "tlv.h"
#include "tlv_template.h"
#include "pkitruststore.h"

#define PUB_FILE_HEADER_ID "KSIPUBLF"

KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationsHeader)
KSI_IMPORT_TLV_TEMPLATE(KSI_CertificateRecord)
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord)

KSI_IMPLEMENT_LIST(KSI_PublicationData, KSI_PublicationData_free);
KSI_IMPLEMENT_LIST(KSI_PublicationRecord, KSI_PublicationRecord_free);



static int publicationsFile_setHeader(KSI_PublicationsFile *t, KSI_PublicationsHeader *header);
static int publicationsFile_setCertificates(KSI_PublicationsFile *t, KSI_LIST(KSI_CertificateRecord) *certificates);
static int publicationsFile_setPublications(KSI_PublicationsFile *t, KSI_LIST(KSI_PublicationRecord) *publications);
static int publicationsFile_setSignature(KSI_PublicationsFile *t, KSI_PKISignature *signature);

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationsFile)
	KSI_TLV_COMPOSITE(0x0701, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationsFile_getHeader, publicationsFile_setHeader, KSI_PublicationsHeader, "pub_header")
	KSI_TLV_COMPOSITE_LIST(0x0702, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationsFile_getCertificates, publicationsFile_setCertificates, KSI_CertificateRecord, "cert_rec")
	KSI_TLV_COMPOSITE_LIST(0x0703, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationsFile_getPublications, publicationsFile_setPublications, KSI_PublicationRecord, "pub_rec")
	KSI_TLV_OBJECT(0x0704, KSI_TLV_TMPL_FLG_MANDATORY | KSI_TLV_TMPL_FLG_MORE_DEFS, KSI_PublicationsFile_getSignature, publicationsFile_setSignature, KSI_PKISignature_fromTlv, KSI_PKISignature_toTlv, KSI_PKISignature_free, "pki_signature")
KSI_END_TLV_TEMPLATE

struct generator_st {
	KSI_RDR *reader;
	KSI_TLV *tlv;
	size_t offset;
	size_t sig_offset;
};

static int generateNextTlv(struct generator_st *gen, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *buf;
	size_t consumed;


	if (gen->tlv != NULL) {
		KSI_TLV_free(gen->tlv);
		gen->tlv = NULL;
	}

	buf = KSI_malloc(0xffff + 4);
	if (buf == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	res = KSI_TLV_readTlv(gen->reader, buf, 0xffff + 4, &consumed);
	if (res != KSI_OK) goto cleanup;

	if(consumed > UINT_MAX){
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	if (consumed > 0) {
		res = KSI_TLV_parseBlob2(KSI_RDR_getCtx(gen->reader), buf, (unsigned)consumed, 1, &gen->tlv);
		if (res != KSI_OK) goto cleanup;

		buf = NULL;

		if (KSI_TLV_getTag(gen->tlv) == 0x0704) {
			gen->sig_offset = gen->offset;
		}
	}

	gen->offset += consumed;

	*tlv = gen->tlv;

	res = KSI_OK;

cleanup:

	KSI_free(buf);

	return res;
}

static int publicationsFile_setHeader(KSI_PublicationsFile *t, KSI_PublicationsHeader *header) {
	int res = KSI_UNKNOWN_ERROR;
	if (t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->header = header;
	res = KSI_OK;
cleanup:
	 return res;
}

static int publicationsFile_setCertificates(KSI_PublicationsFile *t, KSI_LIST(KSI_CertificateRecord) *certificates) {
	int res = KSI_UNKNOWN_ERROR;
	if (t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->certificates = certificates;
	res = KSI_OK;
cleanup:
	 return res;
}

static int publicationsFile_setPublications(KSI_PublicationsFile *t, KSI_LIST(KSI_PublicationRecord) *publications) {
	int res = KSI_UNKNOWN_ERROR;
	if (t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->publications = publications;
	res = KSI_OK;
cleanup:
	 return res;
}

static int publicationsFile_setSignature(KSI_PublicationsFile *t, KSI_PKISignature *signature) {
	int res = KSI_UNKNOWN_ERROR;
	if (t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->signature = signature;
	res = KSI_OK;
cleanup:
	 return res;
}

/*
 * FIXME! At the moment the users may not create publications files, as there are
 * missing functions to manipulate its contents.
 */
static int KSI_PublicationsFile_new(KSI_CTX *ctx, KSI_PublicationsFile **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationsFile *tmp = NULL;
	tmp = KSI_new(KSI_PublicationsFile);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->raw = NULL;
	tmp->raw_len = 0;
	tmp->header = NULL;
	tmp->certificates = NULL;
	tmp->publications = NULL;
	tmp->signature = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_PublicationsFile_free(tmp);
	return res;
}

int KSI_PublicationsFile_parse(KSI_CTX *ctx, const void *raw, size_t raw_len, KSI_PublicationsFile **pubFile) {
	int res;
	unsigned char hdr[8];
	size_t hdr_len = 0;
	KSI_PublicationsFile *tmp = NULL;
	KSI_RDR *reader = NULL;
	struct generator_st gen = {NULL, NULL, 0, 0};
	unsigned char *tmpRaw = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || raw == NULL || raw_len == 0 || pubFile == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_RDR_fromSharedMem(ctx, (unsigned char *)raw, raw_len, &reader);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	/* Read file header. */
	res = KSI_RDR_read_ex(reader, hdr, sizeof(hdr), &hdr_len);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (hdr_len != sizeof(hdr) || memcmp(hdr, PUB_FILE_HEADER_ID, hdr_len)) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, "Unrecognized header.");
		goto cleanup;
	}

	/* Header verification ok - create the store object. */
	res = KSI_PublicationsFile_new(ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->signedDataLength = strlen(PUB_FILE_HEADER_ID);

        /* Initialize generator. */
	gen.reader = reader;
	gen.tlv = NULL;

	/* Read the payload of the file, and make no assumptions with the ordering. */
	res = KSI_TlvTemplate_extractGenerator(ctx, tmp, (void *)&gen, KSI_TLV_TEMPLATE(KSI_PublicationsFile), (int (*)(void *, KSI_TLV **))generateNextTlv);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp->signedDataLength += gen.sig_offset;

	/* Copy the raw value */
	tmpRaw = KSI_malloc(raw_len);
	if (tmpRaw == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	memcpy(tmpRaw, raw, raw_len);

	tmp->raw = tmpRaw;
	tmp->raw_len = raw_len;
	tmpRaw = NULL;

	*pubFile = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:


	KSI_free(tmpRaw);
	KSI_TLV_free(gen.tlv);
	KSI_PublicationsFile_free(tmp);
	KSI_RDR_close(reader);

	return res;
}

int KSI_PublicationsFile_verify(KSI_PublicationsFile *pubFile, KSI_CTX *ctx) {
	int res;
	KSI_CTX *useCtx = ctx;
	KSI_PKITruststore *pki = NULL;

	if (pubFile == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (useCtx == NULL) {
		useCtx = pubFile->ctx;
	}

	KSI_ERR_clearErrors(useCtx);

	/* Make sure the signature exists. */
	if (pubFile->signature == NULL) {
		KSI_pushError(useCtx, res = KSI_PUBLICATIONS_FILE_NOT_SIGNED_WITH_PKI, NULL);
		goto cleanup;
	}

	/* Do we need to serialize the publications file? */
	if (pubFile->raw == NULL) {
		/* FIXME! At the moment the creation of publications file is not supported,
		 * thus this error can not occur under normal conditions. */
		KSI_pushError(useCtx, res = KSI_UNKNOWN_ERROR, "Not implemented");
		goto cleanup;
	}

	res = KSI_CTX_getPKITruststore(useCtx, &pki);
	if (res != KSI_OK) {
		KSI_pushError(useCtx, res, NULL);
		goto cleanup;
	}

	res = KSI_PKITruststore_verifySignature(pki, pubFile->raw, pubFile->signedDataLength, pubFile->signature);
	if (res != KSI_OK) {
		KSI_pushError(useCtx, res, "Publications file not trusted.");
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	KSI_nofree(useCtx);
	KSI_nofree(pki);

	return res;
}

int KSI_PublicationsFile_fromFile(KSI_CTX *ctx, const char *fileName, KSI_PublicationsFile **pubFile) {
	int res;
	KSI_RDR *reader = NULL;
	KSI_PublicationsFile *tmp = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;
	long raw_size = 0;
	FILE *f = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || fileName == NULL || pubFile == 0) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	f = fopen(fileName, "rb");
	if (f == NULL) {
		KSI_pushError(ctx, res = KSI_IO_ERROR, "Unable to open publications file.");
		goto cleanup;
	}

	res = fseek(f, 0, SEEK_END);
	if (res != 0) {
		KSI_pushError(ctx, res = KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	raw_size = ftell(f);
	if (raw_size < 0) {
		KSI_pushError(ctx, res = KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	if (raw_size > UINT_MAX) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = fseek(f, 0, SEEK_SET);
	if (res != 0) {
		KSI_pushError(ctx, res = KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	raw = KSI_calloc((unsigned)raw_size, 1);
	if (raw == NULL) {
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	raw_len = fread(raw, 1, (unsigned)raw_size, f);
	if (raw_len != raw_size) {
		KSI_pushError(ctx, res = KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	res = KSI_PublicationsFile_parse(ctx, raw, (unsigned)raw_len, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	*pubFile = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	if (f != NULL) fclose(f);
	KSI_free(raw);
	KSI_RDR_close(reader);
	KSI_PublicationsFile_free(tmp);

	return res;
}


int KSI_PublicationsFile_serialize(KSI_CTX *ctx, KSI_PublicationsFile *pubFile, char **raw, size_t *raw_len) {
	int res;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || pubFile == 0 || raw == NULL || raw_len == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	*raw_len = pubFile->raw_len;
	*raw = (char*)KSI_malloc(*raw_len);
	if (*raw == NULL){
		KSI_pushError(ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	memcpy(*raw, pubFile->raw, *raw_len);

	res = KSI_OK;

cleanup:

	return res;
}


void KSI_PublicationsFile_free(KSI_PublicationsFile *t) {
	if (t != NULL) {
		KSI_PublicationsHeader_free(t->header);
		KSI_CertificateRecordList_free(t->certificates);
		KSI_PublicationRecordList_free(t->publications);
		KSI_PKISignature_free(t->signature);
		KSI_free(t->raw);
		KSI_free(t);
	}
}

int KSI_PublicationsFile_getHeader(const KSI_PublicationsFile *t, KSI_PublicationsHeader **header) {
	int res = KSI_UNKNOWN_ERROR;
	if (t == NULL || header == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*header = t->header;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_PublicationsFile_getCertificates(const KSI_PublicationsFile *t, KSI_LIST(KSI_CertificateRecord) **certificates) {
	int res = KSI_UNKNOWN_ERROR;
	if (t == NULL || certificates == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*certificates = t->certificates;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_PublicationsFile_getPublications(const KSI_PublicationsFile *t, KSI_LIST(KSI_PublicationRecord) **publications) {
	int res = KSI_UNKNOWN_ERROR;
	if (t == NULL || publications == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*publications = t->publications;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_PublicationsFile_getPKICertificateById(const KSI_PublicationsFile *pubFile, const KSI_OctetString *id, KSI_PKICertificate **cert) {
	int res;
	size_t i;
	KSI_CertificateRecord *certRec = NULL;

	if (pubFile == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(pubFile->ctx);

	if (id == NULL || cert == NULL) {
		KSI_pushError(pubFile->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	for (i = 0; i < KSI_CertificateRecordList_length(pubFile->certificates); i++) {
		KSI_OctetString *cId = NULL;

		res = KSI_CertificateRecordList_elementAt(pubFile->certificates, i, &certRec);
		if (res != KSI_OK) {
			KSI_pushError(pubFile->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_CertificateRecord_getCertId(certRec, &cId);
		if (res != KSI_OK) {
			KSI_pushError(pubFile->ctx, res, NULL);
			goto cleanup;
		}

		if (KSI_OctetString_equals(cId, id)) {
			res = KSI_CertificateRecord_getCert(certRec, cert);
			if (res != KSI_OK) {
				KSI_pushError(pubFile->ctx, res, NULL);
				goto cleanup;
			}

			break;
		}
	}

	res = KSI_OK;

cleanup:

	KSI_nofree(certRec);

	return res;
}

int KSI_PublicationsFile_getPublicationDataByTime(const KSI_PublicationsFile *trust, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec) {
	int res;
	size_t i;
	KSI_PublicationRecord *result = NULL;

	if (trust == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(trust->ctx);

	if (pubTime == NULL || pubRec == NULL) {
		KSI_pushError(trust->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	for (i = 0; i < KSI_PublicationRecordList_length(trust->publications); i++) {
		KSI_PublicationRecord *pr = NULL;
		KSI_PublicationData *pd = NULL;
		KSI_Integer *tm = NULL;

		res = KSI_PublicationRecordList_elementAt(trust->publications, i, &pr);
		if (res != KSI_OK) {
			KSI_pushError(trust->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_PublicationRecord_getPublishedData(pr, &pd);
		if (res != KSI_OK) {
			KSI_pushError(trust->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_PublicationData_getTime(pd, &tm);
		if (res != KSI_OK) {
			KSI_pushError(trust->ctx, res, NULL);
			goto cleanup;
		}

		if (KSI_Integer_equals(pubTime, tm)) {
			result = pr;
			break;
		}

		KSI_nofree(tm);
		KSI_nofree(pd);
	}

	*pubRec = result;

	res = KSI_OK;

cleanup:

	KSI_nofree(result);

	return res;
}

int KSI_PublicationsFile_getPublicationDataByPublicationString(const KSI_PublicationsFile *pubFile, const char *pubString, KSI_PublicationRecord **pubRec) {
	int res;
	KSI_PublicationData *findPubData = NULL;
	KSI_DataHash *findImprint = NULL;
	KSI_Integer *findTime = NULL;

	KSI_PublicationRecord *tmpPubRec = NULL;
	KSI_PublicationData *tmpPubData = NULL;
	KSI_DataHash *tmpImprint = NULL;

	if (pubFile == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(pubFile->ctx);

	if (pubString == NULL || pubRec == NULL) {
		KSI_pushError(pubFile->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	/* Decode the publication string. */
	res = KSI_PublicationData_fromBase32(pubFile->ctx, pubString, &findPubData);
	if (res != KSI_OK) {
		KSI_pushError(pubFile->ctx, res, NULL);
		goto cleanup;
	}

	/* Extract the expected imprint. */
	res = KSI_PublicationData_getImprint(findPubData, &findImprint);
	if (res != KSI_OK) {
		KSI_pushError(pubFile->ctx, res, NULL);
		goto cleanup;
	}

	/* Extract the expected publication time. */
	res = KSI_PublicationData_getTime(findPubData, &findTime);
	if (res != KSI_OK) {
		KSI_pushError(pubFile->ctx, res, NULL);
		goto cleanup;
	}

	/* Find the publication using the publication time. */
	res = KSI_PublicationsFile_getPublicationDataByTime(pubFile, findTime, &tmpPubRec);
	if (res != KSI_OK) {
		KSI_pushError(pubFile->ctx, res, NULL);
		goto cleanup;
	}

	if (tmpPubRec != NULL) {
		/* Extract published data. */
		res = KSI_PublicationRecord_getPublishedData(tmpPubRec, &tmpPubData);
		if (res != KSI_OK) {
			KSI_pushError(pubFile->ctx, res, NULL);
			goto cleanup;
		}

		/* Extract the time. */
		res = KSI_PublicationData_getImprint(tmpPubData, &tmpImprint);
		if (res != KSI_OK) {
			KSI_pushError(pubFile->ctx, res, NULL);
			goto cleanup;
		}

		if (!KSI_DataHash_equals(findImprint, tmpImprint))  {
			KSI_pushError(pubFile->ctx, res = KSI_INVALID_PUBLICATION, NULL);
			goto cleanup;
		}
	}

	*pubRec = tmpPubRec;

	res = KSI_OK;

cleanup:

	KSI_PublicationData_free(findPubData);
	KSI_nofree(findImprint);
	KSI_nofree(findTime);

	KSI_nofree(tmpPubRec);
	KSI_nofree(tmpPubData);
	KSI_nofree(tmpImprint);

	return res;
}

/*
 */
int KSI_PublicationsFile_getNearestPublication(const KSI_PublicationsFile *trust, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec) {
	int res;
	size_t i;
	KSI_PublicationRecord *result = NULL;
	KSI_Integer *result_tm = NULL;

	if (trust == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(trust->ctx);

	if (pubTime == NULL || pubRec == NULL) {
		KSI_pushError(trust->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	for (i = 0; i < KSI_PublicationRecordList_length(trust->publications); i++) {
		KSI_PublicationRecord *pr = NULL;
		KSI_PublicationData *pd = NULL;
		KSI_Integer *tm = NULL;

		res = KSI_PublicationRecordList_elementAt(trust->publications, i, &pr);
		if (res != KSI_OK) {
			KSI_pushError(trust->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_PublicationRecord_getPublishedData(pr, &pd);
		if (res != KSI_OK) {
			KSI_pushError(trust->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_PublicationData_getTime(pd, &tm);
		if (res != KSI_OK) {
			KSI_pushError(trust->ctx, res, NULL);
			goto cleanup;
		}

		/* Check, if current publication time is after given time. */
		if (KSI_Integer_compare(pubTime, tm) < 0) {
			if (result_tm == NULL || KSI_Integer_compare(result_tm, tm) > 0) {
				result = pr;
				result_tm = tm;
			}
		}

		KSI_nofree(tm);
		KSI_nofree(pd);
	}

	*pubRec = result;

	res = KSI_OK;

cleanup:

	KSI_nofree(result);
	KSI_nofree(result_tm);

	return res;
}

int KSI_PublicationsFile_getLatestPublication(const KSI_PublicationsFile *trust, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec) {
	int res;
	size_t i;
	KSI_PublicationRecord *result = NULL;
	KSI_Integer *result_tm = NULL;

	if (trust == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(trust->ctx);

	if (pubTime == NULL || pubRec == NULL) {
		KSI_pushError(trust->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	for (i = 0; i < KSI_PublicationRecordList_length(trust->publications); i++) {
		KSI_PublicationRecord *pr = NULL;
		KSI_PublicationData *pd = NULL;
		KSI_Integer *tm = NULL;

		res = KSI_PublicationRecordList_elementAt(trust->publications, i, &pr);
		if (res != KSI_OK) {
			KSI_pushError(trust->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_PublicationRecord_getPublishedData(pr, &pd);
		if (res != KSI_OK) {
			KSI_pushError(trust->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_PublicationData_getTime(pd, &tm);
		if (res != KSI_OK) {
			KSI_pushError(trust->ctx, res, NULL);
			goto cleanup;
		}

		/* Check, if current publication time is after given time. If
		 * pubTime is NULL, the latest available publication is returned. */
		if (pubTime == NULL || KSI_Integer_compare(pubTime, tm) < 0) {
			/* Check if the current publication time is after the last found time. */
			if (result_tm == NULL || KSI_Integer_compare(result_tm, tm) > 0) {
				result = pr;
				result_tm = tm;
			}
		}

		KSI_nofree(tm);
		KSI_nofree(pd);
	}

	*pubRec = result;

	res = KSI_OK;

cleanup:

	KSI_nofree(result);
	KSI_nofree(result_tm);

	return res;
}

int KSI_PublicationsFile_findPublication(const KSI_PublicationsFile *trust, KSI_PublicationRecord *inRec, KSI_PublicationRecord **outRec) {
	int res;
	size_t i;

	if (trust == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(trust->ctx);

	if (inRec == NULL || outRec == NULL) {
		KSI_pushError(trust->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	for (i = 0; i < KSI_PublicationRecordList_length(trust->publications); i++) {
		KSI_PublicationRecord *pr = NULL;

		res = KSI_PublicationRecordList_elementAt(trust->publications, i, &pr);
		if (res != KSI_OK) {
			KSI_pushError(trust->ctx, res, NULL);
			goto cleanup;
		}

		if (KSI_DataHash_equals(pr->publishedData->imprint, inRec->publishedData->imprint) && KSI_Integer_equals(pr->publishedData->time, inRec->publishedData->time) ) {
			*outRec = pr;
			break;
		}

		KSI_nofree(pr);
	}

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_PublicationsFile_getSignature(const KSI_PublicationsFile *t, KSI_PKISignature **signature) {
	int res = KSI_UNKNOWN_ERROR;
	if (t == NULL || signature == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*signature = t->signature;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_PublicationData_fromBase32(KSI_CTX *ctx, const char *publication, KSI_PublicationData **published_data) {
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *binary_publication = NULL;
	size_t binary_publication_length;
	KSI_PublicationData *tmp_published_data = NULL;
	unsigned i;
	unsigned long tmp_ulong;
	KSI_uint64_t tmp_uint64;
	KSI_HashAlgorithm algo_id;
	size_t hash_size;
	KSI_DataHash *pubHash = NULL;
	KSI_Integer *pubTime = NULL;

	KSI_ERR_clearErrors(ctx);

	if (ctx == NULL || publication == NULL || published_data == NULL) {
		KSI_pushError(ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_base32Decode(publication, &binary_publication, &binary_publication_length);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	if (binary_publication_length < 13) {
		res = KSI_INVALID_FORMAT;
		goto cleanup;
	}

	tmp_ulong = 0;
	for (i = 0; i < 4; ++i) {
		tmp_ulong <<= 8;
		tmp_ulong |= binary_publication[binary_publication_length - 4 + i];
	}

	if (KSI_crc32(binary_publication, binary_publication_length - 4, 0) !=
			tmp_ulong) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_PublicationData_new(ctx, &tmp_published_data);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	tmp_uint64 = 0;
	for (i = 0; i < 8; ++i) {
		tmp_uint64 <<= 8;
		tmp_uint64 |= binary_publication[i];
	}

	res = KSI_Integer_new(ctx, tmp_uint64, &pubTime);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationData_setTime(tmp_published_data, pubTime);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	pubTime = NULL;


	algo_id = binary_publication[8];
	if (!KSI_isHashAlgorithmSupported(algo_id)) {
		KSI_pushError(ctx, res = KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	hash_size = KSI_getHashLength(algo_id);
	if (binary_publication_length != 8 + 1 + hash_size + 4) {
		KSI_pushError(ctx, res = KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_fromImprint(ctx, binary_publication + 8, hash_size + 1, &pubHash);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_PublicationData_setImprint(tmp_published_data, pubHash);
	if (res != KSI_OK) {
		KSI_pushError(ctx, res, NULL);
		goto cleanup;
	}

	pubHash = NULL;

	*published_data = tmp_published_data;
	tmp_published_data = NULL;

	res = KSI_OK;

cleanup:
	KSI_Integer_free(pubTime);
	KSI_DataHash_free(pubHash);
	KSI_free(binary_publication);
	KSI_PublicationData_free(tmp_published_data);

	return res;
}

int KSI_PublicationData_toBase32(const KSI_PublicationData *pubData, char **pubStr) {
	int res;
	const unsigned char *imprint = NULL;
	size_t imprint_len = 0;
	KSI_uint64_t publication_identifier = 0;
	unsigned char *binPub = NULL;
	size_t binPub_length;
	int i;
	unsigned long tmp_ulong;
	char *tmp = NULL;

	if (pubData == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(pubData->ctx);

	if (pubStr == NULL) {
		KSI_pushError(pubData->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_DataHash_getImprint(pubData->imprint, &imprint, &imprint_len);
	if (res != KSI_OK) {
		KSI_pushError(pubData->ctx, res, NULL);
		goto cleanup;
	}

	binPub_length =	8 + imprint_len + 4;
	binPub = KSI_calloc(binPub_length, 1);
	if (binPub == NULL) {
		KSI_pushError(pubData->ctx, res = KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	publication_identifier = KSI_Integer_getUInt64(pubData->time);

	for (i = 7; i >= 0; --i) {
		binPub[i] = (unsigned char) (publication_identifier & 0xff);
		publication_identifier >>= 8;
	}

	memcpy(binPub + 8, imprint, imprint_len);

	tmp_ulong = KSI_crc32(binPub, binPub_length - 4, 0);
	for (i = 3; i >= 0; --i) {
		binPub[binPub_length - 4 + i] =
			(unsigned char) (tmp_ulong & 0xff);
		tmp_ulong >>= 8;
	}

	res = KSI_base32Encode(binPub, binPub_length, 6, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(pubData->ctx, res, NULL);
		goto cleanup;
	}

	*pubStr = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_free(binPub);
	KSI_free(tmp);

	return res;
}

int KSI_PublicationRecord_toBase32(KSI_PublicationRecord *pubRec, char **pubStr) {
	int res;

	if (pubRec == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(pubRec->ctx);

	if (pubStr == NULL) {
		KSI_pushError(pubRec->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}


	res = KSI_PublicationData_toBase32(pubRec->publishedData, pubStr);
	if (res != KSI_OK) {
		KSI_pushError(pubRec->ctx, res, NULL);
		goto cleanup;
	}

	res = KSI_OK;

cleanup:

	return res;
}

/**
 * KSI_PublicationData
 */
void KSI_PublicationData_free(KSI_PublicationData *t) {
	if (t != NULL) {
		KSI_Integer_free(t->time);
		KSI_DataHash_free(t->imprint);
		KSI_TLV_free(t->baseTlv);
		KSI_free(t);
	}
}

int KSI_PublicationData_new(KSI_CTX *ctx, KSI_PublicationData **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationData *tmp = NULL;

	if (ctx == NULL || t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	tmp = KSI_new(KSI_PublicationData);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->time = NULL;
	tmp->imprint = NULL;
	tmp->baseTlv = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_PublicationData_free(tmp);
	return res;
}

char *KSI_PublicationData_toString(KSI_PublicationData *t, char *buffer, size_t buffer_len) {
	int res = KSI_UNKNOWN_ERROR;
	char *ret = NULL;
	size_t len = 0;
	char *pubStr = NULL;
	char tmp[256];

	res = KSI_PublicationData_toBase32(t, &pubStr);
	if (res != KSI_OK) {
		KSI_LOG_error(t->ctx, "Unable to convert publication data to base 32: %s (%d)", KSI_getErrorString(res), res);
		goto cleanup;
	}

	len += KSI_snprintf(buffer + len, buffer_len - len, "Publication string: %s\nPublication date: %s", pubStr, KSI_Integer_toDateString(t->time, tmp, sizeof(tmp)));
	KSI_snprintf(buffer + len, buffer_len - len, "\nPublished hash: %s", KSI_DataHash_toString(t->imprint, tmp, sizeof(tmp)));

	ret = buffer;

cleanup:

	KSI_free(pubStr);

	return ret;
}

char *KSI_PublicationRecord_toString(KSI_PublicationRecord *t, char *buffer, size_t buffer_len) {
	int res = KSI_UNKNOWN_ERROR;
	char *ret = NULL;
	char tmp[256];
	size_t len = 0;
	size_t i;

	len += KSI_snprintf(buffer + len, buffer_len - len, "%s", KSI_PublicationData_toString(t->publishedData, tmp, sizeof(tmp)));

	for (i = 0; i < KSI_Utf8StringList_length(t->publicationRef); i++) {
		KSI_Utf8String *ref = NULL;

		res = KSI_Utf8StringList_elementAt(t->publicationRef, i, &ref);
		if (res != KSI_OK) goto cleanup;

		len += KSI_snprintf(buffer + len, buffer_len - len, "\nRef: %s", KSI_Utf8String_cstr(ref));
	}

	ret = buffer;

cleanup:

	return ret;
}

KSI_IMPLEMENT_GETTER(KSI_PublicationData, KSI_TLV*, baseTlv, BaseTlv);
KSI_IMPLEMENT_GETTER(KSI_PublicationData, KSI_Integer*, time, Time);
KSI_IMPLEMENT_GETTER(KSI_PublicationData, KSI_DataHash*, imprint, Imprint);

KSI_IMPLEMENT_SETTER(KSI_PublicationData, KSI_TLV*, baseTlv, BaseTlv);
KSI_IMPLEMENT_SETTER(KSI_PublicationData, KSI_Integer*, time, Time);
KSI_IMPLEMENT_SETTER(KSI_PublicationData, KSI_DataHash*, imprint, Imprint);

KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationData);
KSI_IMPLEMENT_FROMTLV(KSI_PublicationData, 0x10, FROMTLV_ADD_BASETLV(baseTlv));
KSI_IMPLEMENT_TOTLV(KSI_PublicationData);
/**
 * KSI_PublicationRecord
 */
void KSI_PublicationRecord_free(KSI_PublicationRecord *t) {
	if (t != NULL) {
		KSI_PublicationData_free(t->publishedData);
		KSI_Utf8StringList_free(t->publicationRef);
		KSI_Utf8StringList_free(t->repositoryUriList);
		KSI_free(t);
	}
}

int KSI_PublicationRecord_new(KSI_CTX *ctx, KSI_PublicationRecord **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationRecord *tmp = NULL;
	if (ctx == NULL || t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	tmp = KSI_new(KSI_PublicationRecord);
	if (tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->publishedData = NULL;
	tmp->repositoryUriList = NULL;
	tmp->publicationRef = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_PublicationRecord_free(tmp);
	return res;
}

int KSI_PublicationRecord_clone(const KSI_PublicationRecord *rec, KSI_PublicationRecord **clone){
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationRecord *tmp = NULL;
	size_t i = 0;

	if (rec == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	KSI_ERR_clearErrors(rec->ctx);

	if (clone == NULL) {
		KSI_pushError(rec->ctx, res = KSI_INVALID_ARGUMENT, NULL);
		goto cleanup;
	}

	res = KSI_PublicationRecord_new(rec->ctx, &tmp);
	if (res != KSI_OK) {
		KSI_pushError(rec->ctx, res, NULL);
		goto cleanup;
	}

	/*Copy publication references*/
	res = KSI_Utf8StringList_new(&(tmp->publicationRef));
	if (res != KSI_OK) goto cleanup;

	for (i = 0; i < KSI_Utf8StringList_length(rec->publicationRef); i++){
		KSI_Utf8String *str = NULL;
		res = KSI_Utf8StringList_elementAt(rec->publicationRef, i, &str);
		if (res != KSI_OK) {
			KSI_pushError(rec->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_Utf8String_ref(str);
		if (res != KSI_OK) {
			KSI_pushError(rec->ctx, res, NULL);
			goto cleanup;
		}

		res = KSI_Utf8StringList_append(tmp->publicationRef, str);
		if (res != KSI_OK) {
			KSI_pushError(rec->ctx, res, NULL);
			goto cleanup;
		}
	}

	/*Copy publication data*/
	res = KSI_PublicationData_new(rec->ctx, &(tmp->publishedData));
	if (res != KSI_OK) {
		KSI_pushError(rec->ctx, res, NULL);
		goto cleanup;
	}

	tmp->publishedData->ctx = rec->ctx;

	res = KSI_DataHash_clone(rec->publishedData->imprint, &(tmp->publishedData->imprint));
	if (res != KSI_OK) {
		KSI_pushError(rec->ctx, res, NULL);
		goto cleanup;
	}

	KSI_Integer_ref(rec->publishedData->time);

	tmp->publishedData->time = rec->publishedData->time;

	*clone = tmp;
	tmp = NULL;

	res = KSI_OK;

cleanup:

	KSI_PublicationRecord_free(tmp);

	return res;
}

KSI_IMPLEMENT_GETTER(KSI_PublicationRecord, KSI_PublicationData*, publishedData, PublishedData);
KSI_IMPLEMENT_GETTER(KSI_PublicationRecord, KSI_LIST(KSI_Utf8String)*, publicationRef, PublicationRefList);
KSI_IMPLEMENT_GETTER(KSI_PublicationRecord, KSI_LIST(KSI_Utf8String)*, repositoryUriList, RepositoryUriList);

KSI_IMPLEMENT_SETTER(KSI_PublicationRecord, KSI_PublicationData*, publishedData, PublishedData);
KSI_IMPLEMENT_SETTER(KSI_PublicationRecord, KSI_LIST(KSI_Utf8String)*, publicationRef, PublicationRefList);
KSI_IMPLEMENT_SETTER(KSI_PublicationRecord, KSI_LIST(KSI_Utf8String)*, repositoryUriList, RepositoryUriList);
