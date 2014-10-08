#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "internal.h"
#include "publicationsfile_impl.h"

KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationsHeader)
KSI_IMPORT_TLV_TEMPLATE(KSI_CertificateRecord)
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord)

KSI_IMPLEMENT_LIST(KSI_PublicationData, KSI_PublicationData_free);
KSI_IMPLEMENT_LIST(KSI_PublicationRecord, KSI_PublicationRecord_free);



static int publicationsFile_setHeader(KSI_PublicationsFile *t, KSI_PublicationsHeader *header);
static int publicationsFile_setCertificates(KSI_PublicationsFile *t, KSI_LIST(KSI_CertificateRecord) *certificates);
static int publicationsFile_setPublications(KSI_PublicationsFile *t, KSI_LIST(KSI_PublicationRecord) *publications);
static int publicationsFile_setSignature(KSI_PublicationsFile *t, KSI_PKISignature *signature);
static int publicationsFile_setSignatureOffset(KSI_PublicationsFile *t, size_t signatureOffset);

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationsFile)
	KSI_TLV_COMPOSITE(0x0701, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationsFile_getHeader, publicationsFile_setHeader, KSI_PublicationsHeader)
	KSI_TLV_COMPOSITE_LIST(0x0702, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationsFile_getCertificates, publicationsFile_setCertificates, KSI_CertificateRecord)
	KSI_TLV_COMPOSITE_LIST(0x0703, KSI_TLV_TMPL_FLG_MANDATORY, KSI_PublicationsFile_getPublications, publicationsFile_setPublications, KSI_PublicationRecord)
	KSI_TLV_OBJECT(0x0704, KSI_TLV_TMPL_FLG_MANDATORY | KSI_TLV_TMPL_FLG_MORE_DEFS, KSI_PublicationsFile_getSignature, publicationsFile_setSignature, KSI_PKISignature_fromTlv, KSI_PKISignature_toTlv, KSI_PKISignature_free)
	KSI_TLV_SEEK_POS(0x0704, publicationsFile_setSignatureOffset)
KSI_END_TLV_TEMPLATE

struct generator_st {
	KSI_RDR *reader;
	KSI_TLV *tlv;
};

static int generateNextTlv(struct generator_st *gen, KSI_TLV **tlv) {
	int res = KSI_UNKNOWN_ERROR;
	if (gen->tlv != NULL) {
		KSI_TLV_free(gen->tlv);
		gen->tlv = NULL;
	}

	res = KSI_TLV_fromReader(gen->reader, &gen->tlv);
	if (res != KSI_OK) goto cleanup;

	*tlv = gen->tlv;

	res = KSI_OK;

cleanup:

	return res;
}

static int publicationsFile_setSignatureOffset(KSI_PublicationsFile *t, size_t signatureOffset) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	t->signatureOffset = signatureOffset;
	res = KSI_OK;
cleanup:
	 return res;
}

static int publicationsFile_setHeader(KSI_PublicationsFile *t, KSI_PublicationsHeader *header) {
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

static int publicationsFile_setCertificates(KSI_PublicationsFile *t, KSI_LIST(KSI_CertificateRecord) *certificates) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL) {
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
	if(t == NULL) {
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
	if(t == NULL) {
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
	if(tmp == NULL) {
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
	KSI_ERR err;
	int res;
	unsigned char hdr[8];
	size_t hdr_len = 0;
	KSI_PublicationsFile *tmp = NULL;
	KSI_RDR *reader = NULL;
	struct generator_st gen = {NULL, NULL};
	unsigned char *tmpRaw = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len > 0) goto cleanup;
	KSI_PRE(&err, pubFile != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_RDR_fromSharedMem(ctx, (unsigned char *)raw, raw_len, &reader);
	KSI_CATCH(&err, res) goto cleanup;

	/* Read file header. */
	res = KSI_RDR_read_ex(reader, hdr, sizeof(hdr), &hdr_len);
	KSI_CATCH(&err, res) goto cleanup;

	if (hdr_len != sizeof(hdr) || memcmp(hdr, "KSIPUBLF", hdr_len)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Unrecognized header.");
		goto cleanup;
	}
        
	/* Header verification ok - create the store object. */
	res = KSI_PublicationsFile_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;
	
        /* Initialize generator. */
	gen.reader = reader;
	gen.tlv = NULL;

	/* Read the payload of the file, and make no assumptions with the ordering. */
	res = KSI_TlvTemplate_extractGenerator(ctx, tmp, (void *)&gen, KSI_TLV_TEMPLATE(KSI_PublicationsFile), (int (*)(void *, KSI_TLV **))generateNextTlv);
	KSI_CATCH(&err, res) goto cleanup;
	
        /* Copy the raw value */
	tmpRaw = KSI_calloc(raw_len, 1);
	if (tmpRaw == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	memcpy(tmpRaw, raw, raw_len);

	tmp->raw = tmpRaw;
        tmp->raw_len = raw_len;
	tmpRaw = NULL;

	*pubFile = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:


	KSI_free(tmpRaw);
	KSI_TLV_free(gen.tlv);
	KSI_PublicationsFile_free(tmp);
	KSI_RDR_close(reader);

	return KSI_RETURN(&err);
}

int KSI_PublicationsFile_verify(KSI_PublicationsFile *pubFile, KSI_CTX *ctx) {
	KSI_ERR err;
	int res;
	KSI_CTX *useCtx = ctx;
	KSI_PKITruststore *pki = NULL;

	KSI_PRE(&err, pubFile != NULL) goto cleanup;
	KSI_BEGIN(pubFile->ctx, &err);

	if (useCtx == NULL) {
		useCtx = pubFile->ctx;
	}

	/* Make sure the signature exists. */
	if (pubFile->signature == NULL) {
		KSI_FAIL(&err, KSI_PUBLICATIONS_FILE_NOT_SIGNED_WITH_PKI, NULL);
		goto cleanup;
	}

	/* Do we need to serialize the publications file? */
	if (pubFile->raw == NULL) {
		/* FIXME! At the moment the creation of publications file is not supported,
		 * thus this error can not occur under normal conditions. */
		KSI_FAIL(&err, KSI_UNKNOWN_ERROR, "Not implemented");
		goto cleanup;
	}

	res = KSI_getPKITruststore(useCtx, &pki);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKITruststore_verifySignature(pki, pubFile->raw, pubFile->signatureOffset, pubFile->signature);
	KSI_CATCH(&err, res) {
		KSI_FAIL(&err, res, "Publications file not trusted.");
		goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(useCtx);
	KSI_nofree(pki);

	return KSI_RETURN(&err);
}

int KSI_PublicationsFile_fromFile(KSI_CTX *ctx, const char *fileName, KSI_PublicationsFile **pubFile) {
	KSI_ERR err;
	int res;
	KSI_RDR *reader = NULL;
	KSI_PublicationsFile *tmp = NULL;
	unsigned char *raw = NULL;
	size_t raw_len = 0;
	long raw_size = 0;
	FILE *f = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, fileName != NULL) goto cleanup;
	KSI_PRE(&err, pubFile != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	f = fopen(fileName, "rb");
	if (f == NULL) {
		KSI_FAIL(&err, KSI_IO_ERROR, "Unable to open publications file.");
		goto cleanup;
	}

	res = fseek(f, 0, SEEK_END);
	if (res != 0) {
		KSI_FAIL(&err, KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	raw_size = ftell(f);
	if (raw_size < 0) {
		KSI_FAIL(&err, KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	if (raw_size > UINT_MAX) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = fseek(f, 0, SEEK_SET);
	if (res != 0) {
		KSI_FAIL(&err, KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	raw = KSI_calloc((unsigned)raw_size, 1);
	if (raw == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	raw_len = fread(raw, 1, (unsigned)raw_size, f);
	if (raw_len != raw_size) {
		KSI_FAIL(&err, KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	res = KSI_PublicationsFile_parse(ctx, raw, (unsigned)raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*pubFile = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	if (f != NULL) fclose(f);
	KSI_free(raw);
	KSI_RDR_close(reader);
	KSI_PublicationsFile_free(tmp);

	return KSI_RETURN(&err);
}


int KSI_PublicationsFile_serialize(KSI_CTX *ctx, KSI_PublicationsFile *pubFile, char **raw, int* raw_len) {
	KSI_ERR err;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, pubFile != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	*raw_len = pubFile->raw_len;
	*raw = (char*)KSI_malloc(*raw_len);
	if(*raw == NULL){
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, "KSI out of memory");
		goto cleanup;
		}

	memcpy(*raw, pubFile->raw, *raw_len);

	KSI_SUCCESS(&err);
cleanup:

	KSI_nofree(*raw);
	return KSI_RETURN(&err);
}


void KSI_PublicationsFile_free(KSI_PublicationsFile *t) {
	if(t != NULL) {
		KSI_PublicationsHeader_free(t->header);
		KSI_CertificateRecordList_freeAll(t->certificates);
		KSI_PublicationRecordList_freeAll(t->publications);
		KSI_PKISignature_free(t->signature);
		KSI_free(t->raw);
		KSI_free(t);
	}
}

int KSI_PublicationsFile_getHeader(const KSI_PublicationsFile *t, KSI_PublicationsHeader **header) {
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

int KSI_PublicationsFile_getCertificates(const KSI_PublicationsFile *t, KSI_LIST(KSI_CertificateRecord) **certificates) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || certificates == NULL) {
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
	if(t == NULL || publications == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*publications = t->publications;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_PublicationsFile_getPKICertificateById(const KSI_PublicationsFile *pubFile, const KSI_OctetString *id, KSI_PKICertificate **cert) {
	KSI_ERR err;
	int res;
	size_t i;
	KSI_CertificateRecord *certRec = NULL;

	KSI_PRE(&err, pubFile != NULL) goto cleanup;
	KSI_PRE(&err, id != NULL) goto cleanup;
	KSI_PRE(&err, cert != NULL) goto cleanup;
	KSI_BEGIN(pubFile->ctx, &err);

	for (i = 0; i < KSI_CertificateRecordList_length(pubFile->certificates); i++) {
		KSI_OctetString *cId = NULL;

		res = KSI_CertificateRecordList_elementAt(pubFile->certificates, i, &certRec);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_CertificateRecord_getCertId(certRec, &cId);
		KSI_CATCH(&err, res) goto cleanup;

		if (KSI_OctetString_equals(cId, id)) {
			res = KSI_CertificateRecord_getCert(certRec, cert);
			KSI_CATCH(&err, res) goto cleanup;

			break;
		}
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(certRec);

	return KSI_RETURN(&err);
}

int KSI_PublicationsFile_getPublicationDataByTime(const KSI_PublicationsFile *trust, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec) {
	KSI_ERR err;
	int res;
	size_t i;
	KSI_PublicationRecord *result = NULL;

	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_PRE(&err, pubTime != NULL) goto cleanup;
	KSI_PRE(&err, pubRec != NULL) goto cleanup;
	KSI_BEGIN(trust->ctx, &err);

	for (i = 0; i < KSI_PublicationRecordList_length(trust->publications); i++) {
		KSI_PublicationRecord *pr = NULL;
		KSI_PublicationData *pd = NULL;
		KSI_Integer *tm = NULL;

		res = KSI_PublicationRecordList_elementAt(trust->publications, i, &pr);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_PublicationRecord_getPublishedData(pr, &pd);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_PublicationData_getTime(pd, &tm);
		KSI_CATCH(&err, res) goto cleanup;

		if (KSI_Integer_equals(pubTime, tm)) {
			result = pr;
			break;
		}

		KSI_nofree(tm);
		KSI_nofree(pd);
	}

	*pubRec = result;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(result);

	return KSI_RETURN(&err);
}

int KSI_PublicationsFile_getPublicationDataByPublicationString(const KSI_PublicationsFile *pubFile, const char *pubString, KSI_PublicationRecord **pubRec) {
	KSI_ERR err;
	int res;
	KSI_PublicationData *findPubData = NULL;
	KSI_DataHash *findImprint = NULL;
	KSI_Integer *findTime = NULL;

	KSI_PublicationRecord *tmpPubRec = NULL;
	KSI_PublicationData *tmpPubData = NULL;
	KSI_DataHash *tmpImprint = NULL;

	KSI_PRE(&err, pubFile != NULL) goto cleanup;
	KSI_PRE(&err, pubString != NULL) goto cleanup;
	KSI_PRE(&err, pubRec != NULL) goto cleanup;
	KSI_BEGIN(pubFile->ctx, &err);

	/* Decode the publication string. */
	res = KSI_PublicationData_fromBase32(pubFile->ctx, pubString, &findPubData);
	KSI_CATCH(&err, res) goto cleanup;

	/* Extract the expected imprint. */
	res = KSI_PublicationData_getImprint(findPubData, &findImprint);
	KSI_CATCH(&err, res) goto cleanup;

	/* Extract the expected publication time. */
	res = KSI_PublicationData_getTime(findPubData, &findTime);
	KSI_CATCH(&err, res) goto cleanup;

	/* Find the publication using the publication time. */
	res = KSI_PublicationsFile_getPublicationDataByTime(pubFile, findTime, &tmpPubRec);
	KSI_CATCH(&err, res) goto cleanup;

	if (tmpPubRec != NULL) {
		/* Extract published data. */
		res = KSI_PublicationRecord_getPublishedData(tmpPubRec, &tmpPubData);
		KSI_CATCH(&err, res) goto cleanup;

		/* Extract the time. */
		res = KSI_PublicationData_getImprint(tmpPubData, &tmpImprint);
		KSI_CATCH(&err, res) goto cleanup;

		if (!KSI_DataHash_equals(findImprint, tmpImprint))  {
			KSI_FAIL(&err, KSI_INVALID_PUBLICATION, NULL);
			goto cleanup;
		}
	}

	*pubRec = tmpPubRec;

	KSI_SUCCESS(&err);

cleanup:

	KSI_PublicationData_free(findPubData);
	KSI_nofree(findImprint);
	KSI_nofree(findTime);

	KSI_nofree(tmpPubRec);
	KSI_nofree(tmpPubData);
	KSI_nofree(tmpImprint);

	return KSI_RETURN(&err);
}

/*
 */
int KSI_PublicationsFile_getNearestPublication(const KSI_PublicationsFile *trust, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec) {
	KSI_ERR err;
	int res;
	size_t i;
	KSI_PublicationRecord *result = NULL;
	KSI_Integer *result_tm = NULL;

	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_PRE(&err, pubTime != NULL) goto cleanup;
	KSI_PRE(&err, pubRec != NULL) goto cleanup;
	KSI_BEGIN(trust->ctx, &err);

	for (i = 0; i < KSI_PublicationRecordList_length(trust->publications); i++) {
		KSI_PublicationRecord *pr = NULL;
		KSI_PublicationData *pd = NULL;
		KSI_Integer *tm = NULL;

		res = KSI_PublicationRecordList_elementAt(trust->publications, i, &pr);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_PublicationRecord_getPublishedData(pr, &pd);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_PublicationData_getTime(pd, &tm);
		KSI_CATCH(&err, res) goto cleanup;

		/* Check, if current publication time is after given time. */
		if (KSI_Integer_compare(pubTime, tm) < 0) {
			if (result_tm == NULL || KSI_Integer_compare(result_tm, tm) < 0) {
				result = pr;
				result_tm = tm;
			}
		}

		KSI_nofree(tm);
		KSI_nofree(pd);
	}

	*pubRec = result;

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(result);
	KSI_nofree(result_tm);

	return KSI_RETURN(&err);
}

int KSI_PublicationsFile_getLatestPublication(const KSI_PublicationsFile *trust, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec) {
	KSI_ERR err;
	int res;
	size_t i;
	KSI_PublicationRecord *result = NULL;
	KSI_Integer *result_tm = NULL;

	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_PRE(&err, pubTime != NULL) goto cleanup;
	KSI_PRE(&err, pubRec != NULL) goto cleanup;

	for (i = 0; i < KSI_PublicationRecordList_length(trust->publications); i++) {
		KSI_PublicationRecord *pr = NULL;
		KSI_PublicationData *pd = NULL;
		KSI_Integer *tm = NULL;

		res = KSI_PublicationRecordList_elementAt(trust->publications, i, &pr);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_PublicationRecord_getPublishedData(pr, &pd);
		KSI_CATCH(&err, res) goto cleanup;

		res = KSI_PublicationData_getTime(pd, &tm);
		KSI_CATCH(&err, res) goto cleanup;

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

	KSI_SUCCESS(&err);

cleanup:

	KSI_nofree(result);
	KSI_nofree(result_tm);

	return KSI_RETURN(&err);
}

int KSI_PublicationsFile_findPublication(const KSI_PublicationsFile *trust, KSI_PublicationRecord *inRec, KSI_PublicationRecord **outRec) {
	KSI_ERR err;
	int res;
	size_t i;

	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_PRE(&err, inRec != NULL) goto cleanup;
	KSI_PRE(&err, outRec != NULL) goto cleanup;
	KSI_BEGIN(trust->ctx, &err);

	for (i = 0; i < KSI_PublicationRecordList_length(trust->publications); i++) {
		KSI_PublicationRecord *pr = NULL;

		res = KSI_PublicationRecordList_elementAt(trust->publications, i, &pr);
		KSI_CATCH(&err, res) goto cleanup;

		if (KSI_DataHash_equals(pr->publishedData->imprint, inRec->publishedData->imprint) && KSI_Integer_equals(pr->publishedData->time, inRec->publishedData->time) ) {
			*outRec = pr;
			break;
		}

		KSI_nofree(pr);
	}

	KSI_SUCCESS(&err);

cleanup:

	return KSI_RETURN(&err);
}

int KSI_PublicationsFile_getSignature(const KSI_PublicationsFile *t, KSI_PKISignature **signature) {
	int res = KSI_UNKNOWN_ERROR;
	if(t == NULL || signature == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}
	*signature = t->signature;
	res = KSI_OK;
cleanup:
	 return res;
}

int KSI_PublicationData_fromBase32(KSI_CTX *ctx, const char *publication, KSI_PublicationData **published_data) {
	KSI_ERR err;
	int res = KSI_UNKNOWN_ERROR;
	unsigned char *binary_publication = NULL;
	size_t binary_publication_length;
	KSI_PublicationData *tmp_published_data = NULL;
	unsigned i;
	unsigned long tmp_ulong;
	KSI_uint64_t tmp_uint64;
	int hash_alg;
	unsigned int hash_size;
	KSI_DataHash *pubHash = NULL;
	KSI_Integer *pubTime = NULL;

	KSI_PRE(&err, publication != NULL) goto cleanup;
	KSI_PRE(&err, published_data != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_base32Decode(publication, &binary_publication, &binary_publication_length);
	KSI_CATCH(&err, res) goto cleanup;

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
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_PublicationData_new(ctx, &tmp_published_data);
	KSI_CATCH(&err, res) goto cleanup;

	tmp_uint64 = 0;
	for (i = 0; i < 8; ++i) {
		tmp_uint64 <<= 8;
		tmp_uint64 |= binary_publication[i];
	}

	res = KSI_Integer_new(ctx, tmp_uint64, &pubTime);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PublicationData_setTime(tmp_published_data, pubTime);
	KSI_CATCH(&err, res) goto cleanup;
	pubTime = NULL;


	hash_alg = binary_publication[8];
	if (!KSI_isHashAlgorithmSupported(hash_alg)) {
		KSI_FAIL(&err, KSI_UNAVAILABLE_HASH_ALGORITHM, NULL);
		goto cleanup;
	}

	hash_size = KSI_getHashLength(hash_alg);
	if (binary_publication_length != 8 + 1 + hash_size + 4) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = KSI_DataHash_fromImprint(ctx, binary_publication + 8, hash_size + 1, &pubHash);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PublicationData_setImprint(tmp_published_data, pubHash);
	KSI_CATCH(&err, res) goto cleanup;
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
	KSI_ERR err;
	const unsigned char *imprint = NULL;
	unsigned int imprint_len = 0;
	int res;
	KSI_uint64_t publication_identifier = 0;
	unsigned char *binPub = NULL;
	size_t binPub_length;
	int i;
	unsigned long tmp_ulong;
	char *tmp = NULL;

	KSI_PRE(&err, pubData != NULL) goto cleanup;
	KSI_BEGIN(pubData->ctx, &err);

	res = KSI_DataHash_getImprint(pubData->imprint, &imprint, &imprint_len);
	KSI_CATCH(&err, res) goto cleanup;

	binPub_length =	8 + imprint_len + 4;
	binPub = KSI_calloc(binPub_length, 1);
	if (binPub == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
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
	KSI_CATCH(&err, res) goto cleanup;

	*pubStr = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(binPub);
	KSI_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_PublicationRecord_toBase32(KSI_PublicationRecord *pubRec, char **pubStr) {
	KSI_ERR err;
	int res;
	KSI_PRE(&err, pubRec != NULL) goto cleanup;
	KSI_PRE(&err, pubStr != NULL) goto cleanup;
	KSI_BEGIN(pubRec->ctx, &err);

	res = KSI_PublicationData_toBase32(pubRec->publishedData, pubStr);
	KSI_CATCH(&err, res) goto cleanup;

	KSI_SUCCESS(&err);

cleanup:

	return res;
}

/**
 * KSI_PublicationData
 */
void KSI_PublicationData_free(KSI_PublicationData *t) {
	if(t != NULL) {
		KSI_Integer_free(t->time);
		KSI_DataHash_free(t->imprint);
		KSI_free(t);
	}
}

int KSI_PublicationData_new(KSI_CTX *ctx, KSI_PublicationData **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationData *tmp = NULL;
	tmp = KSI_new(KSI_PublicationData);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->time = NULL;
	tmp->imprint = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_PublicationData_free(tmp);
	return res;
}

char *KSI_PublicationData_toString(KSI_PublicationData *t, char *buffer, unsigned buffer_len) {
	int res = KSI_UNKNOWN_ERROR;
	char *ret = NULL;
	unsigned len = 0;
	char *pubStr = NULL;
	char tmp[256];

	res = KSI_PublicationData_toBase32(t, &pubStr);
	if (res != KSI_OK) {
		KSI_LOG_error(t->ctx, "Unable to convert publication data to base 32: %s (%d)", KSI_getErrorString(res), res);
		goto cleanup;
	}

	len+= snprintf(buffer + len, buffer_len - len, "Publication string: %s\nPublication date: %s", pubStr, KSI_Integer_toDateString(t->time, tmp, sizeof(tmp)));
	len+= snprintf(buffer + len, buffer_len - len, "\nPublished hash: %s", KSI_DataHash_toString(t->imprint, tmp, sizeof(tmp)));

	ret = buffer;

cleanup:

	KSI_free(pubStr);

	return ret;
}

char *KSI_PublicationRecord_toString(KSI_PublicationRecord *t, char *buffer, unsigned buffer_len) {
	int res = KSI_UNKNOWN_ERROR;
	char *ret = NULL;
	char tmp[256];
	unsigned len = 0;
	size_t i;

	len += snprintf(buffer + len, buffer_len - len, "%s", KSI_PublicationData_toString(t->publishedData, tmp, sizeof(tmp)));

	for (i = 0; i < KSI_Utf8StringList_length(t->publicationRef); i++) {
		KSI_Utf8String *ref = NULL;

		res = KSI_Utf8StringList_elementAt(t->publicationRef, i, &ref);
		if (res != KSI_OK) goto cleanup;

		len += snprintf(buffer + len, buffer_len - len, "\nRef: %s", KSI_Utf8String_cstr(ref));
	}

	ret = buffer;

cleanup:

	return ret;
}

KSI_IMPLEMENT_GETTER(KSI_PublicationData, KSI_Integer*, time, Time);
KSI_IMPLEMENT_GETTER(KSI_PublicationData, KSI_DataHash*, imprint, Imprint);

KSI_IMPLEMENT_SETTER(KSI_PublicationData, KSI_Integer*, time, Time);
KSI_IMPLEMENT_SETTER(KSI_PublicationData, KSI_DataHash*, imprint, Imprint);


/**
 * KSI_PublicationRecord
 */
void KSI_PublicationRecord_free(KSI_PublicationRecord *t) {
	if(t != NULL) {
		KSI_PublicationData_free(t->publishedData);
		KSI_Utf8StringList_freeAll(t->publicationRef);
		KSI_free(t);
	}
}

int KSI_PublicationRecord_new(KSI_CTX *ctx, KSI_PublicationRecord **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_PublicationRecord *tmp = NULL;
	tmp = KSI_new(KSI_PublicationRecord);
	if(tmp == NULL) {
		res = KSI_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->ctx = ctx;
	tmp->publishedData = NULL;
	tmp->publicationRef = NULL;
	*t = tmp;
	tmp = NULL;
	res = KSI_OK;
cleanup:
	KSI_PublicationRecord_free(tmp);
	return res;
}

int KSI_PublicationRecord_clone(const KSI_PublicationRecord *rec, KSI_PublicationRecord **clone){
	KSI_ERR err;
	KSI_TLV *tlv = NULL;
	KSI_PublicationRecord *tmp = NULL;
	KSI_Utf8String *cloneUTF8 = NULL;
	int res = KSI_UNKNOWN_ERROR;
	int i=0;
	
	KSI_PRE(&err, rec != NULL) goto cleanup;
	KSI_PRE(&err, clone != NULL) goto cleanup;

	KSI_BEGIN(rec->ctx, &err);

	res = KSI_PublicationRecord_new(rec->ctx, &tmp);
	KSI_CATCH(&err, res);
		
	/*Copy publication references*/
	res = KSI_Utf8StringList_new(tmp->ctx, &(tmp->publicationRef));
	if(res != KSI_OK && tmp->publicationRef) goto cleanup;

	for(i=0; i<KSI_Utf8StringList_length(rec->publicationRef); i++){
		KSI_Utf8String *srcUTF8 = NULL;
		res = KSI_Utf8StringList_elementAt(rec->publicationRef, i, &srcUTF8);
		KSI_CATCH(&err, res);
		res = KSI_Utf8String_clone(srcUTF8, &cloneUTF8);
		KSI_CATCH(&err, res);
		res = KSI_Utf8StringList_append(tmp->publicationRef, cloneUTF8);
		KSI_CATCH(&err, res);
		cloneUTF8 = NULL;
	}

	
	/*Copy publication data*/
	res = KSI_PublicationData_new(rec->ctx, &(tmp->publishedData));
	if(res != KSI_OK && tmp->publishedData)
	
	tmp->publishedData->ctx = rec->ctx;

	res = KSI_DataHash_clone(rec->publishedData->imprint, &(tmp->publishedData->imprint));
	KSI_CATCH(&err, res);
	
	res = KSI_Integer_clone(rec->publishedData->time, &(tmp->publishedData->time));
	KSI_CATCH(&err, res);
	
	
	*clone = tmp;
	tmp = NULL;
	
	//KSI_SUCCESS(&err);
	
cleanup:
	KSI_PublicationRecord_free(tmp);
	KSI_free(cloneUTF8);
	
	
	return KSI_RETURN(&err);
}

KSI_IMPLEMENT_GETTER(KSI_PublicationRecord, KSI_PublicationData*, publishedData, PublishedData);
KSI_IMPLEMENT_GETTER(KSI_PublicationRecord, KSI_LIST(KSI_Utf8String)*, publicationRef, PublicationRef);

KSI_IMPLEMENT_SETTER(KSI_PublicationRecord, KSI_PublicationData*, publishedData, PublishedData);
KSI_IMPLEMENT_SETTER(KSI_PublicationRecord, KSI_LIST(KSI_Utf8String)*, publicationRef, PublicationRef);
