#include <limits.h>
#include <string.h>
#include <stdio.h>

#include "internal.h"

KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationsHeader)
KSI_IMPORT_TLV_TEMPLATE(KSI_CertificateRecord)
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord)

struct KSI_PublicationsFile_st {
	KSI_CTX *ctx;
	unsigned char *raw;
	int raw_len;
	KSI_PublicationsHeader *header;
	KSI_LIST(KSI_CertificateRecord) *certificates;
	KSI_LIST(KSI_PublicationRecord) *publications;
	size_t signatureOffset;
	KSI_PKISignature *signature;
};

static int publicationsFile_setHeader(KSI_PublicationsFile *t, KSI_PublicationsHeader *header);
static int publicationsFile_setCertificates(KSI_PublicationsFile *t, KSI_LIST(KSI_CertificateRecord) *certificates);
static int publicationsFile_setPublications(KSI_PublicationsFile *t, KSI_LIST(KSI_PublicationRecord) *publications);
static int publicationsFile_setSignature(KSI_PublicationsFile *t, KSI_PKISignature *signature);
static int publicationsFile_setSignatureOffset(KSI_PublicationsFile *t, size_t signatureOffset);

KSI_DEFINE_TLV_TEMPLATE(KSI_PublicationsFile)
	KSI_TLV_COMPOSITE(0x0701, 0, 0, KSI_PublicationsFile_getHeader, publicationsFile_setHeader, KSI_PublicationsHeader)
	KSI_TLV_COMPOSITE_LIST(0x0702, 0, 0, KSI_PublicationsFile_getCertificates, publicationsFile_setCertificates, KSI_CertificateRecord)
	KSI_TLV_COMPOSITE_LIST(0x0703, 0, 0, KSI_PublicationsFile_getPublications, publicationsFile_setPublications, KSI_PublicationRecord)
	KSI_TLV_OBJECT(0x0704, 0, 0, KSI_PublicationsFile_getSignature, publicationsFile_setSignature, KSI_PKISignature_fromTlv, KSI_PKISignature_toTlv, KSI_PKISignature_free)
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
	struct generator_st gen;
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
	res = KSI_TlvTemplate_extractGenerator(ctx, tmp, (void *)&gen, KSI_TLV_TEMPLATE(KSI_PublicationsFile), NULL, (int (*)(void *, KSI_TLV **))generateNextTlv);
	KSI_CATCH(&err, res) goto cleanup;

	/* Copy the raw value */
	tmpRaw = KSI_calloc(raw_len, 1);
	if (tmpRaw == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}
	memcpy(tmpRaw, raw, raw_len);

	tmp->raw = tmpRaw;
	tmpRaw = NULL;

	*pubFile = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:


	KSI_nofree(der);

	KSI_free(tmpRaw);
	KSI_TLV_free(gen.tlv);
	KSI_PublicationsFile_free(tmp);
	KSI_RDR_close(reader);

	return KSI_RETURN(&err);
}

int KSI_PublicationsFile_verify(KSI_PublicationsFile *pubFile, KSI_PKITruststore *pki) {
	KSI_ERR err;
	int res;

	KSI_PRE(&err, pubFile != NULL) goto cleanup;
	KSI_PRE(&err, pki != NULL) goto cleanup;
	KSI_BEGIN(pubFile->ctx, &err);

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

	res = KSI_PKITruststore_verifySignature(pki, pubFile->raw, pubFile->signatureOffset, pubFile->signature);
	KSI_CATCH(&err, res) {
		KSI_FAIL(&err, res, "Publications file not trusted.");
		goto cleanup;
	}

	KSI_SUCCESS(&err);

cleanup:

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

int KSI_PublicationData_toBase32(const KSI_PublicationData *published_data, char **publication) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	KSI_DataHash *hsh = NULL;
	KSI_Integer *publicationTime = NULL;
	const unsigned char *imprint = NULL;
	unsigned int imprint_len = 0;
	int res;
	KSI_uint64_t publication_identifier = 0;
	unsigned char *binary_publication = NULL;
	size_t binary_publication_length;
	int i;
	unsigned long tmp_ulong;
	char *tmp_publication = NULL;

	KSI_PRE(&err, published_data != NULL) goto cleanup;
	ctx = KSI_PublicationData_getCtx((KSI_PublicationData *)published_data);

	KSI_BEGIN(ctx, &err);

	res = KSI_PublicationData_getImprint(published_data, &hsh);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_DataHash_getImprint(hsh, &imprint, &imprint_len);
	KSI_CATCH(&err, res) goto cleanup;

	binary_publication_length =	8 + imprint_len + 4;
	binary_publication = KSI_calloc(binary_publication_length, 1);
	if (binary_publication == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	res = KSI_PublicationData_getTime(published_data, &publicationTime);
	KSI_CATCH(&err, res) goto cleanup;

	if (publicationTime == NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Publication has no publication time.");
		goto cleanup;
	}

	publication_identifier = KSI_Integer_getUInt64(publicationTime);

	for (i = 7; i >= 0; --i) {
		binary_publication[i] = (unsigned char) (publication_identifier & 0xff);
		publication_identifier >>= 8;
	}

	memcpy(binary_publication + 8, imprint, imprint_len);

	tmp_ulong = KSI_crc32(binary_publication, binary_publication_length - 4, 0);
	for (i = 3; i >= 0; --i) {
		binary_publication[binary_publication_length - 4 + i] =
			(unsigned char) (tmp_ulong & 0xff);
		tmp_ulong >>= 8;
	}

	res = KSI_base32Encode(binary_publication, binary_publication_length, 6, &tmp_publication);
	KSI_CATCH(&err, res) goto cleanup;

	*publication = tmp_publication;
	tmp_publication = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_free(binary_publication);
	KSI_free(tmp_publication);

	return KSI_RETURN(&err);
}
