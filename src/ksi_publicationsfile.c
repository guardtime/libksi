#include <limits.h>
#include <string.h>
#include <stdio.h>

#include "ksi_internal.h"

KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationsHeader)
KSI_IMPORT_TLV_TEMPLATE(KSI_CertificateRecord)
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord)

struct KSI_KSITrustProvider_st {
	KSI_CTX *ctx;
	unsigned char *raw;
	int raw_len;
	KSI_PublicationsHeader *header;
	KSI_LIST(KSI_CertificateRecord) *certificates;
	KSI_LIST(KSI_PublicationRecord) *publications;
	int signatureOffset;
	KSI_PKISignature *signature;
};

/**
 * KSI_KSITrustProvider
 */
static int KSI_KSITrustProvider_new(KSI_CTX *ctx, KSI_KSITrustProvider **t);
static int KSI_KSITrustProvider_setHeader(KSI_KSITrustProvider *t, KSI_PublicationsHeader *header);
static int KSI_KSITrustProvider_setCertificates(KSI_KSITrustProvider *t, KSI_LIST(KSI_CertificateRecord) *certificates);
static int KSI_KSITrustProvider_setPublications(KSI_KSITrustProvider *t, KSI_LIST(KSI_PublicationRecord) *publications);
static int KSI_KSITrustProvider_setSignature(KSI_KSITrustProvider *t, KSI_OctetString *signature);
static int KSI_KSITrustProvider_setSignatureOffset(KSI_KSITrustProvider *t, int signatureOffset);
static int KSI_KSITrustProvider_decodePKISignature(KSI_CTX *ctx, KSI_TLV *tlv, KSI_KSITrustProvider *trust, KSI_TlvTemplate *template);
static int KSI_KSITrustProvider_decodePKICertificateList(KSI_CTX *ctx, KSI_TLV *tlv, KSI_KSITrustProvider *trust, KSI_TlvTemplate *template);

KSI_DEFINE_TLV_TEMPLATE(KSI_KSITrustProvider)
	KSI_TLV_COMPOSITE(0x0701, 0, 0, KSI_KSITrustProvider_getHeader, KSI_KSITrustProvider_setHeader, KSI_PublicationsHeader)
	KSI_TLV_CALLBACK(0x0702, 0, 0, KSI_KSITrustProvider_getCertificates, KSI_KSITrustProvider_setCertificates, NULL, KSI_KSITrustProvider_decodePKICertificateList)
	KSI_TLV_COMPOSITE_LIST(0x0703, 0, 0, KSI_KSITrustProvider_getPublications, KSI_KSITrustProvider_setPublications, KSI_PublicationRecord)
	KSI_TLV_CALLBACK(0x0704, 0, 0, KSI_KSITrustProvider_getSignature, KSI_KSITrustProvider_setSignature, NULL, KSI_KSITrustProvider_decodePKISignature)
	KSI_TLV_SEEK_POS(0x0704, KSI_KSITrustProvider_setSignatureOffset)
KSI_END_TLV_TEMPLATE

struct generator_st {
	KSI_RDR *reader;
	KSI_TLV *tlv;
};

static int KSI_KSITrustProvider_decodePKICertificateList(KSI_CTX *ctx, KSI_TLV *tlv, KSI_KSITrustProvider *trust, KSI_TlvTemplate *template) {
	KSI_ERR err;
	int res;
	KSI_CertificateRecord *certRec = NULL;
	KSI_LIST(KSI_CertificateRecord) *listp = NULL;
	KSI_LIST(KSI_CertificateRecord) *list = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	/* Create an empty certificate record. */
	res = KSI_CertificateRecord_new(ctx, &certRec);
	KSI_CATCH(&err, res) goto cleanup;

	/* Extract the values. */
	res = KSI_TlvTemplate_extract(ctx, certRec, tlv, KSI_TLV_TEMPLATE(KSI_CertificateRecord), NULL);

	KSI_CATCH(&err, res) goto cleanup;

	/* Get the list. */
	res = KSI_KSITrustProvider_getCertificates(trust, &listp);
	KSI_CATCH(&err, res) goto cleanup;

	if (listp == NULL) {
		res = KSI_CertificateRecordList_new(ctx, &list);
		KSI_CATCH(&err, res) goto cleanup;

		listp = list;
	}

	/* Append the new element. */
	res = KSI_CertificateRecordList_append(listp, certRec);
	KSI_CATCH(&err, res) goto cleanup;

	certRec = NULL;

	/* If the list was just created, add it to the structure. */
	if (list != NULL) {
		res = KSI_KSITrustProvider_setCertificates(trust, listp);
		KSI_CATCH(&err, res) goto cleanup;

		list = NULL;
	}

	KSI_SUCCESS(&err);

cleanup:

	KSI_CertificateRecord_free(certRec);
	KSI_CertificateRecordList_free(list);

	return KSI_RETURN(&err);
}

static int KSI_KSITrustProvider_decodePKISignature(KSI_CTX *ctx, KSI_TLV *tlv, KSI_KSITrustProvider *trust, KSI_TlvTemplate *template) {
	KSI_ERR err;
	int res;
	KSI_PKISignature *signature = NULL;
	const unsigned char *raw = NULL;
	int len = 0;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, tlv != NULL) goto cleanup;
	KSI_PRE(&err, trust != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	if (trust->signature != NULL) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Too many signatures.");
		goto cleanup;
	}

	res = KSI_TLV_getRawValue(tlv, &raw, &len);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_PKISignature_new(ctx, raw, len, &signature);
	KSI_CATCH(&err, res) goto cleanup;

	trust->signature = signature;
	signature = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_PKISignature_free(signature);

	return KSI_RETURN(&err);
}



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

static int KSI_KSITrustProvider_setSignatureOffset(KSI_KSITrustProvider *t, int signatureOffset) {
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

static int KSI_KSITrustProvider_setHeader(KSI_KSITrustProvider *t, KSI_PublicationsHeader *header) {
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

static int KSI_KSITrustProvider_setCertificates(KSI_KSITrustProvider *t, KSI_LIST(KSI_CertificateRecord) *certificates) {
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

static int KSI_KSITrustProvider_setPublications(KSI_KSITrustProvider *t, KSI_LIST(KSI_PublicationRecord) *publications) {
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

static int KSI_KSITrustProvider_setSignature(KSI_KSITrustProvider *t, KSI_OctetString *signature) {
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

static int KSI_KSITrustProvider_new(KSI_CTX *ctx, KSI_KSITrustProvider **t) {
	int res = KSI_UNKNOWN_ERROR;
	KSI_KSITrustProvider *tmp = NULL;
	tmp = KSI_new(KSI_KSITrustProvider);
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
	KSI_KSITrustProvider_free(tmp);
	return res;
}


static int extractData(KSI_CTX *ctx, void *raw, int raw_len, KSI_KSITrustProvider **ksiTrustProvider) {
	KSI_ERR err;
	int res;
	unsigned char hdr[8];
	int hdr_len = 0;
	KSI_KSITrustProvider *tmp = NULL;
	KSI_RDR *reader = NULL;
	struct generator_st gen;
	unsigned char *der = NULL;
	int der_len = 0;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, raw != NULL) goto cleanup;
	KSI_PRE(&err, raw_len > 0) goto cleanup;
	KSI_PRE(&err, ksiTrustProvider != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_RDR_fromSharedMem(ctx, raw, raw_len, &reader);
	KSI_CATCH(&err, res) goto cleanup;

	/* Read file header. */
	res = KSI_RDR_read_ex(reader, hdr, sizeof(hdr), &hdr_len);
	KSI_CATCH(&err, res) goto cleanup;

	if (hdr_len != sizeof(hdr) || memcmp(hdr, "KSIPUBLF", hdr_len)) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, "Unrecognized header.");
		goto cleanup;
	}

	/* Header verification ok - create the store object. */
	res = KSI_KSITrustProvider_new(ctx, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	/* Initialize generator. */
	gen.reader = reader;
	gen.tlv = NULL;

	/* Read the payload of the file, and make no assumptions with the ordering. */
	res = KSI_TlvTemplate_extractGenerator(ctx, tmp, (void *)&gen, KSI_TLV_TEMPLATE(KSI_KSITrustProvider), NULL, (int (*)(void *, KSI_TLV **))generateNextTlv);
	KSI_CATCH(&err, res) goto cleanup;

	tmp->raw = raw;
	tmp->raw_len = raw_len;

	res = KSI_PKITruststore_validateSignature(ctx, raw, tmp->signatureOffset, tmp->signature);
	KSI_CATCH(&err, res) goto cleanup;

	*ksiTrustProvider = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:


	KSI_nofree(der);

	KSI_TLV_free(gen.tlv);
	KSI_KSITrustProvider_free(tmp);
	KSI_RDR_close(reader);

	return KSI_RETURN(&err);
}

int KSI_KSITrustProvider_fromFile(KSI_CTX *ctx, const char *fileName, KSI_KSITrustProvider **store) {
	KSI_ERR err;
	int res;
	KSI_RDR *reader = NULL;
	KSI_KSITrustProvider *tmp = NULL;
	unsigned char *raw = NULL;
	int raw_len = 0;
	long raw_size = 0;
	FILE *f = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, fileName != NULL) goto cleanup;
	KSI_PRE(&err, store != NULL) goto cleanup;
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

	if (raw_size > INT_MAX) {
		KSI_FAIL(&err, KSI_INVALID_FORMAT, NULL);
		goto cleanup;
	}

	res = fseek(f, 0, SEEK_SET);
	if (res != 0) {
		KSI_FAIL(&err, KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	raw = KSI_calloc(raw_size, 1);
	if (raw == NULL) {
		KSI_FAIL(&err, KSI_OUT_OF_MEMORY, NULL);
		goto cleanup;
	}

	raw_len = fread(raw, 1, raw_size, f);
	if (raw_len != raw_size) {
		KSI_FAIL(&err, KSI_IO_ERROR, NULL);
		goto cleanup;
	}

	res = extractData(ctx, raw, raw_len, &tmp);
	KSI_CATCH(&err, res) goto cleanup;
	raw = NULL;

	*store = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	if (f != NULL) fclose(f);
	KSI_free(raw);
	KSI_RDR_close(reader);
	KSI_KSITrustProvider_free(tmp);

	return KSI_RETURN(&err);
}

/**
 * KSI_KSITrustProvider
 */
void KSI_KSITrustProvider_free(KSI_KSITrustProvider *t) {
	if(t != NULL) {
		KSI_PublicationsHeader_free(t->header);
		KSI_CertificateRecordList_free(t->certificates);
		KSI_PublicationRecordList_free(t->publications);
		KSI_PKISignature_free(t->signature);
		KSI_free(t->raw);
		KSI_free(t);
	}
}

int KSI_KSITrustProvider_getHeader(const KSI_KSITrustProvider *t, KSI_PublicationsHeader **header) {
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

int KSI_KSITrustProvider_getCertificates(const KSI_KSITrustProvider *t, KSI_LIST(KSI_CertificateRecord) **certificates) {
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

int KSI_KSITrustProvider_getPublications(const KSI_KSITrustProvider *t, KSI_LIST(KSI_PublicationRecord) **publications) {
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

int KSI_KSITrustProvider_getSignature(const KSI_KSITrustProvider *t, KSI_OctetString **signature) {
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
