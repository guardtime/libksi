#include <string.h>

#include "ksi_internal.h"

KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationsHeader)
KSI_IMPORT_TLV_TEMPLATE(KSI_CertificateRecord)
KSI_IMPORT_TLV_TEMPLATE(KSI_PublicationRecord)

struct KSI_KSITrustProvider_st {
	KSI_CTX *ctx;
	KSI_PublicationsHeader *header;
	KSI_LIST(KSI_CertificateRecord) *certificates;
	KSI_LIST(KSI_PublicationRecord) *publications;
	KSI_OctetString *signature;
};

/**
 * KSI_KSITrustProvider
 */
static int KSI_KSITrustProvider_new(KSI_CTX *ctx, KSI_KSITrustProvider **t);
static int KSI_KSITrustProvider_setHeader(KSI_KSITrustProvider *t, KSI_PublicationsHeader *header);
static int KSI_KSITrustProvider_setCertificates(KSI_KSITrustProvider *t, KSI_LIST(KSI_CertificateRecord) *certificates);
static int KSI_KSITrustProvider_setPublications(KSI_KSITrustProvider *t, KSI_LIST(KSI_PublicationRecord) *publications);
static int KSI_KSITrustProvider_setSignature(KSI_KSITrustProvider *t, KSI_OctetString *signature);

KSI_DEFINE_TLV_TEMPLATE(KSI_KSITrustProvider)
	KSI_TLV_COMPOSITE(0x0701, 0, 0, KSI_KSITrustProvider_getHeader, KSI_KSITrustProvider_setHeader, KSI_PublicationsHeader)
	KSI_TLV_COMPOSITE_LIST(0x0702, 0, 0, KSI_KSITrustProvider_getCertificates, KSI_KSITrustProvider_setCertificates, KSI_CertificateRecord)
	KSI_TLV_COMPOSITE_LIST(0x0703, 0, 0, KSI_KSITrustProvider_getPublications, KSI_KSITrustProvider_setPublications, KSI_PublicationRecord)
	KSI_TLV_OCTET_STRING(0x04, 0, 0, KSI_KSITrustProvider_getSignature, KSI_KSITrustProvider_setSignature)
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


int KSI_KSITrustProvider_fromReader(KSI_RDR *reader, KSI_KSITrustProvider **store) {
	KSI_ERR err;
	KSI_CTX *ctx = NULL;
	int res;
	unsigned char hdr[8];
	int hdr_len = 0;
	KSI_KSITrustProvider *tmp = NULL;
	struct generator_st gen;

	KSI_PRE(&err, reader != NULL) goto cleanup;
	KSI_PRE(&err, store != NULL) goto cleanup;
	ctx = KSI_RDR_getCtx(reader);
	KSI_BEGIN(ctx, &err);

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
	KSI_CATCH(&err, res);

	*store = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

	KSI_TLV_free(gen.tlv);
	KSI_KSITrustProvider_free(tmp);

	return KSI_RETURN(&err);
}

int KSI_KSITrustProvider_fromFile(KSI_CTX *ctx, const char *fileName, KSI_KSITrustProvider **store) {
	KSI_ERR err;
	int res;
	KSI_RDR *reader = NULL;
	KSI_KSITrustProvider *tmp = NULL;

	KSI_PRE(&err, ctx != NULL) goto cleanup;
	KSI_PRE(&err, fileName != NULL) goto cleanup;
	KSI_PRE(&err, store != NULL) goto cleanup;
	KSI_BEGIN(ctx, &err);

	res = KSI_RDR_fromFile(ctx, fileName, "rb", &reader);
	KSI_CATCH(&err, res) goto cleanup;

	res = KSI_KSITrustProvider_fromReader(reader, &tmp);
	KSI_CATCH(&err, res) goto cleanup;

	*store = tmp;
	tmp = NULL;

	KSI_SUCCESS(&err);

cleanup:

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
		KSI_OctetString_free(t->signature);
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
