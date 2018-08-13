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

#include "types.h"

#ifndef KSI_PUBLICATIONSFILE_H_
#define KSI_PUBLICATIONSFILE_H_

#ifdef __cplusplus
extern "C" {
#endif
	/**
	 * \addtogroup publications Publications
	 * Publication file is a trust anchor for verifying KSI Blockchain signatures. It contains a list
	 * of public-key certificates for verifying authentication records and publications for verifying
	 * calendar hash chains. Publication file has the following components that must appear in the
	 * following order:
	 * - 8-byte magic 4B 53 49 50 55 42 4C 46 (in hexadecimal), which in ASCII means the string 'KSIPUBLF'.
	 * - Header (Single) that contains the version number and the creation time of the publication file.
	 * - Public Key Certificates (Multiple) that are considered trustworthy at the time of creation of the
	 * publication file.
	 * - sPublications (Multiple) that have been created up to the file creation time. Every `publication'
	 * structure consists of `published data' and `publication reference' structures, where the `published
	 * data' structure consists of the `publication time' and `published hash' fields.
	 * - Signature (Single) of the file.
	 * @{
	 */

	typedef struct KSI_PublicationsFile_st KSI_PublicationsFile;

	/**
	 * Function to parse the raw publicationsfile.
	 * \param[in]	ctx				KSI context.
	 * \param[in]	raw				Pointer to the raw publications file.
	 * \param[in]	raw_len			Length of the raw publications file.
	 * \param[out]	pubFile			Pointer to the receiving pointer to the publications file object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_PublicationsFile_parse(KSI_CTX *ctx, const void *raw, size_t raw_len, KSI_PublicationsFile **pubFile);

	KSI_DEFINE_REF(KSI_PublicationsFile);
	/**
	 * A convenience function for loading a publications file from an actual file.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		fileName	Publications file filename.
	 * \param[out]		pubFile		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note It must be noted that access to metadata, supported by some file systems,
	 * is limited by the use of function \c fopen. Alternate Data Streams (WIndows NTFS)
	 * and Resource Forks (OS X HFS) may or may not be supported, depending on the
	 * C standard library used in the application.
	 */
	int KSI_PublicationsFile_fromFile(KSI_CTX *ctx, const char *fileName, KSI_PublicationsFile **pubFile);

	/**
	 * This function serializes the publications file object into raw data.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		pubFile		Publications file.
	 * \param[out]		raw			Pointer to the pointer to output buffer.
	 * \param[out]		raw_len		Pointer to the length of the buffer variable.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_PublicationsFile_serialize(KSI_CTX *ctx, KSI_PublicationsFile *pubFile, char **raw, size_t *raw_len);

	/**
	 * Verify PKI signature of the publications file using the PKI truststore.
	 * \param[in]		pubFile		Publications file.
	 * \param[in]		ctx			KSI context.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_PublicationsFile_verify(const KSI_PublicationsFile *pubFile, KSI_CTX *ctx);

	/**
	 * Publicationsfile header getter method.
	 * \param[in]	pubFile			Publicationsfile object.
	 * \param[out]	header			Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getHeader(const KSI_PublicationsFile *pubFile, KSI_PublicationsHeader **header);

	/**
	 * Publicationsfile certificate list getter method.
	 * \param[in]	pubFile			Publications file.
	 * \param[out]	certificates	Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getCertificates(const KSI_PublicationsFile *pubFile, KSI_LIST(KSI_CertificateRecord) **certificates);

	/**
	 * Publicationsfile publications list getter method.
	 * \param[in]	pubFile			Publications file.
	 * \param[out]	publications	Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getPublications(const KSI_PublicationsFile *pubFile, KSI_LIST(KSI_PublicationRecord) **publications);

	/**
	 * Publicationsfile signature getter method.
	 * \param[in]	pubFile			Publications file.
	 * \param[out]	signature		Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getSignature(const KSI_PublicationsFile *pubFile, KSI_PKISignature **signature);

	/**
	 * Publications file signed data length getter. It describes how many first
	 * bytes of serialized publications file are or are going to be signed with
	 * PKI signature. If publications file is changed it must be serialized to
	 * get valid result \see #KSI_PublicationsFile_serialize.
	 * \param[in]	pubFile			Publications file.
	 * \param signedDataLength
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PublicationsFile_getSignedDataLength(const KSI_PublicationsFile *pubFile, size_t *signedDataLength);

	/**
	 * Publicationsfile certificate constraints getter method.
	 * \param[in]	pubFile			Publications file.
	 * \param[out]	certConstraints	Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getCertConstraints(const KSI_PublicationsFile *pubFile, KSI_CertConstraint **certConstraints);

	/**
	 * PKI Certificate search function by certificate Id.
	 * \param[in]	pubFile			Publications file.
	 * \param[in]	id				Certificate id.
	 * \param[out]	cert			Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getPKICertificateById(const KSI_PublicationsFile *pubFile, const KSI_OctetString *id, KSI_PKICertificate **cert);

	/**
	 * Search publication by exact time. The publication is returned via output
	 * parameter \c pubRec if found, otherwise \c pubRec is evaluated to NULL.
	 * \param[in]	pubFile			Publications file.
	 * \param[in]	pubTime			Publication time.
	 * \param[out]	pubRec			Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getPublicationDataByTime(const KSI_PublicationsFile *pubFile, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);

	/**
	 * Search publication by publication string. The publication is returned via output
	 * parameter \c pubRec if found, otherwise \c pubRec is evaluated to NULL.
	 * \param[in]	pubFile			Publications file.
	 * \param[in]	pubString		Publication string.
	 * \param[out]	pubRec			Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getPublicationDataByPublicationString(const KSI_PublicationsFile *pubFile, const char *pubString, KSI_PublicationRecord **pubRec);

	/**
	 * Search nearest publication by time. The next available publication (published
	 * after the given time \c pubTime) is returned via the output parameter \c pubRec
	 * if found, otherwise \c pubRec is evaluated to NULL.
	 * \param[in]	pubFile			Publications file.
	 * \param[in]	pubTime			Publication time.
	 * \param[out]	pubRec			Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_PublicationsFile_getNearestPublication(const KSI_PublicationsFile *pubFile, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);

	/**
	 * Search latest publication by time. The last available publication (published
	 * after the given time \c pubTime) is returned via the output parameter \c pubRec
	 * if found, otherwise \c pubRec is evaluated to NULL.
	 * \param[in]	pubFile			Publications file.
	 * \param[in]	pubTime			Publication time. If this is \c NULL, latest publication in the file is returned.
	 * \param[out]	pubRec			Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getLatestPublication(const KSI_PublicationsFile *pubFile, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);

	/**
	 * Publicationsfile header setter method.
	 * \param[in]	pubFile			Publications file.
	 * \param[in]	header	Pointer to the list of certificates.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PublicationsFile_setHeader(KSI_PublicationsFile *pubFile, KSI_PublicationsHeader *header);

	/**
	 * Publicationsfile certificate list setter method.
	 * \param[in]	pubFile			Publications file.
	 * \param[in]	certificates	Pointer to the list of certificates.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PublicationsFile_setCertificates(KSI_PublicationsFile *pubFile, KSI_LIST(KSI_CertificateRecord) *certificates);

	/**
	 * Publicationsfile publications list setter method.
	 * \param[in]	pubFile			Publications file.
	 * \param[in]	publications	Pointer to the list of publications.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PublicationsFile_setPublications(KSI_PublicationsFile *pubFile, KSI_LIST(KSI_PublicationRecord) *publications);

	/**
	 * Publicationsfile signature setter method.
	 * \param[in]	pubFile			Publications file.
	 * \param[in]	signature		Pointer to KSI signature object.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PublicationsFile_setSignature(KSI_PublicationsFile *pubFile, KSI_PKISignature *signature);

	/**
	 * This function creates an empty publications file.
	 * \param[in]	ctx		KSI context.
	 * \param[out]	pubFile	Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_PublicationsFile_new(KSI_CTX *ctx, KSI_PublicationsFile **pubFile);

	/**
	 * Function for freeing publicationsfile object.
	 * \param[in]	pubFile		Publicationsfile to be freed.
	 */
	void KSI_PublicationsFile_free(KSI_PublicationsFile *pubFile);

	int KSI_PublicationsFile_findPublicationByTime(const KSI_PublicationsFile *trust, const KSI_Integer *time, KSI_PublicationRecord **outRec);

	int KSI_PublicationsFile_findPublication(const KSI_PublicationsFile *trust, const KSI_PublicationRecord *inRec, KSI_PublicationRecord **outRec);

	/**
	 * Specifies file-specific constraints for verifying the publications file PKI certificate.
	 * The file-specific constraints, if set, override the default constraints in the KSI context.
	 * The input consists of an array of OID and expected value pairs terminated by a pair of two NULLs. Except
	 * in the last terminating NULL pair, the expected value may not be NULL - this will make the function
	 * return #KSI_INVALID_ARGUMENT.
	 * File-specific constraints can be cleared with a NULL in place of \c arr.
	 * \param[in]	pubFile		Publications file for which to set the constraints.
	 * \param[in]	arr			Array of OID and value pairs, terminated by a pair of NULLs.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The function does not take ownership of the input array and makes a copy of it, thus the
	 * caller is responsible for freeing the memory which can be done right after a successful call
	 * to this function.
	 * \code{.c}
	 * KSI_CertConstraint arr[] = {
	 * 		{ KSI_CERT_EMAIL, "publications@guardtime.com"},
	 * 		{ NULL, NULL }
	 * };
	 * res = KSI_PublicationsFile_setCertConstraints(ctx->publicationsFile, arr);
	 * \endcode
	 */
	int KSI_PublicationsFile_setCertConstraints(KSI_PublicationsFile *pubFile, const KSI_CertConstraint *arr);

	/**
	 * Converts the base-32 encoded publicationstring into #KSI_PublicationData object.
	 * \param[in]		ctx				KSI context.
	 * \param[in]		publication		Pointer to base-32 encoded publications string.
	 * \param[out]		published_data	Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The output memory has to be freed by the caller using #KSI_PublicationData_free.
	 */
	int KSI_PublicationData_fromBase32(KSI_CTX *ctx, const char *publication, KSI_PublicationData **published_data);

	/**
	 * Function to concert the published data into a base-32 encoded null-terminated string.
	 * \param[in]		published_data		Pointer to the published data object.
	 * \param[out]		publication			Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \note The output memory has to be freed by the caller using #KSI_free.
	 */
	int KSI_PublicationData_toBase32(const KSI_PublicationData *published_data, char **publication);

	/**
	 * KSI_PublicationData
	 */
	void KSI_PublicationData_free(KSI_PublicationData *t);
	int KSI_PublicationData_new(KSI_CTX *ctx, KSI_PublicationData **t);
	int KSI_PublicationData_getBaseTlv(const KSI_PublicationData *o, KSI_TLV** baseTlv);
	int KSI_PublicationData_getTime(const KSI_PublicationData *t, KSI_Integer **time);
	int KSI_PublicationData_getImprint(const KSI_PublicationData *t, KSI_DataHash **imprint);
	int KSI_PublicationData_setBaseTlv(KSI_PublicationData *o, KSI_TLV* baseTlv);
	int KSI_PublicationData_setTime(KSI_PublicationData *t, KSI_Integer *time);
	int KSI_PublicationData_setImprint(KSI_PublicationData *t, KSI_DataHash *imprint);
	char *KSI_PublicationData_toString(const KSI_PublicationData *t, char *buffer, size_t buffer_len);
	int KSI_PublicationData_fromTlv(KSI_TLV *tlv, KSI_PublicationData **data);
	int KSI_PublicationData_toTlv (KSI_CTX *ctx, const KSI_PublicationData *data, unsigned tag, int isNonCritical, int isForward, KSI_TLV **tlv);
	KSI_DEFINE_REF(KSI_PublicationData);

	/**
	 * KSI_PublicationRecord
	 */
	void KSI_PublicationRecord_free(KSI_PublicationRecord *t);
	int KSI_PublicationRecord_new(KSI_CTX *ctx, KSI_PublicationRecord **t);
	int KSI_PublicationRecord_getPublishedData(const KSI_PublicationRecord *t, KSI_PublicationData **publishedData);
	int KSI_PublicationRecord_getPublicationRefList(const KSI_PublicationRecord *t, KSI_LIST(KSI_Utf8String) **publicationRef);
	int KSI_PublicationRecord_getRepositoryUriList(const KSI_PublicationRecord *t, KSI_LIST(KSI_Utf8String) **repUriList);
	int KSI_PublicationRecord_setPublishedData(KSI_PublicationRecord *t, KSI_PublicationData *publishedData);
	int KSI_PublicationRecord_setPublicationRefList(KSI_PublicationRecord *t, KSI_LIST(KSI_Utf8String) *publicationRef);
	int KSI_PublicationRecord_setRepositoryUriList(KSI_PublicationRecord *t, KSI_LIST(KSI_Utf8String) *repUriList);
	char *KSI_PublicationRecord_toString(const KSI_PublicationRecord *t, char *buffer, size_t buffer_len);
	int KSI_PublicationRecord_clone(const KSI_PublicationRecord *rec, KSI_PublicationRecord **clone);
	KSI_DEFINE_REF(KSI_PublicationRecord);
	KSI_DEFINE_WRITE_BYTES(KSI_PublicationRecord);
	/**
	 * @}
	 */

#ifdef __cplusplus
}
#endif

#endif /* KSI_PUBLICATIONSFILE_H_ */
