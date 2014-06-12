#include "ksi_common.h"

#ifndef KSI_PUBLICATIONSFILE_H_
#define KSI_PUBLICATIONSFILE_H_

#ifdef __cplusplus
extern "C" {
#endif
	/**
	 * \addtogroup publicationsfile Publications file.
	 * Publication file is a trust anchor for verifying keyless signatures. It contains a list
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

	/**
	 * Function to parse the raw publicationsfile.
	 * \param[in]	ctx				KSI context.
	 * \param[in]	raw				Pointer to the raw publications file.
	 * \param[in]	raw_len			Length of the raw publications file.
	 * \param[out]	pubFile			Pointer to the receiving pointer to the publications file object.
	 */
	int KSI_PublicationsFile_parse(KSI_CTX *ctx, const void *raw, int raw_len, KSI_PublicationsFile **pubFile);

	/**
	 * A convenience function for loading a publications file from an actual file.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		fileName	Publications file filename.
	 * \param[out]		pubFile		Pointer to the receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PublicationsFile_fromFile(KSI_CTX *ctx, const char *fileName, KSI_PublicationsFile **pubFile);

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
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[out]	certificates	Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getCertificates(const KSI_PublicationsFile *pubFile, KSI_LIST(KSI_CertificateRecord) **certificates);

	/**
	 * Publicationsfile publications list getter method.
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[out]	publications	Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getPublications(const KSI_PublicationsFile *pubFile, KSI_LIST(KSI_PublicationRecord) **publications);

	/**
	 * Publicationsfile signature getter method.
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[out]	signature		Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getSignature(const KSI_PublicationsFile *pubFile, KSI_PKISignature **signature);

	/**
	 * PKI Certificate search function by certificate Id.
	 * \param[in]	pubFile			PublicationsFille.
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
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[in]	pubTime			Publication time.
	 * \param[out]	pubRec			Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getPublicationDataByTime(const KSI_PublicationsFile *pubFile, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);

	/**
	 * Search nearest publication by time. The next available publication (published
	 * after the given time \c pubTime) is returned via the output parameter \c pubRec
	 * if found, otherwise \c pubRec is evaluated to NULL.
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[in]	pubTime			Publication time.
	 * \param[out]	pubRec			Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getNearestPublication(const KSI_PublicationsFile *pubFile, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);

	/**
	 * Search nearest publication by time. The next available publication (published
	 * after the given time \c pubTime) is returned via the output parameter \c pubRec
	 * if found, otherwise \c pubRec is evaluated to NULL.
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[in]	pubTime			Publication time.
	 * \param[out]	pubRec			Pointer to receiving pointer.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getLatestPublication(const KSI_PublicationsFile *pubFile, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);

	/**
	 * Function for freeing publicationsfile object.
	 * \param[in]	pubFile		Publicationsfile to be freed.
	 */
	void KSI_PublicationsFile_free(KSI_PublicationsFile *pubFile);

	/**
	 * @}
	 */

#ifdef __cplusplus
}
#endif

#endif /* KSI_PUBLICATIONSFILE_H_ */
