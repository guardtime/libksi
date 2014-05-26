#include "module/ksi_ksitrustprovider.h"

#ifndef KSI_PUBLICATIONSFILE_H_
#define KSI_PUBLICATIONSFILE_H_

#ifdef __cplusplus
extern "C" {
#endif
	/**
	 * A convenience function for loading a publications file from an actual file.
	 * \param[in]		ctx			KSI context.
	 * \param[in]		fileName	Publications file filename.
	 * \param[out]		pubFile		Pointer to the receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 */
	int KSI_PublicationsFile_fromFile(KSI_CTX *ctx, const char *fileName, KSI_PublicationsFile **pubFile);

	/**
	 * Publicationsfile header getter method.
	 * \param[in]	pubFile			Publicationsfile object.
	 * \param[out]	header			Pointer to receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getHeader(const KSI_PublicationsFile *pubFile, KSI_PublicationsHeader **header);

	/**
	 * Publicationsfile certificate list getter method.
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[out]	certificates	Pointer to receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getCertificates(const KSI_PublicationsFile *pubFile, KSI_LIST(KSI_CertificateRecord) **certificates);

	/**
	 * Publicationsfile publications list getter method.
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[out]	publications	Pointer to receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getPublications(const KSI_PublicationsFile *pubFile, KSI_LIST(KSI_PublicationRecord) **publications);

	/**
	 * Publicationsfile signature getter method.
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[out]	signature		Pointer to receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getSignature(const KSI_PublicationsFile *pubFile, KSI_PKISignature **signature);

	/**
	 * PKI Certificate search function by certificate Id.
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[out]	cert			Pointer to receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getPKICertificateById(const KSI_PublicationsFile *pubFile, const KSI_OctetString *id, KSI_PKICertificate **cert);

	/**
	 * Search publication by exact time. The publication is returned via output
	 * parameter #pubRec if found, otherwise #pubRec is evaluated to NULL.
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[in]	pubTime			Publication time.
	 * \param[out]	pubRec			Pointer to receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getPublicationDataByTime(const KSI_PublicationsFile *pubFile, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);

	/**
	 * Search nearest publication by time. The next available publication (published
	 * after the given time #pubTime) is returned via the output parameter #pubRec
	 * if found, otherwise #pubRec is evaluated to NULL.
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[in]	pubTime			Publication time.
	 * \param[out]	pubRec			Pointer to receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getNearestPublication(const KSI_PublicationsFile *pubFile, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);

	/**
	 * Search nearest publication by time. The next available publication (published
	 * after the given time #pubTime) is returned via the output parameter #pubRec
	 * if found, otherwise #pubRec is evaluated to NULL.
	 * \param[in]	pubFile			PublicationsFille.
	 * \param[in]	pubTime			Publication time.
	 * \param[out]	pubRec			Pointer to receiving pointer.
	 *
	 * \return status code (\c KSI_OK, when operation succeeded, otherwise an
	 * error code).
	 * \note The output object may not be freed by the user.
	 */
	int KSI_PublicationsFile_getLatestPublication(const KSI_PublicationsFile *pubFile, const KSI_Integer *pubTime, KSI_PublicationRecord **pubRec);

	/**
	 * Function for freeing publicationsfile object.
	 * \param[in]	pubFile		Publicationsfile to be freed.
	 */
	void KSI_PublicationsFile_free(KSI_PublicationsFile *t);

#ifdef __cplusplus
}
#endif

#endif /* KSI_PUBLICATIONSFILE_H_ */
