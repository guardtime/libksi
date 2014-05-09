#ifndef KSI_SIGNATURE_H_
#define KSI_SIGNATURE_H_

#include "ksi_common.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * TODO!
	 */
	void KSI_Signature_free(KSI_Signature *signature);

	/**
	 * TODO!
	 */
	int KSI_Signature_clone(const KSI_Signature *sig, KSI_Signature **clone);

	/**
	 * TODO!
	 */
	int KSI_Signature_parse(KSI_CTX *ctx, unsigned char *raw, int raw_len, KSI_Signature **sig);

	/**
	 * TODO!
	 */
	int KSI_Signature_fromFile(KSI_CTX *ctx, const char *fileName, KSI_Signature **sig);

	/**
	 * TODO!
	 */
	int KSI_Signature_serialize(KSI_Signature *sig, unsigned char **raw, int *raw_len);

	/**
	 * TODO!
	 */
	int KSI_Signature_sign(const KSI_DataHash *hsh, KSI_Signature **signature);

	/**
	 * TODO!
	 */
	int KSI_Signature_extend(KSI_Signature *signature, KSI_Integer *extendTo, KSI_Signature **extended);

	/**
	 * TODO!
	 */
	int KSI_parseAggregationResponse(KSI_CTX *ctx, const unsigned char *response, int response_len, KSI_Signature **signature);

	/**
	 * TODO!
	 */
	int KSI_Signature_replaceCalendarChain(KSI_Signature *sig, KSI_CalendarHashChain *calendarHashChain);

	int KSI_Signature_validate(KSI_Signature *sig);
	void KSI_Signature_free(KSI_Signature *sig);
	int KSI_Signature_getDataHash(KSI_Signature *sig, const KSI_DataHash ** hsh);
	int KSI_Signature_getSigningTime(const KSI_Signature *sig, KSI_Integer **signTime);
	int KSI_Signature_getSignerIdentity(KSI_Signature *sig, char **identity);
	/** TODO! For now these are just mock declarations
	int KSI_Signature_getPublishedData(KSI_Signature *sig, char **pub_data);
	int KSI_Signature_getPublicationReference(KSI_Signature *sig, char **pub_ref);
	int KSI_Signature_getPublicationSignature(KSI_Signature *sig, char **pub_sig);
	*/


	KSI_DEFINE_GET_CTX(KSI_Signature);


#ifdef __cplusplus
}
#endif

#endif /* KSI_SIGNATURE_H_ */
