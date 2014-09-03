#ifndef VERIFICATION_H_
#define VERIFICATION_H_

#include "ksi.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * TODO!
	 */
	typedef struct KSI_VerificationInfo_st KSI_VerificationResult;
	typedef struct KSI_VerificationStepResult_st KSI_VerificationStepResult;

	typedef enum KSI_VerificationStep_en {
	    /**
	     * OK! verify aggregation chain
	     */
	    KSI_SIG_AGGREGATION_CHAIN = 0x01,
	    /**
	     * OK!check if signature and document hashes match
	     */
	    KSI_SIG_DOCUMENT_MATCH = 0x02,
	    /**
	     * OK! check if calendar chain matches aggregation chain
	     */
	    KSI_SIG_CALENDAR_CHAIN = 0x04,
	    /**
	     * check publication file signature
	     */
	    KSI_PUB_SIGNATURE = 0x08,
	    /**
	     * OK!verify that calendar authentication record matches calendar chain
	     */
	    KSI_SIG_CAL_AUTH_REC_MATCH = 0x10,
	    /**
	     * OK!verify that calendar authentication record signature is correct
	     */
	    KSI_SIG_CAL_AUTH_REC_SIGNATURE = 0x20,
	    /**
	     * OK! check if publication record matches calendar chain
	     */
	    KSI_SIG_PUBLICATION_MATCH = 0x40,
	    /**
	     * OK! check if publication record is stored in KSI Trust provider
	     */
	    KSI_SIG_PUBLICATION_TRUSTED = 0x80,
	    /**
	     * OK! verify signature against online calendar
	     */
	    KSI_SIG_VERIFY_ONLINE = 0x100
	} KSI_VerificationStep;

	/**
	 * TODO!
	 */
	int KSI_VerificationResult_init(KSI_CTX *ctx, KSI_VerificationResult *info);

	/**
	 * TODO!
	 */
	int KSI_VerificationResult_reset(KSI_VerificationResult *info);

	/**
	 * TODO!
	 */
	int KSI_VerificationResult_addFailure(KSI_VerificationResult *info, KSI_VerificationStep step, const char *desc);

	/**
	 * TODO!
	 */
	int KSI_VerificationResult_addSuccess(KSI_VerificationResult *info, KSI_VerificationStep step, const char *desc);

	/**
	 * TODO!
	 */
	int KSI_VerificationStepResult_fail(KSI_VerificationStepResult *result, const char *description);

	/**
	 * TODO!
	 */
	int KSI_VerificationStepResult_success(KSI_VerificationStepResult *result);

	/**
	 * TODO!
	 */
	void KSI_VerificationStepResult_free(KSI_VerificationStepResult *stepResult);

	/**
	 * TODO!
	 */
	int KSI_VerificationStepResult_new(KSI_CTX *ctx, KSI_VerificationStep step, KSI_VerificationStepResult **stepResult);


#ifdef __cplusplus
}
#endif

#endif /* VERIFICATION_INFO_H_ */
