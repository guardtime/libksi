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

#ifndef VERIFICATION_H_
#define VERIFICATION_H_

#include "ksi.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * \addtogroup signature
	 * @{
	 */

	/**
	 * This type keeps track of all the performed verification steps (#KSI_VerificationStep_en) and
	 * their results.
	 */
	typedef struct KSI_VerificationResult_st KSI_VerificationResult;

	/**
	 * This type holds a concrete result for a single verification step (#KSI_VerificationStep_en).
	 */
	typedef struct KSI_VerificationStepResult_st KSI_VerificationStepResult;

	/**
	 * Enumeration of all KSI signature (#KSI_Signature) available verification steps.
	 */
	typedef enum KSI_VerificationStep_en {
	    /**
	     * Check if signature input hash and document hash match.
	     */
	    KSI_VERIFY_DOCUMENT = 0x01,

	    /**
	     * Verify the aggregation chain internally.
	     */
	    KSI_VERIFY_AGGRCHAIN_INTERNALLY = 0x02,

	    /**
	     * Check if calendar chain matches aggregation chain
	     */
	    KSI_VERIFY_AGGRCHAIN_WITH_CALENDAR_CHAIN = 0x04,

	    /**
	     * Verify calendar chain internally.
	     */
	    KSI_VERIFY_CALCHAIN_INTERNALLY = 0x08,

	    /**
	     * Verify calendar chain using calendar auth record.
	     */
	    KSI_VERIFY_CALCHAIN_WITH_CALAUTHREC = 0x10,

	    /**
	     * Verify calendar chain with publication.
	     */
	    KSI_VERIFY_CALCHAIN_WITH_PUBLICATION = 0x20,

	    /**
	     * Verify signature against online calendar
	     */
	    KSI_VERIFY_CALCHAIN_ONLINE = 0x40,

	    /**
	     * OK!verify that calendar authentication record signature is correct
	     */
	    KSI_VERIFY_CALAUTHREC_WITH_SIGNATURE = 0x80,

	    /**
	     * check publication file signature
	     */
	    KSI_VERIFY_PUBFILE_SIGNATURE = 0x100,

	    /**
	     * Check if publication record is stored in KSI Trust provider
	     */
	    KSI_VERIFY_PUBLICATION_WITH_PUBFILE = 0x200,
	    
		/**
	     * Check if publication record equals to publication string
	     */
	    KSI_VERIFY_PUBLICATION_WITH_PUBSTRING = 0x400,

	} KSI_VerificationStep;

	/**
	 * Initializes the #KSI_VerificationResult object.
	 * \param[in]	info		Pointer to #KSI_VerificationResult.
	 * \param[in]	ctx			KSI context.
	 *
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationResult_init(KSI_VerificationResult *info, KSI_CTX *ctx);

	/**
	 * Reset the value of #KSI_VerificationResult.
	 * \param[in]	info		Pointer to #KSI_VerificationResult.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_VerificationResult_reset(KSI_VerificationResult *info);

	/**
	 * @}
	 */
#ifdef __cplusplus
}
#endif

#endif /* VERIFICATION_INFO_H_ */
