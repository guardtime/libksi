/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
 */

#ifndef VERIFICATION_IMPL_H_
#define VERIFICATION_IMPL_H_

#include "ksi.h"
#include "verification.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_VerificationStepResult_st {
		KSI_VerificationStep step;
		int succeeded;
		char description[0xff];
	};

	struct KSI_VerificationResult_st {
		KSI_CTX *ctx;

		/** Bitmap of performed steps (#KSI_VerificationStep_en values). */
		unsigned stepsPerformed;

		/** Bitmap of failed steps (#KSI_VerificationStep_en values). */
		unsigned stepsFailed;

		/** List of performed verification steps and the outcomes. */
		KSI_VerificationStepResult steps[32];
		unsigned steps_len;

		/** Indicates if the document hash should be verified */
		bool verifyDocumentHash;

		/** Document hash to be verified. */
		const KSI_DataHash *documentHash;

		/** Indicates if the publication string should be used. */
		bool useUserPublication;

		/** Publicationsfile to be used. */
		KSI_PublicationsFile *publicationsFile;

		/** Publication string to be used. */
		KSI_PublicationData *userPublication;

		KSI_DataHash *aggregationHash;
	};

#ifdef __cplusplus
}
#endif

#endif /* VERIFICATION_IMPL_H_ */
