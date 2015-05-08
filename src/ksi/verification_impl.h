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

		/* Initial aggregation level. */
		KSI_uint64_t docAggrLevel;

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
