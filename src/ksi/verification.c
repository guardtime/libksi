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

#include <string.h>

#include "internal.h"

#include "impl/verification_impl.h"

int KSI_VerificationResult_reset(KSI_VerificationResult *info) {
	int res = KSI_UNKNOWN_ERROR;

	if (info == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	info->stepsFailed = 0;
	info->stepsPerformed = 0;

	info->verifyDocumentHash = false;

	KSI_DataHash_free(info->documentHash);
	info->documentHash = NULL;
	info->docAggrLevel = 0;

	info->useUserPublication = false;
	info->userPublication = NULL;

	KSI_PublicationsFile_free(info->publicationsFile);
	info->publicationsFile = NULL;

	info->steps_len = 0;

	KSI_DataHash_free(info->aggregationHash);
	info->aggregationHash = NULL;

	res = KSI_OK;

cleanup:

	return res;
}

int KSI_VerificationResult_init(KSI_VerificationResult *info, KSI_CTX *ctx) {
	int res = KSI_UNKNOWN_ERROR;
	if (info == NULL) {
		res = KSI_INVALID_ARGUMENT;
		goto cleanup;
	}

	memset(info, 0, sizeof(KSI_VerificationResult));

	info->ctx = ctx;

	res = KSI_VerificationResult_reset(info);
	if (res != KSI_OK) goto cleanup;

	res = KSI_OK;

cleanup:

	return res;
}


