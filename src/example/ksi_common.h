/*
 * Copyright 2013-2016 Guardtime, Inc.
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

#ifndef KSI_COMMON_H
#define KSI_COMMON_H

#include <ksi/policy.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opens a log file for logging.
 * User is responsible for closing the logfile after use.
 * \param[in]		ksi			KSI context.
 * \param[in]		fileName 	Name of the logfile.
 *
 * \param[out]		logFile		Pointer that will receive the logfile pointer
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int OpenLogging(KSI_CTX *ksi, char *fileName, FILE **logFile);

/**
 * Calculates the hash of the document using the same algorithm as found in the signature.
 * User is responsible for freeing the hash object after use.
 * \param[in]		fileName	Name of the document.
 * \param[in]		sig			Signature from where to extract the algorithm ID.
 *
 * \param[out]		hsh			Pointer that will receive the hash pointer
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int GetDocumentHash(char *fileName, KSI_Signature *sig, KSI_DataHash **hsh);

/**
 * Prints detailed information about the verification result.
 * On each separate line a rule name with corresponding result is printed.
 * On the last line the final policy result is printed.
 * \param[in]		result		Result of the verification.
 *
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int PrintVerificationInfo(KSI_PolicyVerificationResult *result);

#ifdef __cplusplus
}
#endif

#endif // KSI_COMMON_H
