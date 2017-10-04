/*
 * Copyright 2013-2017 Guardtime, Inc.
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

#ifndef TEST_MOCK_ASYNC_H_
#define TEST_MOCK_ASYNC_H_

#include <ksi/ksi.h>

/**
 * Mock for async service endpoint setter. The input array \c paths files should be in binary tlv format.
 * Only one file is read per #KSI_AsyncService_run invocation. Each file can contain multiple PDU's.
 * \param[in]		service		Async service instance.
 * \param[in]		paths		Array on test resource file paths.
 * \param[in]		nofPaths	Number of paths in the array \c paths.
 * \param[in]		loginId		User name.
 * \param[in]		key			HMAC shared secret.
 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
 */
int KSITest_MockAsyncService_setEndpoint(KSI_AsyncService *service, const char **paths, size_t nofPaths, const char *loginId, const char *key);

#endif /* TEST_MOCK_ASYNC_H_ */
