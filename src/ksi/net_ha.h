/*
 * Copyright 2013-2018 Guardtime, Inc.
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

#ifndef KSI_NET_HA_H_
#define KSI_NET_HA_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup asyncNetwork Network Interface (Asynchronous)
 * @{
 */

#define KSI_HA_MAX_SUBSERVICES 3
/**
 * Creates and initalizes a concrete HA async service object to be used to interract with aggregator endpoint.
 * \param[in]		ctx				KSI context.
 * \param[out]		service			Pointer to the receiving pointer.
 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_AsyncService_setEndpoint
 * \see #KSI_AsyncService_free
 */
int KSI_SigningHighAvailabilityService_new(KSI_CTX *ctx, KSI_AsyncService **service);

/**
 * Creates and initalizes a concrete HA async service object to be used to interract with extender endpoint.
 * \param[in]		ctx				KSI context.
 * \param[out]		service			Pointer to the receiving pointer.
 * \return Status code (#KSI_OK, when operation succeeded, otherwise an error code).
 * \see #KSI_AsyncService_setEndpoint
 * \see #KSI_AsyncService_free
 */
int KSI_ExtendingHighAvailabilityService_new(KSI_CTX *ctx, KSI_AsyncService **service);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* KSI_NET_HA_H_ */
