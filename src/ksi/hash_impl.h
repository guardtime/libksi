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

#ifndef HASH_IMPL_H_
#define HASH_IMPL_H_

#include "hash.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_DataHash_st {
		/** KSI context */
		KSI_CTX *ctx;

		/** Reference count for shared pointer. */
		unsigned refCount;

		/** Imprint: 1 byte for algorithm and #KSI_MAX_IMPRINT_LEN bytes for the actual digest. */
		unsigned char imprint[KSI_MAX_IMPRINT_LEN + 1]; /* For an extra '0' for meta hash. */
		/** Length of the imprint actual value. */
		unsigned int imprint_length;
	};

	struct KSI_DataHasher_st {
		/** KSI context */
		KSI_CTX *ctx;

		/** Implementation context. */
		void *hashContext;

		/** Algorithm id */
		int algorithm;

		/** This function functions similarly to #KSI_DataHasher_close except, it
		 * modifies an existing #KSI_DataHash. This function may not be publicly
		 * accessible as the #KSI_DataHash is intended to be an immutable object.
		 * \param	Instance of an opened data hasher object.
		 * \param	Instance of an existing data hash object.
		 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
		 * \note *** DO NOT USE unless for optimization reasons only and the data hash object is not a shared pointer. ***
		 */
		int (*closeExisting)(KSI_DataHasher *, KSI_DataHash *);
	};

#ifdef __cplusplus
}
#endif

#endif /* HASH_IMPL_H_ */
