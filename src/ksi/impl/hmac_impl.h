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

#ifndef HMAC_IMPL_H_
#define HMAC_IMPL_H_

#include "../hash.h"

#ifdef __cplusplus
extern "C" {
#endif

	/**
	* The maximum block size of an algorithm.
	*/
	#define MAX_BUF_LEN 128

	struct KSI_HmacHasher_st {
		/** KSI context. */
		KSI_CTX *ctx;

		/** Data hasher. */
		KSI_DataHasher *dataHasher;

		/** Inner buffer for XOR-ed key, padded with zeros. */
		unsigned char ipadXORkey[MAX_BUF_LEN];

		/** Outer buffer for XOR-ed key, padded with zeros. */
		unsigned char opadXORkey[MAX_BUF_LEN];

		/** Block size of algorithm. */
		unsigned blockSize;
	};

#ifdef __cplusplus
}
#endif

#endif /* HMAC_IMPL_H_ */
