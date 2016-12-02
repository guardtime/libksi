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

#ifndef HASHCHAIN_IMPL_H_
#define HASHCHAIN_IMPL_H_

#ifdef __cplusplus
extern "C" {
#endif

struct KSI_HashChainLink_st {
	KSI_CTX *ctx;
	int isLeft;
	KSI_Integer *levelCorrection;
	KSI_OctetString *legacyId;
	KSI_MetaDataElement *metaData;
	KSI_DataHash *imprint;
};

struct KSI_CalendarHashChain_st {
	KSI_CTX *ctx;
	size_t ref;
	KSI_Integer *publicationTime;
	KSI_Integer *aggregationTime;
	KSI_DataHash *inputHash;
	KSI_LIST(KSI_HashChainLink) *hashChain;
};

struct KSI_AggregationHashChain_st {
	KSI_CTX *ctx;
	size_t ref;

	KSI_Integer *aggregationTime;
	KSI_LIST(KSI_Integer) *chainIndex;
	KSI_OctetString *inputData;
	KSI_DataHash *inputHash;
	KSI_Integer *aggrHashId;
	KSI_LIST(KSI_HashChainLink) *chain;
};

#ifdef __cplusplus
}
#endif

#endif /* HASHCHAIN_IMPL_H_ */
