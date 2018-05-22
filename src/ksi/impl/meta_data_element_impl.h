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


#ifndef META_DATA_ELEMENT_IMPL_H_
#define META_DATA_ELEMENT_IMPL_H_

#include "../tlv_element.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_MetaDataElement_st {
		KSI_CTX *ctx;
		size_t ref;

		/* Temporary fieds for holding getter values for further cleanup. */
		KSI_OctetString *padding;
		KSI_Utf8String *clientId;
		KSI_Utf8String *machineId;
		KSI_Integer *sequenceNr;
		KSI_Integer *reqTimeInMicros;

		KSI_TlvElement *impl;
	};

#ifdef __cplusplus
}
#endif

#endif /* META_DATA_ELEMENT_IMPL_H_ */
