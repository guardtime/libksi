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

#ifndef PUBLICATIONSFILE_IMPL_H_
#define PUBLICATIONSFILE_IMPL_H_

#ifdef __cplusplus
extern "C" {
#endif

	struct KSI_PublicationsFile_st {
		KSI_CTX *ctx;
		unsigned char *raw;
		size_t raw_len;
		KSI_PublicationsHeader *header;
		KSI_LIST(KSI_CertificateRecord) *certificates;
		KSI_LIST(KSI_PublicationRecord) *publications;
		size_t signedDataLength;
		KSI_PKISignature *signature;
	};

	struct KSI_PublicationData_st {
		KSI_CTX *ctx;
		KSI_Integer *time;
		KSI_DataHash *imprint;
		KSI_TLV *baseTlv;
	};

	struct KSI_PublicationRecord_st {
		KSI_CTX *ctx;
		size_t ref;

		KSI_PublicationData *publishedData;
		KSI_LIST(KSI_Utf8String) *publicationRef;
		KSI_LIST(KSI_Utf8String) *repositoryUriList;
	};


#ifdef __cplusplus
}
#endif

#endif /* PUBLICATIONSFILE_IMPL_H_ */
