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

#ifndef CTX_IMPL_H_
#define CTX_IMPL_H_

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KSI_ERR_STACK_LEN 16

	typedef void (*GlobalCleanupFn)(void);
	typedef int (*GlobalInitFn)(void);

	KSI_DEFINE_LIST(GlobalCleanupFn)

	struct KSI_CertConstraint_st {
		char *oid;
		char *val;
	};

	struct KSI_CTX_st {

		/******************
		 *  ERROR HANDLING.
		 ******************/

		/* Array of errors. */
		KSI_ERR *errors;

		/* Length of error array. */
		unsigned int errors_size;

		/* Count of errors (usually #error_end - #error_start + 1, unless error count > #errors_size. */
		size_t errors_count;

		KSI_LoggerCallback loggerCB;
		int logLevel;
		void *loggerCtx;

		/************
		 * TRANSPORT.
		 ************/
	
		int isCustomNetProvider;
	
		KSI_NetworkClient *netProvider;

		KSI_PKITruststore *pkiTruststore;

		KSI_PublicationsFile *publicationsFile;

		char *publicationCertEmail;

		/* List of cleanup functions to be called when the #KSI_CTX_free is called. */
		KSI_List *cleanupFnList;

		/** User defined function to be called on the request pdu header before sending it. */
		KSI_RequestHeaderCallback requestHeaderCB;

		/** Counter for the requests sent by this context. */
		KSI_uint64_t requestCounter;

		/** A list of key-value pairs of OID and expected values for publications file certificate verification. */
		KSI_List *certConstraints;
	};

#ifdef __cplusplus
}
#endif

#endif /* CTX_IMPL_H_ */
