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

	struct KSI_CTX_st {

		/******************
		 *  ERROR HANDLING.
		 ******************/

		/** Array of errors. */
		KSI_ERR *errors;

		/** Length of error array. */
		unsigned int errors_size;

		/** Count of errors (usually #error_end - #error_start + 1, unless error count > #errors_size. */
		size_t errors_count;

		/** Logger callback function. */
		KSI_LoggerCallback loggerCB;

		/** Logger log level. */
		int logLevel;

		/** Logger context. */
		void *loggerCtx;

		/************
		 * TRANSPORT.
		 ************/
	
		/** Flag indicating if the user has provided a custom network provider. */
		int isCustomNetProvider;
	
		/** Network provider. */
		KSI_NetworkClient *netProvider;

		/** PKI trust provider. */
		KSI_PKITruststore *pkiTruststore;

		/** Pointer to an instance of a publications file. */
		KSI_PublicationsFile *publicationsFile;

		/** This field is kept only for compatibility - will be removed in the future. */
		char *publicationCertEmail_DEPRECATED;

		/* List of cleanup functions to be called when the #KSI_CTX_free is called. */
		KSI_List *cleanupFnList;

		/** User defined function to be called on the request pdu header before sending it. */
		KSI_RequestHeaderCallback requestHeaderCB;

		/** PDU version to be used in serializing KSIAP messages. */
		char serializedAggregationPduVersion;

		/** PDU version determined from parsing KSIAP messages. */
		char parsedAggregationPduVersion;

		/** PDU version to be used in serializing KSIEP messages. */
		char serializedExtendingPduVersion;

		/** PDU version determined from parsing KSIEP messages. */
		char parsedExtendingPduVersion;

		/** Counter for the requests sent by this context. */
		KSI_uint64_t requestCounter;

		/** A NULL-terminated array of key-value pairs of OID and expected values for publications file certificate verification. */
		KSI_CertConstraint *certConstraints;

		/** Pointer to function for freeing the certificate constraints array. */
		void (*freeCertConstraintsArray)(KSI_CertConstraint *);

	};

#ifdef __cplusplus
}
#endif

#endif /* CTX_IMPL_H_ */
