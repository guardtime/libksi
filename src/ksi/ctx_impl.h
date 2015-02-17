/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
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

		/* Status code of the last executed function. */
		int statusCode;

		/* Array of errors. */
		KSI_ERR *errors;

		/* Length of error array. */
		unsigned int errors_size;

		/* Count of errors (usually #error_end - #error_start + 1, unless error count > #errors_size. */
		unsigned int errors_count;

		KSI_LoggerCallback loggerCB;
		int logLevel;
		void *loggerCtx;

		/************
		 * TRANSPORT.
		 ************/

		KSI_NetworkClient *netProvider;

		KSI_PKITruststore *pkiTruststore;

		KSI_PublicationsFile *publicationsFile;

		char *publicationCertEmail;

		/* List of cleanup functions to be called when the #KSI_CTX_free is called. */
		KSI_List *cleanupFnList;

		/** Userdefined function to be called on the request pdu header befor sending it. */
		KSI_RequestHeaderCallback requestHeaderCB;

		/** Counter for the requests sent by this context. */
		KSI_uint64_t requestCounter;
	};

#ifdef __cplusplus
}
#endif

#endif /* CTX_IMPL_H_ */
