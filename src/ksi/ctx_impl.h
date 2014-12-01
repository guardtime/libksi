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

		/** The logger mechanism is deprecated. */
		KSI_Logger *logger;

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

		KSI_List *cleanupFnList;

		KSI_RequestHeaderCallback requestHeaderCB;
	};

#ifdef __cplusplus
}
#endif

#endif /* CTX_IMPL_H_ */
