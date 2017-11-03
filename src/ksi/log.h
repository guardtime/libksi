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

#ifndef KSI_LOG_H_
#define KSI_LOG_H_

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __GNUC__
#  define __attribute__(dummy)
#endif


	/**
	 * \addtogroup log Logging
	 * This group contains primitive functions for logging. There are 6 predefined log levels and one level
	 * for disabling logging.
	 * @{
	 */
	/**
	 * Log level.
	 */
	enum KSI_LOG_LVL_en {
		/** Logging is turned off. */
		KSI_LOG_NONE = 0x00,

		/** Error log level - unrecoverable fatal errors only - gasp of death - code cannot continue and will terminate. */
		KSI_LOG_ERROR = 0x01,

		/** Warning log level - changes in state that affects the service degradation. */
		KSI_LOG_WARN = 0x02,

		/** Notice log level - changes in state that do not necessarily cause service degradation. */
		KSI_LOG_NOTICE = 0x03,

		/** Info log level - events that have no effect on service, but can aid in performance, status and statistics monitoring. */
		KSI_LOG_INFO = 0x04,

		/** Debug log level - events generated to aid in debugging, application flow and detailed service troubleshooting. */
		KSI_LOG_DEBUG = 0x05,
	};

	/**
	 * Logging for debug level. Events generated to aid in debugging, application flow and detailed service troubleshooting.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	format		Format string.
	 * \param[in]	...			Arguments.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_debug(KSI_CTX *ctx, char *format, ...)  __attribute__((format(printf, 2, 3))) __attribute__((nonnull(1)));

	/**
	 * Logging for info level. Events that have no effect on service, but can aid in performance, status and statistics monitoring.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	format		Format string.
	 * \param[in]	...			Arguments.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_info(KSI_CTX *ctx, char *format, ...) __attribute__((format(printf, 2, 3))) __attribute__((nonnull(1)));

	/**
	 * Logging for info level. Changes in state that do not necessarily cause service degradation.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	format		Format string.
	 * \param[in]	...			Arguments.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_notice(KSI_CTX *ctx, char *format, ...) __attribute__((format(printf, 2, 3))) __attribute__((nonnull(1)));

	/**
	 * Logging for warning level. Changes in state that affects the service degradation.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	format		Format string.
	 * \param[in]	...			Arguments.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_warn(KSI_CTX *ctx, char *format, ...) __attribute__((format(printf, 2, 3))) __attribute__((nonnull(1)));

	/**
	 * Logging for error level. Unrecoverable fatal errors only - gasp of death - code cannot continue and will terinate.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	format		Format string.
	 * \param[in]	...			Arguments.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_error(KSI_CTX *ctx, char *format, ...) __attribute__((format(printf, 2, 3))) __attribute__((nonnull(1)));

	/**
	 * A helper function for logging raw data. The log message will be prefixed with \c prefix and
	 * the binary data is logged as hex.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	level		Log level.
	 * \param[in]	prefix		Prefix for the log message.
	 * \param[in]	data		Pointer to the raw data.
	 * \param[in]	data_len	Length of the data.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_logBlob(KSI_CTX *ctx, int level, const char *prefix, const unsigned char *data, size_t data_len) __attribute__((nonnull(1)));

	/**
	 * A helper function for logging plain #KSI_TLV objects. The log message will be prefixed
	 * with \c prefix and the TLV is logged as text on multiple lines (#KSI_TLV_toString)
	 * \param[in]	ctx			KSI context.
	 * \param[in]	level		Log level.
	 * \param[in]	prefix		Prefix for the log message.
	 * \param[in]	tlv			TLV to be logged.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_TLV_toString
	 */
	int KSI_LOG_logTlv(KSI_CTX *ctx, int level, const char *prefix, const KSI_TLV *tlv) __attribute__((nonnull(1)));

	/**
	 * A helper function for logging plain #KSI_TLV objects. The log message will be prefixed
	 * with \c prefix and the TLV is logged as text on multiple lines (#KSI_TLV_toString)
	 * \param[in]	ctx			KSI context.
	 * \param[in]	level		Log level.
	 * \param[in]	prefix		Prefix for the log message.
	 * \param[in]	hsh			Hash value to be logged.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_TLV_toString
	 */
	int KSI_LOG_logDataHash(KSI_CTX *ctx, int level, const char *prefix, const KSI_DataHash *hsh) __attribute__((nonnull(1)));

	/**
	 * A helper function for logging KSI context error trace.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	level		Log level.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_ERR_statusDump
	 */
	int KSI_LOG_logCtxError(KSI_CTX *ctx, int level) __attribute__((nonnull(1)));

	/**
	 * The stream logger is a simple logging call-back to be used with #KSI_CTX_setLoggerCallback.
	 * It will output the value to a \c FILE stream.
	 * \param[in]	logCtx		A stream to write the log messages.
	 * \param[in]	logLevel	Log level.
	 * \param[in]	message		Formatted log message.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_CTX_setLoggerCallback, #KSI_LoggerCallback
	 */
	int KSI_LOG_StreamLogger(void *logCtx, int logLevel, const char *message);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#ifndef __GNUC__
#  undef __attribute__
#endif

#endif /* KSI_LOG_H_ */
