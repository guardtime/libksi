#ifndef KSI_LOG_H_
#define KSI_LOG_H_

#ifdef __cplusplus
extern "C" {
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

		/** Fatal log level. */
		KSI_LOG_FATAL = 0x01,

		/** Error log level. */
		KSI_LOG_ERROR = 0x02,

		/** Info log level. */
		KSI_LOG_INFO = 0x03,

		/** Warn log level. */
		KSI_LOG_WARN = 0x05,

		/** Debug log level. */
		KSI_LOG_DEBUG = 0x06,

		/** Trace log level. */
		KSI_LOG_TRACE = 0x07
	};

	/**
	 * Logging for trace level. Works as \c printf, but takes the KSI context as its first parameter.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	format		Format string.
	 * \param[in]	...			Arguments.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_trace(KSI_CTX *ctx, char *format, ...);

	/**
	 * Logging for debug level. Works as \c printf, but takes the KSI context as its first parameter.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	format		Format string.
	 * \param[in]	...			Arguments.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_debug(KSI_CTX *ctx, char *format, ...);

	/**
	 * Logging for warn level. Works as \c printf, but takes the KSI context as its first parameter.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	format		Format string.
	 * \param[in]	...			Arguments.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_warn(KSI_CTX *ctx, char *format, ...);

	/**
	 * Logging for info level. Works as \c printf, but takes the KSI context as its first parameter.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	format		Format string.
	 * \param[in]	...			Arguments.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_info(KSI_CTX *ctx, char *format, ...);

	/**
	 * Logging for error level. Works as \c printf, but takes the KSI context as its first parameter.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	format		Format string.
	 * \param[in]	...			Arguments.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_error(KSI_CTX *ctx, char *format, ...);

	/**
	 * Logging for fatal level. Works as \c printf, but takes the KSI context as its first parameter.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	format		Format string.
	 * \param[in]	...			Arguments.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_fatal(KSI_CTX *ctx, char *format, ...);

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
	int KSI_LOG_logBlob(KSI_CTX *ctx, int level, const char *prefix, const unsigned char *data, unsigned data_len);

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
	int KSI_LOG_logTlv(KSI_CTX *ctx, int level, const char *prefix, const KSI_TLV *tlv);

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
	int KSI_LOG_logDataHash(KSI_CTX *ctx, int level, const char *prefix, const KSI_DataHash *hsh);

	/**
	 * Creates a new logger. If the output file name is set to \c NULL, the log is
	 * written to the standard output.
	 * \param[in]	ctx			KSI context.
	 * \param[in]	fileName	File name where to write the log.
	 * \param[in]	logLevel	Log level.
	 * \param[out]	logger		Pointer to the receiving ponter.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 * \see #KSI_Logger_free, #KSI_LOG_setLogLevel, #KSI_LOG_setLogFile.
	 */
	int KSI_Logger_new(KSI_CTX *ctx, char *fileName, int logLevel, KSI_Logger **logger);

	/**
	 * Cleanup method for the logger.
	 * \param[in]	logger		Pointer to the logger.
	 */
	void KSI_Logger_free(KSI_Logger *logger);

	/**
	 * Change the log level.
	 * \param[in]	logger		Pointer to the logger.
	 * \param[in]	level		Log level.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_setLogLevel(KSI_Logger *logger, int level);

	/**
	 * Sets the output file for the logger. If \c file is \c NULL the log
	 * is written to the standard output.
	 * \param[in]	logger		Pointer to the logger.
	 * \param[in]	file		Null-terminated file name.
	 * \return status code (#KSI_OK, when operation succeeded, otherwise an error code).
	 */
	int KSI_LOG_setLogFile(KSI_Logger *logger, const char *file);

/**
 * @}
 */
#ifdef __cplusplus
}
#endif

#endif /* KSI_LOG_H_ */
