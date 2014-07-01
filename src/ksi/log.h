#ifndef KSI_LOG_H_
#define KSI_LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

enum KSI_LOG_LVL_en {
	KSI_LOG_NONE,
	KSI_LOG_FATAL,
	KSI_LOG_ERROR,
	KSI_LOG_INFO,
	KSI_LOG_WARN,
	KSI_LOG_DEBUG,
	KSI_LOG_TRACE
};

int KSI_LOG_trace(KSI_CTX *ctx, char *format, ...);
int KSI_LOG_debug(KSI_CTX *ctx, char *format, ...);
int KSI_LOG_warn(KSI_CTX *ctx, char *format, ...);
int KSI_LOG_info(KSI_CTX *ctx, char *format, ...);
int KSI_LOG_error(KSI_CTX *ctx, char *format, ...);
int KSI_LOG_fatal(KSI_CTX *ctx, char *format, ...);

int KSI_LOG_logBlob(KSI_CTX *ctx, int level, const char *prefix, const unsigned char *data, size_t data_len);
int KSI_LOG_logTlv(KSI_CTX *ctx, int level, const char *prefix, KSI_TLV *tlv);
int KSI_LOG_logDataHash(KSI_CTX *ctx, int level, const char *prefix, KSI_DataHash *hsh);

int KSI_Logger_new(KSI_CTX *ctx, char *fileName, int logLevel, KSI_Logger **logger);
void KSI_Logger_free(KSI_Logger *logger);
int KSI_LOG_setLogLevel(KSI_Logger *logger, int level);
int KSI_LOG_setLogFile(KSI_Logger *logger, char *file);

#ifdef __cplusplus
}
#endif

#endif /* KSI_LOG_H_ */
