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


#ifdef __cplusplus
}
#endif

#endif /* KSI_LOG_H_ */
