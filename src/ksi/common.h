#ifndef COMMON_H_
#define COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * Marks a functioin as deprecated.
	 */
	#if defined(__GNUC__) && ((__GNUC__ >= 4) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1)))
		#define KSI_FN_DEPRECATED(decl) decl __attribute__((deprecated))
	#elif defined(_WIN32)
		#define KSI_FN_DEPRECATED(decl) __declspec(deprecated) decl
	#else
		#define KSI_FN_DEPRECATED(decl) decl;
	#endif

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H_ */
