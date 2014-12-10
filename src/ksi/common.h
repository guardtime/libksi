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

	#define KSI_DEFINE_OBJECT_PARSE(typ) \
		/*!
		 * This function is used to parse a raw blob into a \ref typ object.
		 * \param[in]	ctx		KSI context.
		 * \param[in]	raw		Pointer to the raw blob to be parsed.
		 * \param[in]	len		Length of the raw blob.
		 * \param[out]	t		Pointer to the receiving pointer to the \ref typ object.
		 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
		 * \see \ref typ##_serialize
		 */ \
		int typ##_parse(KSI_CTX *ctx, unsigned char *raw, unsigned len, typ **t);

	#define KSI_DEFINE_OBJECT_SERIALIZE(typ) \
		/*!
		 * This function serializes \ref #typ object into a blob.
		 * \param[in]	t		Pointer to the \ref typ object.
		 * \param[out]	raw		Pointer to the receiving pointer.
		 * \param[out]	len		Pointer to the receiving length variable.
		 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
		 * \see \ref typ##_parse
		 * @return
		 */\
		int typ##_serialize(const typ *t, unsigned char **raw, unsigned *len);

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H_ */
