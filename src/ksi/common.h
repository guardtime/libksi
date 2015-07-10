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

#ifndef COMMON_H_
#define COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

	/**
	 * Marks a function as deprecated.
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
		int typ##_parse(KSI_CTX *ctx, const unsigned char *raw, size_t len, typ **t);

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
		int typ##_serialize(const typ *t, unsigned char **raw, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H_ */
