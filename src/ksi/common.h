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

#ifndef __GNUC__
#  define KSI_ATTRIBUTE(x)
#else
#  define KSI_ATTRIBUTE(x) __attribute__(x)
#endif


/**
 * A macro for validating the correctness of any given hash tree level.
 * \param[in]	level		The level to be checked.
 * \return If the parameter is a valid hash tree level a non-zero value is return, zero otherwise.
 */
#define KSI_IS_VALID_TREE_LEVEL(level) (((level) <= 0xff) && ((int)(level) >= 0))

/**
 * Marks a function as deprecated.
 */
#ifndef __KSI_NO_DEPRECATE__
#  if defined(__GNUC__) && ((__GNUC__ >= 4) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1)))
#    define KSI_FN_DEPRECATED(decl, comment) /*! \deprecated comment */ decl __attribute__((deprecated))
#  elif defined(_WIN32)
#    define KSI_FN_DEPRECATED(decl, comment) /*! \deprecated comment */ __declspec(deprecated) decl
#  else
#    define KSI_FN_DEPRECATED(decl, comment) /*! \deprecated comment */ decl
#  endif
#else
#  define KSI_FN_DEPRECATED(decl, comment) decl;
#endif

/**
 * Marks a variable as deprecated.
 */
#ifndef __KSI_NO_DEPRECATE__
#  if defined(__GNUC__) && ((__GNUC__ >= 4) || ((__GNUC__ == 3) && (__GNUC_MINOR__ >= 1)))
#    define KSI_VAR_DEPRECATED(decl, comment) /*! \deprecated comment */ decl __attribute__((deprecated))
#  else
	 /* No reasonable way to show the warning with VS. */
#    define KSI_VAR_DEPRECATED(decl, comment) /*! \deprecated comment */ decl
#  endif
#else
#  define KSI_VAR_DEPRECATED(decl, comment) decl
#endif

/**
 * Marks a enumerator as deprecated.
 */
#ifndef __KSI_NO_DEPRECATE__
#  if defined(__GNUC__) && (__GNUC__ >= 6)
#    define KSI_ENUM_DEPRECATED(decl, comment) /*! \deprecated comment */ decl __attribute__((deprecated))
#  else
	 /* No reasonable way to show the warning with VS. */
#    define KSI_ENUM_DEPRECATED(decl, comment) /*! \deprecated comment */ decl
#  endif
#else
#  define KSI_ENUM_DEPRECATED(decl, comment) decl
#endif

#if defined(_WIN32) && defined(DLL_BUILD) && !(KSI_BUILD)
#  define KSI_DEFINE_EXTERN(e) __declspec( dllimport ) extern e
#else
#  define KSI_DEFINE_EXTERN(e) extern e
#endif

/**
 * The function parameter is unused inside the function body.
 */
#define KSI_UNUSED(x) KSI_ATTRIBUTE((__unused__)) x

#ifdef __cplusplus
}
#endif

#endif /* COMMON_H_ */
