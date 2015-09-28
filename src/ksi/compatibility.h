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

#ifndef COMPATIBILITY_H
#define	COMPATIBILITY_H
#include <stddef.h>
#include <stdarg.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * \addtogroup comp Cross-platform compatibility functions.
 * @{
 */

/**
 * Platform independent version of snprintf.
 * \param[in]		buf		Pointer to buffer.
 * \param[in]		n		Maximum number of bytes to be written into buffer. Includes terminating NULL character.
 * \param[in]		format	Format string.
 * \param[in]		...		Extra parameters for formatting.
 * \return The number of characters written, not including terminating NUL character. On error 0 is returned.
 */
size_t KSI_snprintf(char *buf, size_t n, const char *format, ... );

/**
 * Platform independent version of vsnprintf.
 * \param[in]		buf		Pointer to buffer.
 * \param[in]		n		Maximum number of bytes to be written into buffer. Includes terminating NULL character.
 * \param[in]		format	Format string.
 * \param[in]		va		variable list.
 * \return The number of characters written, not including terminating NUL character. On error 0 is returned.
 */
size_t KSI_vsnprintf(char *buf, size_t n, const char *format, va_list va);

/**
 * Platform independent version of strncpy that guarantees NULL terminated
 * destination. To copy N characters from source to destination n and size of
 * source must be N+1.
 * \param[in]		destination Pointer to destination.
 * \param[in]		source		Pointer to source.
 * \param[in]		n			Maximum number of characters to be copied.
 * \return The pointer to destination is returned. On error NULL is returned.
 */
char *KSI_strncpy (char *destination, const char *source, size_t n);

/**
 * Platform independent string duplicate function. It will create a new null-terminated string from the
 * initial version.
 * \param[in]	from		String to be copied.
 * \param[in]	to 			Pointer to the receiving pointer.
 * \return On success returns KSI_OK, otherwise a status code is returned (see #KSI_StatusCode).
 */
int KSI_strdup(const char *from, char **to);

/*
 * @}
 */

#ifdef	__cplusplus
}
#endif

#endif	/* COMPLEMENTARY_H */

