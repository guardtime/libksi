/**************************************************************************
 *
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright (C) [2015] Guardtime, Inc
 * All Rights Reserved
 *
 * NOTICE:  All information contained herein is, and remains, the
 * property of Guardtime Inc and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime Inc and its suppliers and may be
 * covered by U.S. and Foreign Patents and patents in process,
 * and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this
 * material is strictly forbidden unless prior written permission
 * is obtained from Guardtime Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime Inc.
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
 * \return The number of characters written, not including terminating NUL character. On error -1 is returned.
 */
int KSI_snprintf(char *buf, size_t n, const char *format, ... );

/**
 * Platform independent version of vsnprintf. 
 * \param[in]		buf		Pointer to buffer.
 * \param[in]		n		Maximum number of bytes to be written into buffer. Includes terminating NULL character.
 * \param[in]		format	Format string.
 * \param[in]		va		variable list.
 * \return The number of characters written, not including terminating NUL character. On error -1 is returned.
 */
int KSI_vsnprintf(char *buf, size_t n, const char *format, va_list va);

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


/*
 * @}
 */

#ifdef	__cplusplus
}
#endif

#endif	/* COMPLEMENTARY_H */

