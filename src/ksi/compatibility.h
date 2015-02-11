#ifndef COMPATIBILITY_H
#define	COMPATIBILITY_H
#include <stddef.h>
#include <stdarg.h>

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * Platform independent version of snprintf. 
 * \param[int/out]	buf		Pointer to buffer.
 * \param[in]		n		Maximum number of bytes to be written into buffer. Includes terminating NULL character.
 * \param[in]		format	Format string.
 * \param[in]		...		Extra parameters for formatting.
 * \return The number of characters written, not including terminating NUL character. On error -1 is returned.
 */
int KSI_snprintf(char *buf, size_t n, const char *format, ... );

/**
 * Platform independent version of vsnprintf. 
 * \param[int/out]	buf		Pointer to buffer.
 * \param[in]		n		Maximum number of bytes to be written into buffer. Includes terminating NULL character.
 * \param[in]		format	Format string.
 * \param[in]		va		variable list.
 * \return The number of characters written, not including terminating NUL character. On error -1 is returned.
 */
int KSI_vsnprintf(char *buf, size_t n, const char *format, va_list va);

/**
 * Platform independent version of strncpy that guarantees NULL terminated destination.
 * \param[out]		destination Pointer to destination.
 * \param[in]		source		Pointer to source.
 * \param[in]		n			Maximum number of characters to be copied.
 * \return The pointer to destination is returned. On error NULL is returned.
 */
char *KSI_strncpy (char *destination, const char *source, size_t n);


#ifdef	__cplusplus
}
#endif

#endif	/* COMPLEMENTARY_H */

