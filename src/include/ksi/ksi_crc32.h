#ifndef KSI_CRC32_H_
#define KSI_CRC32_H_

#ifdef __cplusplus
extern "C" {
#endif
/**
 * \addtogroup util Util
 * @{
 */

/**
 * Calculates CRC32 checksum.
 * \param[in]		data		Pointer to the data.
 * \param[in]		length		Length of the data.
 * \param[in]		ival		Initial value. Pass 0 for the first or single call to this
 * 								function and pass result from the previous call for the next part of the
 * 								data.
 * \return CRC32 of the data.
 */
unsigned long KSI_crc32(const void *data, size_t length, unsigned long ival);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* KSI_CRC32_H_ */
