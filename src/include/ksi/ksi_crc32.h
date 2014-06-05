#ifndef KSI_CRC32_H_
#define KSI_CRC32_H_

#ifdef __cplusplus
extern "C" {
#endif

unsigned long KSI_crc32(const void *data, size_t length, unsigned long ival);

#ifdef __cplusplus
}
#endif

#endif /* KSI_CRC32_H_ */
