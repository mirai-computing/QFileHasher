/* crc32.h */
#ifndef CRC32_H
#define CRC32_H

#ifdef __cplusplus
extern "C" {
#endif

#define crc32_update(crc, buf, len) (crc = get_crc32(crc, buf, len))

unsigned get_crc32(unsigned crcinit, const char *c, unsigned len);
unsigned get_crc32_str(unsigned crcinit, const char *str);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* CRC32_H */
