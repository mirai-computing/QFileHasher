/* hex.h */
#ifndef HEX_H
#define HEX_H

#ifdef __cplusplus
extern "C" {
#endif

void byte_to_hex(char *dst, const unsigned char *src, unsigned len, int upper_case);
void byte_to_base32(char* dest, const unsigned char* src, unsigned len, int upper_case);
char* put_hex_char(char *dst, const unsigned char byte, int upper_case);

#define IS_BASE32(a) ( ( (a)<='7' && '2'<=(a) ) || ( 'A'<=((a)&0xdf) && ((a)&0xdf)<='Z' ) )
#define BASE32TODIGIT(a) ( (a)<'A' ? (a)-'2'+26 : ((a)&0xdf)-'A' )

void base32tobyte(const char* str, unsigned char* bin, int len);
void hex_to_byte(const char* str, unsigned char* bin, int len);
unsigned hex_to_uint(const char* str);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* HEX_H */
