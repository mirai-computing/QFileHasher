/* byte_order.c */
#include <unistd.h>
#include <stdlib.h> /* size_t for vc6.0 */
#include "byte_order.h"

void u32_swap_copy(void* to, const void* from, size_t length) {
  int index = (int)((char*)to - (char*)0) & 3;
  const char* src = (const char*)from; 
  const char* end = src + length; 
  char* dst = (char*)to - index;
  for(; src<end; index++) dst[index^3] = *src++;
}

void u64_swap_copy(void* to, int index, const void* from, size_t length) {
  const char* src = (const char*)from; 
  for(length += index; (size_t)index<length; index++) ((char*)to)[index^7] = *src++;
}

void u32_memswap(unsigned *p, int length_in_u32) {
  int i;
  for(i=0; i<length_in_u32; i++) {
    p[i] = bswap_32(p[i]);
  }
}

/* detect if cpu architecture is little endian */
/*int is_little_endian() {
    short tmp = 0x0001;
    return  (0 != *(char*)&tmp);
}*/
