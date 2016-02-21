/* md5.h */
#ifndef MD5_HIDER
#define MD5_HIDER
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define md5_block_size 64

typedef struct md5_ctx {
   /* 512-bit buffer for leftovers */
  unsigned char message[md5_block_size];
  uint64_t length;
  unsigned state[4];
} md5_ctx;

void md5_init(md5_ctx *ctx);
void md5_update(md5_ctx *ctx, const unsigned char* msg, unsigned size);
void md5_final(md5_ctx *ctx, unsigned char result[16]);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* MD5_HIDER */
