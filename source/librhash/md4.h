/* md4.h */
#ifndef MD4_HIDER
#define MD4_HIDER
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define md4_block_size 64

typedef struct md4_ctx {
  /* 512-bit buffer for leftovers */
  unsigned char message[md4_block_size];
  uint64_t length;
  unsigned state[4];
} md4_ctx;

void md4_init(md4_ctx *ctx);
void md4_update(md4_ctx *ctx, const unsigned char* msg, unsigned size);
void md4_final(md4_ctx *ctx, unsigned char result[16]);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* MD4_HIDER */
