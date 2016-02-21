/* sha1.h */
#ifndef SHA1_H
#define SHA1_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define sha1_block_size 64

typedef struct sha1_ctx {
  /* 512-bit buffer for leftovers */
  unsigned char message[sha1_block_size];
  uint64_t length;
  unsigned state[5];
} sha1_ctx;

void sha1_init(sha1_ctx *ctx);
void sha1_update(sha1_ctx *ctx, const unsigned char* msg, unsigned size);
void sha1_final(sha1_ctx *ctx, unsigned char result[20]);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* SHA1_H */
