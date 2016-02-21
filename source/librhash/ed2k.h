/* ed2k.h */
#ifndef ED2K_H
#define ED2K_H
#include "md4.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ed2k_ctx {
  md4_ctx md4_context;
  md4_ctx md4_context_inner;
  
  uint64_t filesize;
  unsigned blockleft;
} ed2k_ctx;

void ed2k_init(ed2k_ctx *ctx);
void ed2k_update(ed2k_ctx *ctx, const unsigned char* msg, unsigned size);
void ed2k_final(ed2k_ctx *ctx, unsigned char result[16]);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* ED2K_H */
