#ifndef TTH_H
#define TTH_H

#include <stdint.h>
#include "tiger.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tth_ctx {
  tiger_ctx tiger;
  uint64_t block_count;
  uint64_t stack[64*3];
} tth_ctx;

void tth_init(tth_ctx *ctx);
void tth_update(tth_ctx *ctx, const unsigned char* msg, unsigned size);
void tth_final(tth_ctx *ctx, unsigned char result[64]);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* TTH_H */
