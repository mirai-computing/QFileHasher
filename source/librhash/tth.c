#include <string.h>
#include "byte_order.h"
#include "tth.h"

void tth_init(tth_ctx *ctx) {
  tiger_init(&ctx->tiger);
  ctx->tiger.message[ ctx->tiger.length++ ] = 0;
  ctx->block_count = 0;
}

#define bswap_3x64(m) { \
  ((uint64_t*)(m))[0] = bswap_64(((uint64_t*)(m))[0]); \
  ((uint64_t*)(m))[1] = bswap_64(((uint64_t*)(m))[1]); \
  ((uint64_t*)(m))[2] = bswap_64(((uint64_t*)(m))[2]); \
}

static void tth_process_block_hash(tth_ctx *ctx) {
  uint64_t it;
  unsigned pos = 0;
  unsigned char msg[24];
  for(it=1; it & ctx->block_count; it <<= 1) {
    tiger_final(&ctx->tiger, msg);
    bswap_3x64(msg);
    tiger_init(&ctx->tiger);
    ctx->tiger.message[ ctx->tiger.length++ ] = 1;
    tiger_update(&ctx->tiger, (unsigned char*)(ctx->stack + pos), 24);
    /* note: we can cut this step, if the previous tiger_final saves directly to ctx->tiger.message+25; */
    tiger_update(&ctx->tiger, msg, 24);
    pos += 3;
  }
  tiger_final(&ctx->tiger, (unsigned char*)(ctx->stack + pos));
  bswap_3x64( ctx->stack + pos );
  ctx->block_count++;
}

void tth_update(tth_ctx *ctx, const unsigned char* msg, unsigned size) {
  unsigned rest = 1025 - (unsigned)ctx->tiger.length;
  for(;;) {
    if(size<rest) rest = size;
    tiger_update(&ctx->tiger, msg, rest);
    msg += rest;
    size -= rest;
    if(ctx->tiger.length<1025) {
      return;
    }
    
    /* process block hash */
    tth_process_block_hash(ctx);
    
    /* init block hash */
    tiger_init(&ctx->tiger);
    ctx->tiger.message[ ctx->tiger.length++ ] = 0;
    rest = 1024;
  }
}

/* get tth root hash */
void tth_final(tth_ctx *ctx, unsigned char result[24]) {
  uint64_t it = 1;
  unsigned pos = 0;
  unsigned char msg[24];
  unsigned char* last_message;

  /* process bytes left in the context buffer */
  if(ctx->tiger.length>1 || ctx->block_count==0) {
    tth_process_block_hash(ctx);
  }
  
  for(; it < ctx->block_count && (it&ctx->block_count)==0; it <<= 1) pos += 3;
  last_message = (unsigned char*)(ctx->stack + pos);

  for(it <<= 1; it <= ctx->block_count; it <<= 1) {
    /* merge tth sums in the tree */
    pos += 3;
    if(it&ctx->block_count) {
      tiger_init(&ctx->tiger);
      ctx->tiger.message[ ctx->tiger.length++ ] = 1;
      tiger_update(&ctx->tiger, (unsigned char*)(ctx->stack + pos), 24);
      tiger_update(&ctx->tiger, last_message, 24);

      tiger_final(&ctx->tiger, msg);
      bswap_3x64(msg);
      last_message = msg;
    }
  }
  
  memcpy(result, last_message, 24);
  return;
}
