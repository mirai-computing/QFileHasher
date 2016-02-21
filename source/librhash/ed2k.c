/* ed2k.c - an implementation of EDonkey2000 Hash Algorithm.
 * Written by Alexei Kravchenko.
 *
 * See http://en.wikipedia.org/wiki/EDonkey_network for algorithm description.
 */
#include <string.h>
#include "ed2k.h"

#define ED2K_BLOCKSIZE 9728000

void ed2k_init(ed2k_ctx *ctx) {
  md4_init(&ctx->md4_context);
  md4_init(&ctx->md4_context_inner);
  ctx->filesize = 0;
  ctx->blockleft = ED2K_BLOCKSIZE;
}

void ed2k_update(ed2k_ctx *ctx, const unsigned char* msg, unsigned size) {
  unsigned char md4_digest_inner[16];
  ctx->filesize += size;

  while ( size > ctx->blockleft ) {
    md4_update(&ctx->md4_context_inner, msg, ctx->blockleft);
    msg += ctx->blockleft;
    size -= ctx->blockleft;
    ctx->blockleft = ED2K_BLOCKSIZE;

    /* just finished an ed2k block, updating context */
    md4_final(&ctx->md4_context_inner, md4_digest_inner);
    md4_update(&ctx->md4_context, md4_digest_inner, 16);
    md4_init(&ctx->md4_context_inner);
  }
  if(size) {
    md4_update(&ctx->md4_context_inner, msg, size);
    ctx->blockleft -= size;
  }
}

void ed2k_final(ed2k_ctx *ctx, unsigned char result[16]) {
  unsigned char md4_digest_inner[16];
  md4_final(&ctx->md4_context_inner, md4_digest_inner);
  if (ctx->filesize>ED2K_BLOCKSIZE) {
    if (ctx->blockleft!=ED2K_BLOCKSIZE)
      md4_update(&ctx->md4_context, md4_digest_inner, 16);
    md4_final(&ctx->md4_context, result);
  } else {
    memcpy(result, md4_digest_inner, 16);
  }
}
