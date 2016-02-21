/* aich.c - an implementation of EMule AICH Algorithm.
 * Written by Alexei Kravchenko.
 *
 * Description http://www.amule.org/wiki/index.php/AICH.
 *
 * AICH Algorithm
 *
 * Each ed2k chunk (9728000 bytes) is divided into 53 parts (52x 180KB and
 * 1x 140KB) and each of these parts is hashed using the SHA1 algorithm.
 * Each of these hashes is called a Block Hash. By combining pairs of Block
 * Hashes (i.e. each part with the part next to it) aMule will get a whole
 * tree of hashes (this tree which is therefore a hashset made of all of the
 * other Block Hashes is called the AICH Hashset). Each hash which is neither
 * a Block Hash nor the Root Hash, is a Verifying Hash. The hash at the top
 * level is the Root Hash and it is supposed to be provided by the ed2k link
 * when releasing.
 */
#include <string.h>
#include "aich.h"

#define ED2K_CHUNKSIZE 9728000
#define FULL_BLOCK_SIZE 184320
#define LAST_BLOCK_SIZE 143360

void aich_init2(aich_ctx *ctx, uint64_t file_size) {
  ctx->file_size = file_size;
  aich_init(ctx);
}

void aich_init(aich_ctx *ctx) {
  /* Note: set ctx->file_size before calling aich_init! */
  unsigned n_chunks;
  unsigned last_chunk_size;
  sha1_init(&ctx->sha1_context);
  ctx->index = 0;

  ctx->path = 1;
  ctx->level = 0;
  n_chunks = (unsigned)( (ctx->file_size + ED2K_CHUNKSIZE - 1) / ED2K_CHUNKSIZE );
  last_chunk_size = (unsigned)(ctx->file_size%ED2K_CHUNKSIZE>0 ?
      ctx->file_size%ED2K_CHUNKSIZE : (ctx->file_size==0 ? 0 : ED2K_CHUNKSIZE));
  ctx->last_chunk_blocks = (last_chunk_size + FULL_BLOCK_SIZE - 1) / FULL_BLOCK_SIZE;
  ctx->chunk_level = (n_chunks>1 ? 0 : -1);
  ctx->blocks_stack[0] = (n_chunks>1 ? n_chunks : ctx->last_chunk_blocks);
  memset(ctx->sha1_stack[0], 0, 20);
}

static void aich_process_block(aich_ctx *ctx) {
  unsigned char sha1_message[20];
  int is_left_branch;
  if(!ctx->path) return;

  /* go down into the left branch */
  while(1) {
    int level = ctx->level;
    unsigned blocks = ctx->blocks_stack[level];
    if(ctx->chunk_level>=level) {
      /* we are still at the chunk level */
      ctx->chunk_level=level+1;
    }
    if(blocks<=1 && ctx->chunk_level>level) {
      /* divide EDonkey chunk into parts */
      blocks = ( ctx->path&(ctx->path-1) ? 53 : ctx->last_chunk_blocks );
      ctx->blocks_stack[level] = blocks;
      ctx->chunk_level = level;
    }

    if(blocks<=1 && ctx->chunk_level<=level) {
      /* we are at the bottom point of tree */
      break;
    }

    /* step down into the left branch */
    blocks = (blocks + ((unsigned)ctx->path&1)) / 2;
    ctx->level++;
    ctx->blocks_stack[ctx->level] = blocks;
    ctx->path = (ctx->path<<1) | 1;
  }

  /* go up while right branch */
  for(; ctx->level>0 && (ctx->path&1)==0; ctx->path>>=1) {
    sha1_final(&ctx->sha1_context, sha1_message);
    sha1_init(&ctx->sha1_context);
    sha1_update(&ctx->sha1_context, ctx->sha1_stack[ctx->level], 20);
    sha1_update(&ctx->sha1_context, sha1_message, 20);
    ctx->level--;
  }
  sha1_final(&ctx->sha1_context, ctx->sha1_stack[ctx->level]);
  sha1_init(&ctx->sha1_context);

  ctx->path &= ~1;
  if(ctx->level==0 || ctx->path==0) return;

  /* switch to the right branch */
  is_left_branch = ((int)ctx->path & 2) >> 1;
  ctx->blocks_stack[ctx->level] = (ctx->blocks_stack[ctx->level-1] + 1 - is_left_branch)/2;
}

void aich_update(aich_ctx *ctx, const unsigned char* msg, unsigned size) {
  while(size>0) {
    unsigned left_in_chunk = ED2K_CHUNKSIZE - ctx->index;
    unsigned rest = ( left_in_chunk <= LAST_BLOCK_SIZE ?
      left_in_chunk : FULL_BLOCK_SIZE - ctx->index % FULL_BLOCK_SIZE );

    if(size>=rest) {
      sha1_update(&ctx->sha1_context, msg, rest);
      aich_process_block(ctx);
      msg += rest;
      size-= rest;
      ctx->index += rest;
      if(ctx->index>=ED2K_CHUNKSIZE) {
        ctx->index = 0;
      }
    } else {
      /* add to the bottom block */
      sha1_update(&ctx->sha1_context, msg, size);
      ctx->index += size;
      break;
    }
  }

}

void aich_final(aich_ctx *ctx, unsigned char result[20]) {
  if(ctx->sha1_context.length>0 || ctx->file_size==0) {
    aich_process_block(ctx);
  }
  memcpy(result, ctx->sha1_stack[0], 20);
  return;
}
