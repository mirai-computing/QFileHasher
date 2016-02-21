/* aich.h */
#ifndef AICH_H
#define AICH_H
#include "sha1.h"

#ifdef __cplusplus
extern "C" {
#endif

/* state of the AICH algorithm */
typedef struct aich_ctx {
  sha1_ctx sha1_context;
  uint64_t file_size; /* algorithm requires to know file_size */
  uint64_t path; /* branch path */
  unsigned index;

  /* it's big, isn't it ;) */
  unsigned blocks_stack[56];
  unsigned char sha1_stack[56][20];
  int level;
  int chunk_level;
  unsigned last_chunk_blocks;
} aich_ctx;


void aich_init(aich_ctx *ctx);
void aich_init2(aich_ctx *ctx, uint64_t file_size);
void aich_update(aich_ctx *ctx, const unsigned char* msg, unsigned size);
void aich_final(aich_ctx *ctx, unsigned char result[20]);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* AICH_H */
