/* md4.c - an implementation of MD4 Message-Digest Algorithm
 * based on RFC 1320.
 *
 * Implementation written by Alexei Kravchenko.
 */
#include <string.h>
#include "byte_order.h"
#include "md4.h"

void md4_init(md4_ctx *ctx) {
  ctx->length = 0;

  /* Initialize MD4 state */
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
}

/* First, define three auxiliary functions that each take as input
   three 32-bit words and returns a 32-bit word.
    F(X,Y,Z) = XY v not(X) Z
    G(X,Y,Z) = XY v XZ v YZ
    H(X,Y,Z) = X xor Y xor Z */
#define MD4_F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define MD4_H(x, y, z) ((x) ^ (y) ^ (z))

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define MD4_ROUND1(a, b, c, d, x, s) { \
    (a) += MD4_F ((b), (c), (d)) + (x); \
    (a) = ROTATE_LEFT ((a), (s)); \
}
#define MD4_ROUND2(a, b, c, d, x, s) { \
    (a) += MD4_G ((b), (c), (d)) + (x) + 0x5a827999; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }
#define MD4_ROUND3(a, b, c, d, x, s) { \
    (a) += MD4_H ((b), (c), (d)) + (x) + 0x6ed9eba1; \
    (a) = ROTATE_LEFT ((a), (s)); \
  }

static void md4_process_message_block(unsigned state[4], unsigned* x) {
  register unsigned a, b, c, d;
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];

  MD4_ROUND1(a, b, c, d, x[ 0],  3);
  MD4_ROUND1(d, a, b, c, x[ 1],  7);
  MD4_ROUND1(c, d, a, b, x[ 2], 11);
  MD4_ROUND1(b, c, d, a, x[ 3], 19);
  MD4_ROUND1(a, b, c, d, x[ 4],  3);
  MD4_ROUND1(d, a, b, c, x[ 5],  7);
  MD4_ROUND1(c, d, a, b, x[ 6], 11);
  MD4_ROUND1(b, c, d, a, x[ 7], 19);
  MD4_ROUND1(a, b, c, d, x[ 8],  3);
  MD4_ROUND1(d, a, b, c, x[ 9],  7);
  MD4_ROUND1(c, d, a, b, x[10], 11);
  MD4_ROUND1(b, c, d, a, x[11], 19);
  MD4_ROUND1(a, b, c, d, x[12],  3);
  MD4_ROUND1(d, a, b, c, x[13],  7);
  MD4_ROUND1(c, d, a, b, x[14], 11);
  MD4_ROUND1(b, c, d, a, x[15], 19);
  
  MD4_ROUND2(a, b, c, d, x[ 0],  3);
  MD4_ROUND2(d, a, b, c, x[ 4],  5);
  MD4_ROUND2(c, d, a, b, x[ 8],  9);
  MD4_ROUND2(b, c, d, a, x[12], 13);
  MD4_ROUND2(a, b, c, d, x[ 1],  3);
  MD4_ROUND2(d, a, b, c, x[ 5],  5);
  MD4_ROUND2(c, d, a, b, x[ 9],  9);
  MD4_ROUND2(b, c, d, a, x[13], 13);
  MD4_ROUND2(a, b, c, d, x[ 2],  3);
  MD4_ROUND2(d, a, b, c, x[ 6],  5);
  MD4_ROUND2(c, d, a, b, x[10],  9);
  MD4_ROUND2(b, c, d, a, x[14], 13);
  MD4_ROUND2(a, b, c, d, x[ 3],  3);
  MD4_ROUND2(d, a, b, c, x[ 7],  5);
  MD4_ROUND2(c, d, a, b, x[11],  9);
  MD4_ROUND2(b, c, d, a, x[15], 13);

  MD4_ROUND3(a, b, c, d, x[ 0],  3);
  MD4_ROUND3(d, a, b, c, x[ 8],  9);
  MD4_ROUND3(c, d, a, b, x[ 4], 11);
  MD4_ROUND3(b, c, d, a, x[12], 15);
  MD4_ROUND3(a, b, c, d, x[ 2],  3);
  MD4_ROUND3(d, a, b, c, x[10],  9);
  MD4_ROUND3(c, d, a, b, x[ 6], 11);
  MD4_ROUND3(b, c, d, a, x[14], 15);
  MD4_ROUND3(a, b, c, d, x[ 1],  3);
  MD4_ROUND3(d, a, b, c, x[ 9],  9);
  MD4_ROUND3(c, d, a, b, x[ 5], 11);
  MD4_ROUND3(b, c, d, a, x[13], 15);
  MD4_ROUND3(a, b, c, d, x[ 3],  3);
  MD4_ROUND3(d, a, b, c, x[11],  9);
  MD4_ROUND3(c, d, a, b, x[ 7], 11);
  MD4_ROUND3(b, c, d, a, x[15], 15);
  
  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

void md4_update(md4_ctx *ctx, const unsigned char* msg, unsigned size) {
  unsigned index = (unsigned)ctx->length & 63;
  unsigned left;
  ctx->length += size;
  
  /* Try to fill partial block */
  if (index) {
    left = md4_block_size - index;
    if (size < left) {
      le32_copy(ctx->message + index, msg, size);
      return;
    } else {
      le32_copy(ctx->message + index, msg, left);
      md4_process_message_block(ctx->state, (unsigned*)ctx->message);
      msg += left;
      size -= left;
    }
  }
  while (size >= md4_block_size) {
    if( IS_LITTLE_ENDIAN && IS_ALIGNED_32(msg) ) {
      /* the most common case is processing of an already aligned message 
         on little-endian CPU without copying it */
      md4_process_message_block(ctx->state, (unsigned*)msg);
    } else {
      le32_copy(ctx->message, msg, md4_block_size);
      md4_process_message_block(ctx->state, (unsigned*)ctx->message);
    }

    msg += md4_block_size;
    size -= md4_block_size;
  }
  if(size) {
    /* save leftovers */
    le32_copy(ctx->message, msg, size);
  }
}

#ifdef CPU_BIG_ENDIAN
# define MD4_INDEX(i) ((i) ^ 3)
#else
# define MD4_INDEX(i) (i)
#endif

void md4_final(md4_ctx *ctx, unsigned char result[16]) {
  unsigned index = (unsigned)ctx->length & 63;
  unsigned* msg32 = (unsigned*)ctx->message;
  
  /* pad message and run for last block */
  ctx->message[ MD4_INDEX(index++) ] = 0x80;
  while( index&3 ) {
      ctx->message[ MD4_INDEX(index++) ] = 0;
  }
  index >>= 2;

  /* if no room left in the message to store 64-bit message length */
  if(index>14) {
    /* then pad the rest with zeros and process it */
    while(index < 16) {
      msg32[index++] = 0;
    }
    md4_process_message_block(ctx->state, msg32);
    index = 0;
  }
  while(index < 14) {
    msg32[index++] = 0;
  }
  msg32[14] = (unsigned)(ctx->length << 3);
  msg32[15] = (unsigned)(ctx->length >> 29);
  md4_process_message_block(ctx->state, msg32);

  le32_copy(result, &ctx->state, 16);
}
