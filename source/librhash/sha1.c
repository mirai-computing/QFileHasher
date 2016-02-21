/* sha1.c - an implementation of Secure Hash Algorithm 1 (SHA1)
 * based on RFC 3174.
 *
 * Implementation written by Alexei Kravchenko.
 */
#include <string.h>
#include "byte_order.h"
#include "sha1.h"

void sha1_init(sha1_ctx *ctx) {
  ctx->length = 0;

  /* initialize sha1 state */
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xefcdab89;
  ctx->state[2] = 0x98badcfe;
  ctx->state[3] = 0x10325476;
  ctx->state[4] = 0xc3d2e1f0;
}

/* CIRCULAR_LEFT_SHIFT rotates the word left n bits */
#define CIRCULAR_LEFT_SHIFT(word, n) (((word) << (n)) ^ ((word) >> (32-(n))))

static void sha1_process_message_block(unsigned *state, const unsigned* block) {
    int           t;                 /* Loop counter */
    uint32_t      temp;              /* Temporary word value */
    uint32_t      W[80];             /* Word sequence */
    uint32_t      A, B, C, D, E;     /* Word buffers */

    /* initialize the first 16 words in the array W */
    for(t = 0; t < 16; t++) {
      W[t] = be2me_32(block[t]);
    }

    /* initialize the rest */
    for(t = 16; t < 80; t++) {
       W[t] = CIRCULAR_LEFT_SHIFT(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];

    for(t = 0; t < 20; t++) {
        temp =  CIRCULAR_LEFT_SHIFT(A, 5) + ((B & C) | ((~B) & D))
          + E + W[t] + 0x5A827999;
        E = D;
        D = C;
        C = CIRCULAR_LEFT_SHIFT(B, 30);
        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++) {
        temp = CIRCULAR_LEFT_SHIFT(A, 5) + (B ^ C ^ D) + E + W[t] + 0x6ED9EBA1;
        E = D;
        D = C;
        C = CIRCULAR_LEFT_SHIFT(B, 30);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++) {
        temp = CIRCULAR_LEFT_SHIFT(A, 5) + ((B & C) | (B & D) | (C & D))
         + E + W[t] + 0x8F1BBCDC;
        E = D;
        D = C;
        C = CIRCULAR_LEFT_SHIFT(B, 30);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++) {
        temp = CIRCULAR_LEFT_SHIFT(A, 5) + (B ^ C ^ D) + E + W[t] + 0xCA62C1D6;
        E = D;
        D = C;
        C = CIRCULAR_LEFT_SHIFT(B, 30);
        B = A;
        A = temp;
    }

    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
    state[4] += E;
}

void sha1_update(sha1_ctx *ctx, const unsigned char* msg, unsigned size) {
  unsigned index = (unsigned)ctx->length & 63;
  unsigned left;
  ctx->length += size;

  /* Try to fill partial block */
  if (index) {
    left = sha1_block_size - index;
    if (size < left) {
      memcpy(ctx->message + index, msg, size);
      return;
    } else {
      memcpy(ctx->message + index, msg, left);
      sha1_process_message_block(ctx->state, (unsigned*)ctx->message);
      msg += left;
      size -= left;
    }
  }
  while (size >= sha1_block_size) {
    if( IS_ALIGNED_32(msg) ) {
      /* the most common case is processing of an already aligned message 
         without copying it */
      sha1_process_message_block(ctx->state, (unsigned*)msg);
    } else {
      memcpy(ctx->message, msg, sha1_block_size);
      sha1_process_message_block(ctx->state, (unsigned*)ctx->message);
    }

    msg += sha1_block_size;
    size -= sha1_block_size;
  }
  if(size) {
    /* save leftovers */
    memcpy(ctx->message, msg, size);
  }
}

void sha1_final(sha1_ctx *ctx, unsigned char result[20]) {
  unsigned index = (unsigned)ctx->length & 63;
  
  /* pad message and run for last block */
  ctx->message[index++] = 0x80;

  /* if no room left in the message to store 64-bit message length */
  if(index>56) {
    /* then pad the rest with zeros and process it */
    while(index < 64) {
      ctx->message[index++] = 0;
    }
    sha1_process_message_block(ctx->state, (unsigned*)ctx->message);
    index = 0;
  }
  while(index < 56) {
    ctx->message[index++] = 0;
  }
  ((unsigned*)ctx->message)[14] = be2me_32( (unsigned)(ctx->length >> 29) );
  ((unsigned*)ctx->message)[15] = be2me_32( (unsigned)(ctx->length << 3) );

  sha1_process_message_block(ctx->state, (unsigned*)ctx->message);

  be32_copy(result, &ctx->state, 20);
}
