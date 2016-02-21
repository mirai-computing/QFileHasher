/* crc_sums.c */
#include <unistd.h> /* size_t */
#include <string.h> /* memset() */
#include <stdlib.h> /* free() */
#include <stdio.h>
#include <assert.h>

#include "crc32.h"
#include "md5.h"
#include "ed2k.h"
#include "sha1.h"
#include "tiger.h"
#include "tth.h"
#include "aich.h"
#include "hex.h"
#include "byte_order.h"

#include "crc_sums.h"

/**
 * Allocate context to keep hash sums calculation results
 *
 * @return allocated context
 */
struct crc_context* crc_context_new(void) {
  crc_context* res = (crc_context*)malloc(sizeof(crc_context));
  if(res) memset(res, 0, sizeof(crc_context));
  return res;
}

/**
 * Free memory allocated by crc_context_new()
 */
void crc_context_free(struct crc_context* ctx) {
  free(ctx);
}

/**
 * Initialize context before calculation of sums
 *
 * @param context the context to initialize
 * @param flags determines which sums to compute
 * @param filesize size of the file needed only for AICH hash calculation
 */
void crc_sums_init(struct crc_context* context, unsigned flags, size_t filesize) {
  context->flags = flags;

  if(context->flags&FLAG_CRC32) context->crc32 = 0;
  if(context->flags&FLAG_MD5)   md5_init (&context->md5_context);
  if(context->flags&FLAG_SHA1)  sha1_init(&context->sha1_context);
  if(context->flags&FLAG_ED2K)  ed2k_init(&context->ed2k_context);
#ifndef DONT_COMPILE_TIGER
  if(context->flags&FLAG_TIGER) tiger_init(&context->tiger_context);
  if(context->flags&FLAG_TTH)   tth_init (&context->tth_context);
#endif

  /* AICH can be correctly calculated only for known file sizes, so init the size */
  if(context->flags&FLAG_AICH)  aich_init2(&context->aich_context, (uint64_t)filesize);
}

/**
 * Process a part of the message
 *
 * @param context keeps intermediate hash sums calculation results
 * @param buffer a part of message to process
 * @param len size of the message part
 */
void crc_sums_update(struct crc_context* context, const unsigned char* buffer, size_t len) {
  if(context->flags&FLAG_CRC32) context->crc32 = get_crc32(context->crc32, (char*)buffer, (unsigned)len);
  if(context->flags&FLAG_MD5)   md5_update (&context->md5_context, buffer, (unsigned)len);
  if(context->flags&FLAG_SHA1)  sha1_update(&context->sha1_context, buffer, (unsigned)len);
  if(context->flags&FLAG_ED2K)  ed2k_update(&context->ed2k_context, buffer, (unsigned)len);
#ifndef DONT_COMPILE_TIGER
  if(context->flags&FLAG_TIGER) tiger_update(&context->tiger_context, buffer, (unsigned)len);
  if(context->flags&FLAG_TTH)   tth_update (&context->tth_context, buffer, (unsigned)len);
#endif
  if(context->flags&FLAG_AICH)  aich_update(&context->aich_context, buffer, (unsigned)len);
}

/**
 * Obtain calculated hash sums
 *
 * @param context contains intermediate hash sums calculation results
 * @param sums a structure to store binary hash sums
 */
void crc_sums_final(struct crc_context* context, struct crc_sums* sums) {
  sums->crc32 = context->crc32;
  if(context->flags&FLAG_MD5)   md5_final(&context->md5_context, sums->md5_digest);
  if(context->flags&FLAG_ED2K)  ed2k_final(&context->ed2k_context, sums->ed2k_digest);
  if(context->flags&FLAG_SHA1)  sha1_final(&context->sha1_context, sums->sha1_digest);
#ifndef DONT_COMPILE_TIGER
  if(context->flags&FLAG_TIGER) tiger_final(&context->tiger_context, sums->tiger_digest);
  if(context->flags&FLAG_TTH)   tth_final (&context->tth_context, sums->tth_digest);
#endif
  if(context->flags&FLAG_AICH)  aich_final(&context->aich_context, sums->aich_digest);
}

struct sum_descriptor_t sum_descriptors[] = {
  {  4,  7, 0, "CRC32" },
  { 16, 26, 0, "MD5"   },
  { 16, 26, 0, "ED2K"  },
  { 20, 32, 0, "SHA1"  },
  { 24, 39, 0, "TIGER" },
  { 24, 39, 1, "TTH"   },
  { 20, 32, 1, "AICH"  }
};

sum_descriptor_t* get_sum_descriptor(unsigned sum_id)
{
  int i;

  /* check that sum_id has only one bit set and it is in the SUMS_MASK */
  if(0 != (sum_id&(sum_id-1)) || 0==(sum_id&FLAG_SUMS_MASK)) {
    return 0;
  }

  for(i=0; sum_id; sum_id>>=1, i++) {
    if(sum_id&1) return &sum_descriptors[i];
  }
  return 0;
}

/**
 * Print text presentation of a given hash sum to specified buffer
 *
 * @param output a buffer to print the hash to
 * @param sums a structure with hash calculations results
 * @param sum_id id of the sum to print
 * @param flags  controls how to print the sum, can contain flags
 *               CRC_PRINT_UPPERCASE, CRC_PRINT_HEX, CRC_PRINT_BASE32
 */
void print_sum(char* output, const crc_sums *sums, unsigned sum_id, int flags) {
  const unsigned char *digest;
  unsigned crc32;
  int upper_case = (flags & CRC_PRINT_UPPERCASE);
  int base32 = 0;
  int length;
  struct sum_descriptor_t* d = get_sum_descriptor(sum_id);

  switch(sum_id) {
    case FLAG_CRC32:
      crc32 = be2me_32(sums->crc32);
      digest = (unsigned char*)&crc32;
      break;
    case FLAG_MD5:
      digest = sums->md5_digest;
      break;
    case FLAG_SHA1:
      digest = sums->sha1_digest;
      break;
    case FLAG_TIGER:
      digest = sums->tiger_digest;
      break;
    case FLAG_TTH:
      digest = sums->tth_digest;
      break;
    case FLAG_AICH:
      digest = sums->aich_digest;
      break;
    case FLAG_ED2K:
      digest = sums->ed2k_digest;
      break;
    default:
      output[0] = '\0';
      return;
  }
  assert(d != 0);
  length = d->length;

  /* override default text presentation with flags, if given  */
  base32 = (flags&CRC_PRINT_HEX ? 0 : flags&CRC_PRINT_BASE32 ? 1 : d->base32);
  if(base32) byte_to_base32(output, digest, length, upper_case);
  else byte_to_hex(output, digest, length, upper_case);
}

/**
 * Return sum name by sum flag, NULL flag is not a hash sum id
 *
 * @param  sum_id an id of crc sum @see crc_sum_flags
 * @return crc sum name
 */
const char* get_sum_name(unsigned sum_id) {
  struct sum_descriptor_t* d = get_sum_descriptor(sum_id);
  return (d!=0 ? d->name : 0);
}
