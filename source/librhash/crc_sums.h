/* crc_sums.h */
#ifndef CRC_SUMS_H
#define CRC_SUMS_H

#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "ed2k.h"
#include "tiger.h"
#include "tth.h"
#include "aich.h"

#ifdef __cplusplus
extern "C" {
#endif

/* crc flags */
enum crc_sum_flags {
  FLAG_CRC32 = 0x01,
  FLAG_MD5   = 0x02,
  FLAG_ED2K  = 0x04,
  FLAG_SHA1  = 0x08,
  FLAG_TIGER = 0x10,
  FLAG_TTH   = 0x20,
  FLAG_AICH  = 0x40,
  FLAG_MD5_ED2K_MIXED_UP = 0x100,
  FLAG_MD5_AICH_MIXED_UP = 0x200,
  FLAG_IS_MIXED  = FLAG_MD5_ED2K_MIXED_UP|FLAG_MD5_AICH_MIXED_UP,
  FLAG_SUMS_MASK = FLAG_CRC32|FLAG_MD5|FLAG_ED2K|FLAG_SHA1|FLAG_TIGER|FLAG_TTH|FLAG_AICH
};

/* state of the crc algorithms, keeps info while calculating sums */
//struct crc_context;
typedef struct crc_context {
  unsigned flags;
  unsigned crc32;
  md5_ctx md5_context;
  sha1_ctx sha1_context;
  ed2k_ctx ed2k_context;
#ifndef DONT_COMPILE_TIGER
  tiger_ctx tiger_context;
  tth_ctx tth_context;
#endif
  aich_ctx aich_context;
} crc_context;

/* binary result of calculations */
typedef struct crc_sums {
  unsigned crc32;
  unsigned char md5_digest[16];
  unsigned char ed2k_digest[16];
  unsigned char sha1_digest[20];
  unsigned char tiger_digest[24];
  unsigned char tth_digest[24];
  unsigned char aich_digest[20];
  unsigned flags;
} crc_sums;

/* functions to calculate hash sums */
void crc_sums_init(struct crc_context* context, unsigned flags, size_t filesize);
void crc_sums_update(struct crc_context* context, const unsigned char* buffer, size_t len);
void crc_sums_final(struct crc_context* context, struct crc_sums* sums);

struct crc_context* crc_context_new(void);
void crc_context_free(struct crc_context* ctx);

/* a hash sum descriptor */
typedef struct sum_descriptor_t {
  short length;
  short base32_length;
  short base32;
  const char* name;
} sum_descriptor_t;

enum print_sum_flags {
  CRC_PRINT_UPPERCASE = 1,
  CRC_PRINT_HEX = 2,
  CRC_PRINT_BASE32 = 4
};

void print_sum(char* output, const crc_sums *sums, unsigned sum_id, int flags);
struct sum_descriptor_t* get_sum_descriptor(unsigned sum_id);
const char* get_sum_name(unsigned sum_id);

/*#if !defined(_MSC_VER) || (_MSC_VER >= 1300)
#define COMPILE_TIGER
#endif*/

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* CRC_SUMS_H */
