/* test_sums.c */
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include "crc_sums.h"

/************************************************************************
 *                         Data for tests
 ************************************************************************/
const char* crc32_tests[] = {
  "", "00000000",
  "a", "E8B7BE43",
  "abc", "352441C2",
  "message digest", "20159D7F",
  "abcdefghijklmnopqrstuvwxyz", "4C2750BD",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "1FC2E6D2",
  "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "7CA94A72",
  0
};

const char* md5_tests[] = {
  "", "D41D8CD98F00B204E9800998ECF8427E",
  "a", "0CC175B9C0F1B6A831C399E269772661",
  "abc", "900150983CD24FB0D6963F7D28E17F72",
  "message digest", "F96B697D7CB7938D525A2F31AAF161D0",
  "abcdefghijklmnopqrstuvwxyz", "C3FCD3D76192E4007DFB496CCA67E13B",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "D174AB98D277D9F5A5611C2C9F419D9F",
  "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57EDF4A22BE3C955AC49DA2E2107B67A",
  0
};

const char* ed2k_tests[] = {
  "", "31D6CFE0D16AE931B73C59D7E0C089C0",
  "a", "BDE52CB31DE33E46245E05FBDBD6FB24",
  "abc", "A448017AAF21D8525FC10AE87AA6729D",
  "message digest", "D9130A8164549FE818874806E1C7014B",
  "abcdefghijklmnopqrstuvwxyz", "D79E1C308AA5BBCDEEA8ED63DF412DA9",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043F8582F241DB351CE627E153E7F0E4",
  "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "E33B4DDC9C38F2199C3E7B164FCC0536",
  0
};

const char* sha1_tests[] = {
  "", "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",
  "a", "86F7E437FAA5A7FCE15D1DDCB9EAEAEA377667B8",
  "abc", "A9993E364706816ABA3E25717850C26C9CD0D89D",
  "message digest", "C12252CEDA8BE8994D5FA0290A47231C1D16AAE3",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "761C457BF73B14D27E9E9265C46F4B4DDA11F940",
  "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "50ABF5706A150990A08B2C5EA40FA0E585554732",
  0
};

const char* tiger_hashes[] = {
  "", "24F0130C63AC933216166E76B1BB925FF373DE2D49584E7A",
  "abc", "F258C1E88414AB2A527AB541FFC5B8BF935F7B951C132951",
  "Tiger", "9F00F599072300DD276ABB38C8EB6DEC37790C116F9D2BDF",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-", "87FB2A9083851CF7470D2CF810E6DF9EB586445034A5A386",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+0123456789", "467DB80863EBCE488DF1CD1261655DE957896565975F9197",
  "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham", "0C410A042968868A1671DA5A3FD29A725EC1E457D3CDB303",
  "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge.", "EBF591D5AFA655CE7F22894FF87F54AC89C811B6B0DA3193",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-", "00B83EB4E53440C576AC6AAEE0A7485825FD15E70A59FFE4",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "EE8375A180A6CE8D5186363C8AA32B50CCA849DCCCFB0F89",
  0
};

const char* tth_tests[] = {
  "", "LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ",
  "a", "CZQUWH3IYXBF5L3BGYUGZHASSMXU647IP2IKE4Y",
  "abc", "ASD4UJSEH5M47PDYB46KBTSQTSGDKLBHYXOMUIA",
  "message digest", "YM432MSOX5QILIH2L4TNO62E3O35WYGWSBSJOBA",
  "abcdefghijklmnopqrstuvwxyz", "LMHNA2VYO465P2RDOGTR2CL6XKHZNI2X4CCUY5Y",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "TF74ENF7MF2WPDE35M23NRSVKJIRKYRMTLWAHWQ",
  "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "NBKCANQ2ODNTSV4C7YJFF3JRAV7LKTFIPHQNBJY",
  0
};

const char* aich_tests[] = {
  "", "3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ",
  "a", "Q336IN72UWT7ZYK5DXOLT2XK5I3XMZ5Y",
  "abc", "VGMT4NSHA2AWVOR6EVYXQUGCNSONBWE5",
  "message digest", "YERFFTW2RPUJSTK7UAUQURZDDQORNKXD",
  "abcdefghijklmnopqrstuvwxyz", "GLIQY64M7FSXBSQEZY37FIM5QQSA2OUJ",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "OYOEK67XHMKNE7U6SJS4I32LJXNBD6KA",
  "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "KCV7K4DKCUEZBIELFRPKID5A4WCVKRZS",
  0
};

/************************************************************************
 *                         Auxiliary functions
 ************************************************************************/

static crc_sums* calc_sums_c(const char* msg, size_t msg_size, size_t length, unsigned sum_id) {
  struct crc_context *ctx = crc_context_new();
  static crc_sums sums;
  size_t i;

  crc_sums_init(ctx, sum_id, length);
  for(i=0; i<length; i+=msg_size) {
    crc_sums_update(ctx, (const unsigned char*)msg, ( (i+msg_size)<=length ? msg_size : length%msg_size ) );
  }
  crc_sums_final(ctx, &sums);
  crc_context_free(ctx);
  return &sums;
}

static crc_sums* calc_sums(const char* msg, unsigned sum_id) {
  return calc_sums_c(msg, strlen(msg), strlen(msg), sum_id);
}

static char* sum_to_text(crc_sums* sums, unsigned sum_id) {
  static char res[50];
  print_sum(res, sums, sum_id, CRC_PRINT_UPPERCASE);
  return res;
}

static char* calc_sum(const char* msg, unsigned sum_id) {
  return sum_to_text(calc_sums(msg, sum_id), sum_id);
}

static int n_errors = 0;
#ifdef UNDER_CE
static char *g_msg = NULL;
#endif

static int assert_equals(const char* obtained, const char* expected, const char* name, const char* msg) {
  int success = (strcmp(obtained, expected) == 0);
//  printf("testing: %-5s (\"%s\") = %s, expected: \"%s\"\n", name, msg, obtained, expected); // debug
  if(!success) {
#ifndef UNDER_CE
    printf("error: %-5s (\"%s\") = %s, expected: \"%s\"\n", name, msg, obtained, expected);

#else /* UNDER_CE */
    char str[100];
    int add_nl = (g_msg == NULL);

    sprintf(str, "error: %-5s (\"%s\") = %s, expected: \"%s\"\n", name, msg, obtained, expected);
    g_msg = (char*)realloc(g_msg, (g_msg ? strlen(g_msg) : 0) + strlen(str) + 3);
    if(add_nl) strcat(g_msg, "\r\n");
    strcat(g_msg, str);
#endif /* UNDER_CE */
    n_errors++;
  }
  return success;
}

static void test_str(const char* message, const char* expected_hash, unsigned sum_id) {
  char* obtained = calc_sum(message, sum_id);
  assert_equals(obtained, expected_hash, get_sum_name(sum_id), message);
  //printf("?: %s (\"%s\") = %s\n", get_sum_name(sum_id), message, obtained);
  fflush(stdout);
}

/************************************************************************
 *                            Test functions
 ************************************************************************/

static void test_known_strings(void) {
  const char** tests[] = { crc32_tests, md5_tests, ed2k_tests, sha1_tests, tiger_hashes, tth_tests, aich_tests };
  int i, sum_id;

  for(i=0, sum_id=1; sum_id&FLAG_SUMS_MASK; sum_id<<=1, i++) {
    const char** p;
    for(p = tests[i]; *p; p+=2) test_str(p[0], p[1], sum_id);
  }
}

/* check that result calculation doesn't depends no message alignment */
static void test_alignment(void) {
  int i, start, sum_id, alignment_size;

  /* loop by sums */
  for(i=0, sum_id=1; sum_id&FLAG_SUMS_MASK; sum_id<<=1, i++) {
    char expected_hash[50];

    alignment_size = (sum_id&(FLAG_TTH|FLAG_TIGER) ? 8 : 4);

    /* start message with different alignment */
    for(start=0; start<alignment_size; start++) {
      char message[30];
      char* obtained;
      int j, msg_length = 8 + alignment_size;

      /* fill the buffer fifth shifted letter sequence */
      for(j=0; j<msg_length; j++) message[start + j] = 'a' + j;
      message[start + j] = 0;

      obtained = calc_sum(message + start, sum_id);

      if(start==0) {
        /* save original sum */
        strcpy(expected_hash, obtained);
        //printf("testing with: %-5s (\"%s\") = %s\n", get_sum_name(sum_id), message, obtained);
      } else {
        /* verify sum result */
        assert_equals(obtained, expected_hash, get_sum_name(sum_id), message);
        fflush(stdout);
      }
    }
  }
}

static double fsec(struct timeval *delta) {
  return ((double)delta->tv_usec/1000000.0)+delta->tv_sec;
}

/* benchmark to test algorithm speed */
void speed_test(unsigned sum_id);
void speed_test(unsigned sum_id) {
  struct crc_context *ctx = crc_context_new();
  static crc_sums sums;
  unsigned char message[8192]; //8Kb
  struct timeval st,en,st2,delta;
  int i, j;
  for(i=0; i<(int)sizeof(message); i++) message[i] = i&0xff;

  gettimeofday(&st, NULL);
  st2 = st;
//  printf("time = %u.%06u\n", st.tv_sec, st.tv_usec);

  for(j=0; j<4; j++) {
    const int sz1Gb =1073741824;

  // process repeated message buffer
    crc_sums_init(ctx, sum_id, sz1Gb);
    for(i=0; i<(sz1Gb/(int)sizeof(message)); i++) crc_sums_update(ctx, message, sizeof(message)); //1Gb
    crc_sums_final(ctx, &sums);

    gettimeofday(&en, NULL);
    delta.tv_sec  = en.tv_sec  - st.tv_sec - (en.tv_usec>=st.tv_usec ? 0 : 1);
    delta.tv_usec = en.tv_usec + (en.tv_usec>=st.tv_usec ? 0 : 1000000 ) - st.tv_usec;
    st = en;

    printf("%s HASH = %s  ", get_sum_name(sum_id), sum_to_text(&sums, sum_id));
    printf("calculated in %u.%06u sec, %f Mbps\n", (int)delta.tv_sec, (int)delta.tv_usec, 1024.0/fsec(&delta));
//    printf("time = %u.%06u\n", tmptime.tv_sec, tmptime.tv_usec);
//  printf("calculated in %u sec\n", delay);
    fflush(stdout);
  }
  delta.tv_sec  = en.tv_sec  - st2.tv_sec - (en.tv_usec>=st2.tv_usec ? 0 : 1);
  delta.tv_usec = en.tv_usec + (en.tv_usec>=st2.tv_usec ? 0 : 1000000 ) - st2.tv_usec;
  printf("total %u.%06u sec, %f Mbps\n", (int)delta.tv_sec, (int)delta.tv_usec, 4096.0/fsec(&delta));
}

/* program entry point */
#ifndef UNDER_CE

/* linux/windows program entry point */
int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  test_known_strings();
  test_alignment();
  if(n_errors==0) printf("All sums are working properly!\n");
  fflush(stdout);

//  speed_test(FLAG_CRC32);
//  speed_test(FLAG_TTH);

  return (n_errors==0 ? 0 : 1);
}
#else /* UNDER_CE */

#include <windows.h>
#include <commctrl.h>
wchar_t *char2wchar(char* str) {
  size_t origsize;
  wchar_t *wcstring;

  origsize = strlen(str) + 1;
  wcstring = (wchar_t*)malloc(origsize*2);
  mbstowcs(wcstring, str, origsize);
  return wcstring;
}

int _tmain(int argc, _TCHAR* argv[]) {
  wchar_t *wcstring;

  test_known_strings();
  test_alignment();

  wcstring = char2wchar(g_msg ? g_msg : "Success!\r\nAll sums are working properly.");
  MessageBox(NULL, wcstring, _T("caption"), MB_OK|MB_ICONEXCLAMATION);
  free(wcstring);

  return (n_errors==0 ? 0 : 1);
}
#endif /* UNDER_CE */
