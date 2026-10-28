/* Regression for MOVHPS loading the upper qword without changing the lower one. */
#include "fy.h"

int app_main(void) {
  u64 initial[2] = {0x1122334455667788ull, 0};
  u64 upper = 0x99aabbccddeeff00ull;
  u64 result[2] = {0, 0};
  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "movhps %2, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(*(char(*)[16])result)
                   : "m"(*(char(*)[16])initial), "m"(upper)
                   : "xmm0");
  out("movhps_low="); outi((i64)result[0]); crlf();
  out("movhps_high="); outi((i64)result[1]); crlf();
  return result[0] == initial[0] && result[1] == upper ? 0 : 1;
}
