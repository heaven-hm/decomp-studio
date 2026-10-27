/* Adapted from Remill's Apache-2.0 MOVLHPS/MOVHLPS tests, including self moves. */
#include "fy.h"

int app_main(void) {
  u64 destination[2] = {11, 22};
  u64 source[2] = {33, 44};
  u64 result[2] = {0, 0};
  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "movdqu %2, %%xmm1\n\t"
                   "movlhps %%xmm1, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(result) : "m"(destination), "m"(source) : "xmm0", "xmm1");
  out("movlhps="); outi(result[0] == 11 && result[1] == 33); crlf();
  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "movlhps %%xmm0, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(result) : "m"(destination) : "xmm0");
  out("movlhps_self="); outi(result[0] == 11 && result[1] == 11); crlf();
  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "movdqu %2, %%xmm1\n\t"
                   "movhlps %%xmm1, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(result) : "m"(destination), "m"(source) : "xmm0", "xmm1");
  out("movhlps="); outi(result[0] == 44 && result[1] == 22); crlf();
  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "movhlps %%xmm0, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(result) : "m"(destination) : "xmm0");
  out("movhlps_self="); outi(result[0] == 22 && result[1] == 22); crlf();
  return 0;
}
