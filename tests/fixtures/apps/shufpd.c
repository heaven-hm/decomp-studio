/* Regression for SHUFPD's independent 64-bit lane selectors. */
#include "fy.h"

int app_main(void) {
  u64 destination[2] = {0x11ull, 0x22ull};
  u64 source[2] = {0x33ull, 0x44ull};
  u64 result[2] = {0, 0};

  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "movdqu %2, %%xmm1\n\t"
                   "shufpd $1, %%xmm1, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(*(char(*)[16])result)
                   : "m"(*(char(*)[16])destination), "m"(*(char(*)[16])source)
                   : "xmm0", "xmm1");
  const int register_form = result[0] == 0x22ull && result[1] == 0x33ull;

  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "shufpd $2, %2, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(*(char(*)[16])result)
                   : "m"(*(char(*)[16])destination), "m"(*(char(*)[16])source)
                   : "xmm0");
  const int memory_form = result[0] == 0x11ull && result[1] == 0x44ull;
  out("shufpd_reg_ok="); outi(register_form); crlf();
  out("shufpd_mem_ok="); outi(memory_form); crlf();
  return register_form && memory_form ? 0 : 1;
}
