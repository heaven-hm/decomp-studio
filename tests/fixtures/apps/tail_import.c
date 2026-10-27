/* A real x64 IAT tail thunk must consume the caller's return address. */
#include "fy.h"

int tail_rand(void);
__asm__(".text\n"
        ".globl tail_rand\n"
        "tail_rand:\n"
        "jmp *__imp_rand(%rip)\n");

int app_main(void) {
  u64 before, after;
  __asm__ volatile("mov %%rsp, %0" : "=r"(before));
  int value = tail_rand();
  __asm__ volatile("mov %%rsp, %0" : "=r"(after));
  out("tail_stack_ok="); outi(before == after); crlf();
  out("tail_rand_in_range="); outi(value >= 0 && value <= 32767); crlf();
  return 0;
}
