/* Regression for IRETD used as a handler-stub exit. The Unicorn reference
 * cannot execute this: it runs at CPL0 without a GDT, so every protected-mode
 * IRET faults while loading the return CS. The e2e test therefore runs this
 * fixture candidate-only against these hand-computed expectations. */
#include "fy.h"

/* Pushes a synthetic IRET frame and returns through it. On hardware the trailing
 * `ret` consumes the call's return address; the translated build returns natively
 * from the handler, so both paths must leave ESP and the restored flags alike. */
__attribute__((naked, noinline)) void perform_iretd(void) {
  __asm__ volatile("pushfl\n\t"
                   "stc\n\t"
                   "pushl $0x1b\n\t"
                   "pushl $1f\n\t"
                   "iret\n\t"
                   "1:\n\t"
                   "ret");
}

int app_main(void) {
  /* The frame saves CF=0 and the live flag is then set to 1 before IRET restores
   * the saved value, so a CF of 0 afterwards proves the restore happened. EAX
   * carries ESP across the call so the stack-pointer balance is checked too. */
  unsigned char iretd_cf = 1;
  unsigned char iretd_esp_ok = 0;
  __asm__ volatile("movl %%esp, %%eax\n\t"
                   "clc\n\t"
                   "call _perform_iretd\n\t"
                   "setc %0\n\t"
                   "cmpl %%eax, %%esp\n\t"
                   "sete %1"
                   : "=m"(iretd_cf), "=m"(iretd_esp_ok)
                   :
                   : "eax", "ebx", "ecx", "edx", "esi", "edi", "cc", "memory");
  out("iretd_cf="); outi(iretd_cf); crlf();
  out("iretd_esp_ok="); outi(iretd_esp_ok); crlf();
  return iretd_cf == 0 && iretd_esp_ok == 1 ? 0 : 1;
}
