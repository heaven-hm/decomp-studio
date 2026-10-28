/* Regression for POPAL's register order and ignored ESP stack slot. */
#include "fy.h"

u32 popal_original_esp;
u32 popal_results[8];
u32 popal_words[8] = {
    0x77777777, 0x66666666, 0x55555555, 0x44444444,
    0x33333333, 0x22222222, 0x11111111, 0xaaaaaaaa,
};

__attribute__((naked, noinline)) void perform_popal(u32 *stack_words) {
  __asm__ volatile("movl %esp, _popal_original_esp\n\t"
                   "movl 4(%esp), %esp\n\t"
                   "popal\n\t"
                   "movl %eax, _popal_results+0\n\t"
                   "movl %ecx, _popal_results+4\n\t"
                   "movl %edx, _popal_results+8\n\t"
                   "movl %ebx, _popal_results+12\n\t"
                   "movl %ebp, _popal_results+16\n\t"
                   "movl %esi, _popal_results+20\n\t"
                   "movl %edi, _popal_results+24\n\t"
                   "movl %esp, _popal_results+28\n\t"
                   "movl _popal_original_esp, %esp\n\t"
                   "ret");
}

int app_main(void) {
  perform_popal(popal_words);
  const int registers_ok = popal_results[0] == 0xaaaaaaaau && popal_results[1] == 0x11111111 &&
                           popal_results[2] == 0x22222222 && popal_results[3] == 0x33333333 &&
                           popal_results[4] == 0x55555555 && popal_results[5] == 0x66666666 &&
                           popal_results[6] == 0x77777777;
  const int stack_ok = popal_results[7] == (u32)(popal_words + 8);
  out("popal_registers="); outi(registers_ok); crlf();
  out("popal_stack="); outi(stack_ok); crlf();
  return registers_ok && stack_ok ? 0 : 1;
}
