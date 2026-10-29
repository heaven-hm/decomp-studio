/* Regression for POPAW's 16-bit register order and ignored SP stack slot. */
#include "fy.h"

u32 popaw_original_esp;
u16 popaw_results[8];
u16 popaw_words[8] = {
    0x7777, 0x6666, 0x5555, 0x4444,
    0x3333, 0x2222, 0x1111, 0xaaaa,
};

__attribute__((naked, noinline)) void perform_popaw(u16 *stack_words) {
  __asm__ volatile("movl %esp, _popaw_original_esp\n\t"
                   "movl 4(%esp), %esp\n\t"
                   "popaw\n\t"
                   "movw %ax, _popaw_results+0\n\t"
                   "movw %cx, _popaw_results+2\n\t"
                   "movw %dx, _popaw_results+4\n\t"
                   "movw %bx, _popaw_results+6\n\t"
                   "movw %bp, _popaw_results+8\n\t"
                   "movw %si, _popaw_results+10\n\t"
                   "movw %di, _popaw_results+12\n\t"
                   "movl %esp, %eax\n\t"
                   "movw %ax, _popaw_results+14\n\t"
                   "movl _popaw_original_esp, %esp\n\t"
                   "ret");
}

int app_main(void) {
  perform_popaw(popaw_words);
  const int registers_ok = popaw_results[0] == 0xaaaa && popaw_results[1] == 0x1111 &&
                           popaw_results[2] == 0x2222 && popaw_results[3] == 0x3333 &&
                           popaw_results[4] == 0x5555 && popaw_results[5] == 0x6666 &&
                           popaw_results[6] == 0x7777;
  const int stack_ok = popaw_results[7] == (u16)(u32)(popaw_words + 8);
  out("popaw_registers="); outi(registers_ok); crlf();
  out("popaw_stack="); outi(stack_ok); crlf();
  return registers_ok && stack_ok ? 0 : 1;
}
