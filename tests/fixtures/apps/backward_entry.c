/* A function's first recovered address can precede its actual entry. */
#include "fy.h"

int backward_entry(int condition);
__asm__(".text\n"
        "backward_block:\n"
        "mov $7, %eax\n"
        "ret\n"
        ".globl backward_entry\n"
        "backward_entry:\n"
        "test %ecx, %ecx\n"
        "jne backward_block\n"
        "mov $42, %eax\n"
        "ret\n");

int app_main(void) {
  out("entry_zero="); outi(backward_entry(0)); crlf();
  out("entry_nonzero="); outi(backward_entry(1)); crlf();
  return 0;
}
