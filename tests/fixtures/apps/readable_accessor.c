#include "fy.h"

/* An ACCESSOR: the whole body returns its own first stack argument. It is the second shape
 * the bounded high-level path recognises, after a constant return, and it is worth having
 * because `mov eax, [esp+4]; ret` is what a compiler emits for a getter. */
__attribute__((naked, noinline)) int first_argument(int first, int second) {
  __asm__("movl 4(%esp), %eax\n\tret");
}

int app_main(void) {
  return first_argument(7, 9) == 7 ? 0 : 1;
}
