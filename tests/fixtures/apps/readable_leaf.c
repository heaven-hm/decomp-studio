#include "fy.h"

__attribute__((naked, noinline)) int constant_leaf(void) {
  __asm__("movl $42, %eax\n\tret");
}

int app_main(void) {
  return constant_leaf() == 42 ? 0 : 1;
}
