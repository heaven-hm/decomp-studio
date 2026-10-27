/* Cases adapted from Remill tests/X86/DECIMAL/AAS.S, Apache-2.0. */
#include "fy.h"

int app_main(void) {
  static const unsigned input[] = {0x0f0f, 0xffff, 0x44440f0f, 0x0f08, 0x0f09, 0, 0x0f00};
  static const unsigned af[] = {0, 1, 1, 1, 0, 1, 0};
  static const unsigned expected[] = {0x0e09, 0xfe09, 0x44440e09, 0x0e02, 0x0f09, 0xfe0a, 0x0f00};
  unsigned ok = 1;
  for (unsigned i = 0; i < 7; ++i) {
    unsigned result, flags;
    unsigned initial_flags = af[i] ? 0x12 : 0x02;
    __asm__ volatile("pushl %[f]\n\tpopfl\n\tmovl %[v], %%eax\n\t.byte 0x3f\n\t"
                     "movl %%eax, %%edx\n\tlahf\n\tmovzbl %%ah, %%eax"
                     : "=&a"(flags), "=&d"(result)
                     : [f] "r"(initial_flags), [v] "r"(input[i]) : "cc");
    unsigned adjusted = i != 4 && i != 6;
    ok &= result == expected[i] && (flags & 0x11) == (adjusted ? 0x11 : 0);
  }
  out("remill_aas="); outi(ok); crlf();
  return 0;
}
