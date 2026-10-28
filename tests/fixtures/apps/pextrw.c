/* PEXTRW regression fixture.
 *
 * Remill's Apache-2.0 X86 MMX semantics select an XMM 16-bit lane modulo
 * eight, zero-extend it into the general-register destination, and do not
 * alter the source. The modulo case mirrors fd.exe's immediate lane use.
 */
#include "fy.h"

int app_main(void) {
  u16 lanes[8] = {0x1000, 0x1001, 0x1002, 0x1003, 0x1004, 0x1005, 0x1006, 0x1007};
  u32 modulo_lane = 0;
  u32 ordinary_lane = 0;

  __asm__ volatile("movdqu %2, %%xmm0\n\t"
                   "pextrw $13, %%xmm0, %%eax\n\t"
                   "mov %%eax, %0\n\t"
                   "pextrw $2, %%xmm0, %%ecx\n\t"
                   "mov %%ecx, %1"
                   : "=m"(modulo_lane), "=m"(ordinary_lane)
                   : "m"(*(u16(*)[8])lanes)
                   : "eax", "ecx", "xmm0");

  const int modulo_ok = modulo_lane == 0x1005u;
  const int ordinary_ok = ordinary_lane == 0x1002u;
  out("pextrw_modulo_ok="); outi(modulo_ok); crlf();
  out("pextrw_lane_ok="); outi(ordinary_ok); crlf();
  return modulo_ok && ordinary_ok ? 0 : 1;
}
