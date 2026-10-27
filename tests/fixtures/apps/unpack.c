/* Interleave and vector-move forms.
 *
 * `unpcklps`/`unpckhps` interleave dwords and `unpcklpd`/`unpckhpd` interleave
 * qwords -- the same operation the punpck family performs at byte and word
 * granularity, which the lifter already handled. `movq xmm, xmm` moves the low 64
 * bits of a vector register, and reading a vector register as a general register
 * throws, so the source has to be taken as a vector.
 *
 * Both were reaching the lifter and being rejected, so no fixture covered them.
 * The values below are chosen so that an interleave done at the wrong
 * granularity, or a move of the wrong half, produces a different number. */
#include "fy.h"

static u32 low32(u64 value) { return (u32)(value & 0xffffffffu); }

int app_main(void) {
  out("unpack:start"); crlf();

  volatile u64 a[2] = {0x1111111122222222ull, 0x3333333344444444ull};
  volatile u64 b[2] = {0x5555555566666666ull, 0x7777777788888888ull};
  volatile u64 out_low[2] = {0, 0};
  volatile u64 out_high[2] = {0, 0};
  volatile u64 out_pd[2] = {0, 0};
  volatile u64 out_move[2] = {0, 0};

  __asm__ volatile("movups (%0), %%xmm0" ::"r"(a));
  __asm__ volatile("movups (%0), %%xmm1" ::"r"(b));

  /* unpcklps: dwords 0 and 1 of each, low half of each register. */
  __asm__ volatile("unpcklps %%xmm1, %%xmm0\n\tmovups %%xmm0, (%0)" ::"r"(out_low) : "memory", "xmm0");
  out("unpcklps_0="); outi((int)low32(out_low[0])); crlf();
  out("unpcklps_1="); outi((int)low32(out_low[1])); crlf();

  __asm__ volatile("movups (%0), %%xmm0" ::"r"(a));
  __asm__ volatile("movups (%0), %%xmm1" ::"r"(b));
  /* unpckhps: dwords 2 and 3 of each. */
  __asm__ volatile("unpckhps %%xmm1, %%xmm0\n\tmovups %%xmm0, (%0)" ::"r"(out_high) : "memory", "xmm0");
  out("unpckhps_0="); outi((int)low32(out_high[0])); crlf();
  out("unpckhps_1="); outi((int)low32(out_high[1])); crlf();

  __asm__ volatile("movups (%0), %%xmm0" ::"r"(a));
  __asm__ volatile("movups (%0), %%xmm1" ::"r"(b));
  /* unpcklpd: qwords 0 of each -- a different result from unpcklps. */
  __asm__ volatile("unpcklpd %%xmm1, %%xmm0\n\tmovups %%xmm0, (%0)" ::"r"(out_pd) : "memory", "xmm0");
  out("unpcklpd_0="); outi((int)low32(out_pd[0])); crlf();
  out("unpcklpd_1="); outi((int)low32(out_pd[1])); crlf();

  /* movq xmm, xmm: the low 64 bits of the source. */
  __asm__ volatile("movups (%0), %%xmm0" ::"r"(a));
  __asm__ volatile("movups (%0), %%xmm1" ::"r"(b));
  __asm__ volatile("movq %%xmm1, %%xmm0\n\tmovups %%xmm0, (%0)" ::"r"(out_move) : "memory", "xmm0");
  out("movq_low="); outi((int)low32(out_move[0])); crlf();
  out("movq_high="); outi((int)low32(out_move[1])); crlf();

  out("unpack:done"); crlf();
  return 0;
}
