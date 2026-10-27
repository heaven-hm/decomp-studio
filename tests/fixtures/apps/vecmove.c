/* SSE vector-move merge fixture.
 *
 * A register-to-register move narrower than 16 bytes is a merge, not a copy:
 * `movsd xmm2, xmm0` writes the low 64 bits and leaves xmm2[127:64] alone, and
 * `movss` does the same for the low 32 bits. The lifter used to emit a 16-byte
 * memcpy for every register-to-register move regardless of width, which
 * clobbered that upper half. The two values below are chosen so the difference
 * is unmistakable: the correct results are {7, 11} and a float 33.0 still in
 * the top lane, and the 16-byte copy produced {7, 22} and a zeroed top lane.
 *
 * This is also the mechanism the three-operand VEX scalar forms rely on, so a
 * regression here breaks those too. */
#include "fy.h"

int app_main(void) {
  out("vecmove:start"); crlf();

  /* movsd: low double replaced, high double preserved. */
  double destination[2] = {0.0, 11.0};
  double source[2] = {7.0, 22.0};
  double merged[2] = {0.0, 0.0};
  __asm__ volatile(
      "movupd %1, %%xmm2\n\t"
      "movupd %2, %%xmm0\n\t"
      "movsd %%xmm0, %%xmm2\n\t"
      "movupd %%xmm2, %0"
      : "=m"(*(double(*)[2])merged)
      : "m"(*(double(*)[2])destination), "m"(*(double(*)[2])source)
      : "xmm0", "xmm2");
  out("movsd_lo="); outi((i64)merged[0]); crlf();
  out("movsd_hi="); outi((i64)merged[1]); crlf();

  /* movss: low float replaced, the other three lanes preserved. */
  float destination_f[4] = {0.0f, 0.0f, 0.0f, 33.0f};
  float source_f[4] = {5.0f, 0.0f, 0.0f, 0.0f};
  float merged_f[4] = {0.0f, 0.0f, 0.0f, 0.0f};
  __asm__ volatile(
      "movups %1, %%xmm3\n\t"
      "movups %2, %%xmm1\n\t"
      "movss %%xmm1, %%xmm3\n\t"
      "movups %%xmm3, %0"
      : "=m"(*(float(*)[4])merged_f)
      : "m"(*(float(*)[4])destination_f), "m"(*(float(*)[4])source_f)
      : "xmm1", "xmm3");
  out("movss_lo="); outi((i64)merged_f[0]); crlf();
  out("movss_lane3="); outi((i64)merged_f[3]); crlf();

  /* The load forms must zero what they do not fill: `movsd xmm, m64` leaves
     xmm[127:64] zero, unlike the register form above. */
  double loaded[2] = {0.0, 0.0};
  double scalar_source = 42.0;
  __asm__ volatile(
      "movupd %1, %%xmm4\n\t"
      "movsd %2, %%xmm4\n\t"
      "movupd %%xmm4, %0"
      : "=m"(*(double(*)[2])loaded)
      : "m"(*(double(*)[2])destination), "m"(scalar_source)
      : "xmm4");
  out("load_lo="); outi((i64)loaded[0]); crlf();
  out("load_hi="); outi((i64)loaded[1]); crlf();

  out("vecmove:done"); crlf();
  return 0;
}
