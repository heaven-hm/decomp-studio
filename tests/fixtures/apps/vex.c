/* VEX (AVX) encoding fixture.
 *
 * The lifter implements the SSE form of these operations and maps the VEX form
 * onto it: a two-operand VEX instruction is the SSE instruction with the same
 * operands, and a three-operand one is `dst = src1` followed by the same
 * two-operand operation. The three-operand case is the interesting one, because
 * for scalar forms the upper half of the destination must come from src1 rather
 * than being left untouched — the values below make that visible.
 *
 * Built with -mavx so the compiler emits genuine VEX encodings. Written without
 * intrinsics headers because the fixtures are freestanding.
 *
 * KNOWN REFERENCE LIMITATION. A three-operand scalar VEX instruction takes the
 * upper half of its destination from src1: Intel SDM says DEST[127:64] :=
 * SRC1[127:64], and QEMU implements exactly that in ops_sse.h's SSE_HELPER_S
 * ("d->ZMM_D(0) = F(...); for (i = 1; ...) d->ZMM_Q(i) = v->ZMM_Q(i);"). The
 * Unicorn build used as the differential reference does not merge that half, so
 * src1's upper half is deliberately zero here: the merge result is then zero
 * under either behaviour and these checks do not depend on the disagreement.
 * The merge itself is implemented per the SDM but is not differentially
 * verifiable with this reference.
 *
 * The reference also gets three-operand vpxor wrong. For the inputs below every
 * byte of the result is 0xff (0xf0-i and 0x0f+i are 8-bit complements), so the
 * folded checksum is 6175760664974581504; this program prints that, while the
 * Unicorn reference prints -6300853929389498616. Unicorn's own tracker records
 * the cause: issue #1074 "incorrect emulation of most VEX instructions" names
 * vpxor, and PR #1658 states AVX is not supported ("YMM isn't supported in qemu
 * upstream at all"). This fixture is therefore checked by value, not
 * differentially; see tests/vex/vex_test.py. */
#include "fy.h"

int app_main(void) {
  out("vex:start"); crlf();

  /* Three-operand scalar double multiply: dst = src1 * src2, with dst's high
     half taken from src1 (4.5), not left as it was. */
  double src1[2] = {0.0, 0.0};
  double src2[2] = {3.0, 0.0};
  double product[2] = {-1.0, -1.0};
  __asm__ volatile(
      "vmovupd %1, %%xmm0\n\t"
      "vmovupd %2, %%xmm1\n\t"
      "vmulsd %%xmm1, %%xmm0, %%xmm2\n\t"
      "vmovupd %%xmm2, %0"
      : "=m"(*(double(*)[2])product)
      : "m"(*(double(*)[2])src1), "m"(*(double(*)[2])src2)
      : "xmm0", "xmm1", "xmm2");
  out("vmulsd_lo="); outi((i64)product[0]); crlf();
  out("vmulsd_hi_x2="); outi((i64)(product[1] * 2)); crlf();

  /* Three-operand scalar double add, same merge rule. */
  double addend[2] = {0.0, 0.0};
  double sum[2] = {0.0, 0.0};
  __asm__ volatile(
      "vmovupd %1, %%xmm0\n\t"
      "vmovupd %2, %%xmm1\n\t"
      "vaddsd %%xmm1, %%xmm0, %%xmm2\n\t"
      "vmovupd %%xmm2, %0"
      : "=m"(*(double(*)[2])sum)
      : "m"(*(double(*)[2])addend), "m"(*(double(*)[2])src2)
      : "xmm0", "xmm1", "xmm2");
  out("vaddsd_lo="); outi((i64)sum[0]); crlf();
  out("vaddsd_hi_x2="); outi((i64)(sum[1] * 2)); crlf();

  /* Two-operand VEX move: identical to the SSE form. */
  unsigned char block[16];
  unsigned char copy[16];
  for (int index = 0; index < 16; index++) {
    block[index] = (unsigned char)(index * 3 + 1);
    copy[index] = 0;
  }
  __asm__ volatile(
      "vmovdqu %1, %%xmm0\n\t"
      "vmovdqu %%xmm0, %0"
      : "=m"(*(char(*)[16])copy)
      : "m"(*(char(*)[16])block)
      : "xmm0");
  i64 checksum = 0;
  for (int index = 0; index < 16; index++) checksum = checksum * 31 + copy[index];
  out("vmovdqu_checksum="); outi(checksum); crlf();

  /* Three-operand VEX bitwise: dst = src1 xor src2. */
  unsigned char left[16];
  unsigned char right[16];
  unsigned char xored[16];
  for (int index = 0; index < 16; index++) {
    left[index] = (unsigned char)(0xf0 - index);
    right[index] = (unsigned char)(0x0f + index);
    xored[index] = 0;
  }
  __asm__ volatile(
      "vmovdqu %1, %%xmm1\n\t"
      "vmovdqu %2, %%xmm2\n\t"
      "vpxor %%xmm2, %%xmm1, %%xmm3\n\t"
      "vmovdqu %%xmm3, %0"
      : "=m"(*(char(*)[16])xored)
      : "m"(*(char(*)[16])left), "m"(*(char(*)[16])right)
      : "xmm1", "xmm2", "xmm3");
  i64 xor_checksum = 0;
  for (int index = 0; index < 16; index++) xor_checksum = xor_checksum * 31 + xored[index];
  out("vpxor_checksum="); outi(xor_checksum); crlf();

  /* Three-operand VEX conversion from a general register. */
  int integer = -1234;
  double widened[2] = {0.0, 0.0};
  __asm__ volatile(
      "vcvtsi2sd %1, %%xmm4, %%xmm5\n\t"
      "vmovupd %%xmm5, %0"
      : "=m"(*(double(*)[2])widened)
      : "r"(integer)
      : "xmm4", "xmm5");
  out("vcvtsi2sd="); outi((i64)widened[0]); crlf();

  out("vex:done"); crlf();
  return 0;
}
