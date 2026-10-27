/* Packed integer-to-float conversion fixture.
 *
 * Exercises CVTDQ2PS with register and memory operands, signed values, negative
 * values, values around the 2^24 precision boundary and int32 extremes, under
 * all four MXCSR rounding modes. Results are printed as raw single-precision bit
 * patterns so the comparison against the reference is exact. LDMXCSR/STMXCSR
 * round-tripping is checked directly.
 */
#include "fy.h"

/* The MXCSR precision flag (bit 5) is architecturally set when a conversion is
 * inexact, but the Unicorn/QEMU reference does not model it for CVTDQ2PS. It is
 * masked out of the printed state so the comparison isolates the rounding mode
 * and the conversion results, which both sides do model. */
#define kMxcsrPrecisionFlag ((u32)0x20u)

static u32 read_mxcsr(void) {
  u32 value;
  __asm__ volatile("stmxcsr %0" : "=m"(value));
  return value;
}

static void write_mxcsr(u32 value) {
  __asm__ volatile("ldmxcsr %0" : : "m"(value) : "memory");
}

/* cvtdq2ps with an XMM register source. */
static void convert_vector(const i32* input, float* output) {
  __asm__ volatile("movdqu (%1), %%xmm0\n\t"
                   "cvtdq2ps %%xmm0, %%xmm0\n\t"
                   "movups %%xmm0, (%0)"
                   :
                   : "r"(output), "r"(input)
                   : "xmm0", "memory");
}

/* cvtdq2ps with a 128-bit memory source. */
static void convert_memory(const i32* input, float* output) {
  __asm__ volatile("cvtdq2ps (%1), %%xmm0\n\t"
                   "movups %%xmm0, (%0)"
                   :
                   : "r"(output), "r"(input)
                   : "xmm0", "memory");
}

static u32 bits_of(float value) {
  u32 bits;
  __builtin_memcpy(&bits, &value, 4);
  return bits;
}

static void emit_row(const char* label, const i32* input) {
  float converted[4];
  convert_vector(input, converted);
  out(label);
  outc(' ');
  for (i32 index = 0; index < 4; index++) {
    outi(bits_of(converted[index]));
    outc(' ');
  }
  out("mxcsr=");
  outi((i64)(read_mxcsr() & ~kMxcsrPrecisionFlag));
  crlf();
}

static const i32 kNormal[4] = {1, 2, 3, 4};
static const i32 kNegative[4] = {-1, -2, -3, (i32)0x80000000u};
static const i32 kBoundary[4] = {16777216, 16777217, 16777219, 33554433};
static const i32 kExtremes[4] = {2147483647, (i32)0x80000000u, 123456789, -123456789};

int app_main(void) {
  out("simdconvert:start"); crlf();
  out("default_mxcsr="); outi((i64)(read_mxcsr() & ~kMxcsrPrecisionFlag)); crlf();

  for (i32 mode = 0; mode < 4; mode++) {
    write_mxcsr(0x1f80u | ((u32)mode << 13));
    out("mode="); outi(mode);
    out(" rc_mxcsr="); outi((i64)(read_mxcsr() & ~kMxcsrPrecisionFlag)); crlf();
    emit_row("normal", kNormal);
    emit_row("negative", kNegative);
    emit_row("boundary", kBoundary);
    emit_row("extremes", kExtremes);
  }

  write_mxcsr(0x1f80u);

  float converted[4];
  convert_memory(kExtremes, converted);
  out("memory ");
  for (i32 index = 0; index < 4; index++) {
    outi(bits_of(converted[index]));
    outc(' ');
  }
  out("mxcsr="); outi((i64)(read_mxcsr() & ~kMxcsrPrecisionFlag)); crlf();

  /* STMXCSR / LDMXCSR must round-trip the full register. */
  const u32 distinctive = 0x1f80u | (2u << 13) | (1u << 6) | (1u << 15);
  write_mxcsr(distinctive);
  out("roundtrip="); outi((i64)(read_mxcsr() & ~kMxcsrPrecisionFlag)); crlf();
  write_mxcsr(0x1f80u);
  out("restored="); outi((i64)(read_mxcsr() & ~kMxcsrPrecisionFlag)); crlf();

  out("simdconvert:done"); crlf();
  return 0;
}
