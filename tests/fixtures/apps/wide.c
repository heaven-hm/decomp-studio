/* 64-bit arithmetic fixture.
 *
 * Exercises 64-bit multiply, add, shift, divide and mixed 32/64-bit widths,
 * including the carry/overflow flags of 64-bit operations and 64-bit shifts.
 * A wrong 64-bit width or shift changes the printed values. */
#include "fy.h"

static u64 mix(u64 value) {
  value ^= value >> 33;
  value *= 0xff51afd7ed558ccdull;
  value ^= value >> 29;
  return value;
}

int app_main(void) {
  out("wide:start"); crlf();

  /* Rolling 64-bit checksum used by the flags fixture. */
  u64 checksum = 0;
  for (int index = 0; index < 36; index++) checksum = checksum * 131 + (u64)(index * 7 + 3);
  out("roll="); outi((i64)checksum); crlf();
  out("roll_hi="); outi((i64)(checksum >> 32)); crlf();

  /* 64-bit shifts at every width boundary. */
  const u64 pattern = 0x0123456789abcdefull;
  for (int amount = 0; amount <= 64; amount += 8) {
    out("shl="); outi((i64)(pattern << amount)); outc(' ');
    outi((i64)(pattern >> amount)); outc(' ');
    outi((i64)((u64)((i64)pattern >> amount))); crlf();
  }

  /* 64-bit multiply, including the full 128-bit product split. */
  const u64 left = 0xfedcba9876543210ull;
  const u64 right = 0x0fedcba987654321ull;
  const u64 product_low = left * right;
  out("mul_lo="); outi((i64)product_low); crlf();

  /* 64-bit division and remainder. */
  out("div="); outi((i64)(left / (right | 1u))); crlf();
  out("mod="); outi((i64)(left % (right | 1u))); crlf();

  /* Signed 64-bit comparisons and negation. */
  i64 negative = -1234567890123ll;
  out("abs="); outi(negative < 0 ? -negative : negative); crlf();
  out("shift_right_signed="); outi((i64)(negative >> 7)); crlf();

  /* Final hash chain mixes everything. */
  u64 hash = 0xcbf29ce484222325ull;
  for (int index = 0; index < 32; index++) {
    hash ^= mix((u64)index * 0x9e3779b97f4a7c15ull);
    hash = (hash << 7) | (hash >> 57);
  }
  out("hash="); outi((i64)hash); crlf();

  out("wide:done"); crlf();
  return 0;
}
