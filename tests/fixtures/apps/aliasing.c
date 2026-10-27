/* Register-aliasing fixture.
 *
 * Exercises 8/16/32/64-bit register writes, sub-register merges, the high-byte
 * registers (ah/bh/ch/dh) and 32-bit zero-extension, so a mistake in
 * partial-register modelling changes the printed values. */
#include "fy.h"

static u32 mix_bytes(u8 low, u8 high) { return (u32)low * 0x01010101u + (u32)high; }

int app_main(void) {
  out("aliasing:start"); crlf();

  /* ah/al style: build a 16-bit value from two bytes. */
  u8 low = 0xab;
  u8 high = 0xcd;
  u16 word = (u16)((u16)(high << 8) | (u16)low);
  out("word="); outi(word); crlf();

  /* word/dword halves. */
  u32 dword = 0x12345678u;
  out("upper16="); outi((u16)(dword >> 16)); crlf();
  out("lower16="); outi((u16)dword); crlf();

  /* 64-bit halves. */
  u64 qword = 0x1122334455667788ull;
  out("q_hi="); outi((i64)(qword >> 32)); crlf();
  out("q_lo="); outi((i64)(u32)qword); crlf();

  /* Writing a 32-bit register must clear bits 32..63. */
  u64 widened = 0xffffffffffffffffull;
  widened = (u64)(u32)0x00000001u;
  out("zero_extend="); outi((i64)widened); crlf();

  /* Sign extension through narrowing types. */
  out("s8="); outi((i64)(i8)0x80); crlf();
  out("s16="); outi((i64)(i16)0x8000); crlf();
  out("s32="); outi((i64)(i32)0x80000000u); crlf();

  /* Byte merges across a loop to catch any sub-register corruption. */
  u32 accumulator = 0;
  u16 staging = 0;
  for (int index = 0; index < 24; index++) {
    staging = (u16)((staging & 0xff00u) | (u16)((index * 7 + 1) & 0xff));
    staging = (u16)((staging & 0x00ffu) | (u16)(((index * 13 + 5) & 0xff) << 8));
    accumulator += mix_bytes((u8)staging, (u8)(staging >> 8));
  }
  out("accumulator="); outi(accumulator); crlf();

  out("aliasing:done"); crlf();
  return 0;
}
