/* SSE2 packed-integer fixture.
 *
 * Exercises the element-wise packed operations the lifter now implements, in
 * both register and immediate forms. Every case folds the 16 result bytes into a
 * checksum, so a wrong element width, a missing saturation clamp or a wrong
 * shift direction changes the number. The operands are chosen to be hostile:
 * bytes that overflow, words that need saturation, and negative values where a
 * logical shift would differ from an arithmetic one.
 *
 * These are SSE, so unlike the VEX fixture this one is differentially verified
 * against the Unicorn reference. */
#include "fy.h"

#define LANES 16

static u64 fold(const u8* bytes) {
  u64 checksum = 0;
  for (int index = 0; index < LANES; index++) checksum = checksum * 131 + bytes[index];
  return checksum;
}

static int unpack_matches(const u8* result, const u8* left, const u8* right, int size, int high) {
  for (int index = 0; index < LANES; ++index) {
    const int lane = index / size;
    const u8* source = (lane & 1) ? right : left;
    const int offset = (high ? 8 : 0) + (lane / 2) * size + index % size;
    if (result[index] != source[offset]) return 0;
  }
  return 1;
}

/* result = a OP b, all three 128-bit. */
#define BINOP(op)                                                                        \
  do {                                                                                   \
    __asm__ volatile("movdqu %1, %%xmm0\n\t"                                             \
                     "movdqu %2, %%xmm1\n\t" op " %%xmm1, %%xmm0\n\t"                    \
                     "movdqu %%xmm0, %0"                                                 \
                     : "=m"(*(char(*)[LANES])result)                                     \
                     : "m"(*(char(*)[LANES])left), "m"(*(char(*)[LANES])right)           \
                     : "xmm0", "xmm1");                                                  \
  } while (0)

/* result = result SHIFT imm */
#define IMMOP(op, count)                                                                 \
  do {                                                                                   \
    __asm__ volatile("movdqu %1, %%xmm0\n\t" op " $" #count ", %%xmm0\n\t"               \
                     "movdqu %%xmm0, %0"                                                 \
                     : "=m"(*(char(*)[LANES])result)                                     \
                     : "m"(*(char(*)[LANES])left)                                        \
                     : "xmm0");                                                          \
  } while (0)

/* result = result OP [memory] */
#define MEMOP(op)                                                                        \
  do {                                                                                   \
    __asm__ volatile("movdqu %1, %%xmm0\n\t" op " %2, %%xmm0\n\t"                    \
                     "movdqu %%xmm0, %0"                                                 \
                     : "=m"(*(char(*)[LANES])result)                                     \
                     : "m"(*(char(*)[LANES])left), "m"(*(char(*)[LANES])right)           \
                     : "xmm0");                                                          \
  } while (0)

int app_main(void) {
  u8 left[LANES];
  u8 right[LANES];
  u8 result[LANES];

  for (int index = 0; index < LANES; index++) {
    left[index] = (u8)(index * 17 + 3);      /* 3, 20, 37, ...  */
    right[index] = (u8)(200 + index * 5);    /* 200, 205, ...   */
    result[index] = 0;
  }

  out("packed:start"); crlf();

  /* Wrapping byte and word arithmetic: the low 8 bits must not carry into the
     next lane. */
  BINOP("paddb"); out("paddb="); outi((i64)fold(result)); crlf();
  BINOP("psubb"); out("psubb="); outi((i64)fold(result)); crlf();
  BINOP("paddw"); out("paddw="); outi((i64)fold(result)); crlf();
  BINOP("psubw"); out("psubw="); outi((i64)fold(result)); crlf();
  BINOP("paddd"); out("paddd="); outi((i64)fold(result)); crlf();
  BINOP("paddq"); out("paddq="); outi((i64)fold(result)); crlf();

  /* Saturation: unsigned byte adds must clamp at 255, signed byte subtracts at
     -128. */
  BINOP("paddusb"); out("paddusb="); outi((i64)fold(result)); crlf();
  BINOP("paddsb"); out("paddsb="); outi((i64)fold(result)); crlf();
  BINOP("psubusb"); out("psubusb="); outi((i64)fold(result)); crlf();
  BINOP("psubsb"); out("psubsb="); outi((i64)fold(result)); crlf();
  BINOP("paddusw"); out("paddusw="); outi((i64)fold(result)); crlf();
  BINOP("psubsw"); out("psubsw="); outi((i64)fold(result)); crlf();

  /* Comparisons produce all-ones or all-zero per lane, at three widths. */
  BINOP("pcmpeqb"); out("pcmpeqb="); outi((i64)fold(result)); crlf();
  BINOP("pcmpeqw"); out("pcmpeqw="); outi((i64)fold(result)); crlf();
  BINOP("pcmpgtb"); out("pcmpgtb="); outi((i64)fold(result)); crlf();
  BINOP("pcmpgtw"); out("pcmpgtw="); outi((i64)fold(result)); crlf();

  /* Multiplies: low word, high word, and the unsigned dword product. */
  BINOP("pmullw"); out("pmullw="); outi((i64)fold(result)); crlf();
  BINOP("pmulhw"); out("pmulhw="); outi((i64)fold(result)); crlf();
  BINOP("pmulhuw"); out("pmulhuw="); outi((i64)fold(result)); crlf();
  BINOP("pmuludq"); out("pmuludq="); outi((i64)fold(result)); crlf();
  BINOP("pmaddwd"); out("pmaddwd="); outi((i64)fold(result)); crlf();
  BINOP("psadbw"); out("psadbw="); outi((i64)fold(result)); crlf();
  BINOP("pandn"); out("pandn="); outi((i64)fold(result)); crlf();

  /* Immediate shifts. PSRAW must replicate the sign, PSRLW must not. */
  IMMOP("psllw", 3); out("psllw3="); outi((i64)fold(result)); crlf();
  IMMOP("pslld", 5); out("pslld5="); outi((i64)fold(result)); crlf();
  IMMOP("psllq", 9); out("psllq9="); outi((i64)fold(result)); crlf();
  IMMOP("psrlw", 3); out("psrlw3="); outi((i64)fold(result)); crlf();
  IMMOP("psrld", 5); out("psrld5="); outi((i64)fold(result)); crlf();
  IMMOP("psrlq", 9); out("psrlq9="); outi((i64)fold(result)); crlf();
  IMMOP("psraw", 3); out("psraw3="); outi((i64)fold(result)); crlf();
  IMMOP("psrad", 5); out("psrad5="); outi((i64)fold(result)); crlf();

  /* Variable-count shifts: the count is the low 64 bits of the source operand
     and applies to EVERY element. Reading each element's own source element as
     its count gives a different answer, so this case pins that. */
  for (int index = 0; index < LANES; index++) {
    left[index] = 0xff;
    right[index] = 0;
  }
  right[0] = 2;                                  /* count = 2 for all elements */
  BINOP("psllw"); out("psllw_var="); outi((i64)fold(result)); crlf();
  BINOP("psrlw"); out("psrlw_var="); outi((i64)fold(result)); crlf();
  BINOP("psraw"); out("psraw_var="); outi((i64)fold(result)); crlf();
  BINOP("pslld"); out("pslld_var="); outi((i64)fold(result)); crlf();
  BINOP("psrad"); out("psrad_var="); outi((i64)fold(result)); crlf();

  /* Saturation edge: 0 - (-128) must clamp to +127, not wrap to -128. */
  for (int index = 0; index < LANES; index++) {
    left[index] = 0x00;
    right[index] = 0x80;
  }
  BINOP("psubsb"); out("psubsb_edge="); outi((i64)fold(result)); crlf();
  for (int index = 0; index < LANES; index += 2) {
    left[index] = 0x00; left[index + 1] = 0x00;
    right[index] = 0x00; right[index + 1] = 0x80;   /* word 0x8000 = -32768 */
  }
  BINOP("psubsw"); out("psubsw_edge="); outi((i64)fold(result)); crlf();

  /* Whole-register byte shifts. */
  IMMOP("psrldq", 4); out("psrldq4="); outi((i64)fold(result)); crlf();
  IMMOP("pslldq", 4); out("pslldq4="); outi((i64)fold(result)); crlf();

  /* Unpack and pack, which change the lane layout rather than the values. */
  BINOP("punpcklbw"); out("punpcklbw="); outi((i64)fold(result)); crlf();
  BINOP("punpckhbw"); out("punpckhbw="); outi((i64)fold(result)); crlf();
  BINOP("punpcklwd"); out("punpcklwd="); outi((i64)fold(result)); crlf();
  BINOP("punpckhwd"); out("punpckhwd="); outi((i64)fold(result)); crlf();
  BINOP("packsswb"); out("packsswb="); outi((i64)fold(result)); crlf();
  BINOP("packuswb"); out("packuswb="); outi((i64)fold(result)); crlf();
  BINOP("packssdw"); out("packssdw="); outi((i64)fold(result)); crlf();

  /* Byte shuffle and the half-word shuffles. */
  BINOP("pshufb"); out("pshufb="); outi((i64)fold(result)); crlf();
  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "pshuflw $0x1b, %%xmm0, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(*(char(*)[LANES])result)
                   : "m"(*(char(*)[LANES])left)
                   : "xmm0");
  out("pshuflw="); outi((i64)fold(result)); crlf();
  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "pshufhw $0x1b, %%xmm0, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(*(char(*)[LANES])result)
                   : "m"(*(char(*)[LANES])left)
                   : "xmm0");
  out("pshufhw="); outi((i64)fold(result)); crlf();

  /* A memory-source PSHUFD selects dwords, including nontrivial reordering. */
  __asm__ volatile("pshufd $0x1b, %1, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(*(char(*)[LANES])result)
                   : "m"(*(char(*)[LANES])left) : "xmm0");
  int shuffle_ok = 1;
  for (int index = 0; index < LANES; ++index)
    if (result[index] != left[(3 - index / 4) * 4 + index % 4]) shuffle_ok = 0;
  out("pshufd_mem_ok="); outi(shuffle_ok); crlf();

  /* SHUFPS selects two lanes from each operand; exercise register and memory sources. */
  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "movdqu %2, %%xmm1\n\t"
                   "shufps $0x88, %%xmm1, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(*(char(*)[LANES])result)
                   : "m"(*(char(*)[LANES])left), "m"(*(char(*)[LANES])right) : "xmm0", "xmm1");
  shuffle_ok = 1;
  for (int index = 0; index < LANES; ++index) {
    const u8* source = index < 8 ? left : right;
    if (result[index] != source[((index % 8) / 4) * 8 + index % 4]) shuffle_ok = 0;
  }
  out("shufps_reg_ok="); outi(shuffle_ok); crlf();
  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "shufps $0x88, %2, %%xmm0\n\t"
                   "movdqu %%xmm0, %0"
                   : "=m"(*(char(*)[LANES])result)
                   : "m"(*(char(*)[LANES])left), "m"(*(char(*)[LANES])right) : "xmm0");
  shuffle_ok = 1;
  for (int index = 0; index < LANES; ++index) {
    const u8* source = index < 8 ? left : right;
    if (result[index] != source[((index % 8) / 4) * 8 + index % 4]) shuffle_ok = 0;
  }
  out("shufps_mem_ok="); outi(shuffle_ok); crlf();

  /* PMOVMSKB moves the sign bit of each byte into a general-purpose register. */
  u32 mask = 0;
  __asm__ volatile("movdqu %1, %%xmm0\n\t"
                   "pmovmskb %%xmm0, %0"
                   : "=r"(mask)
                   : "m"(*(char(*)[LANES])right)
                   : "xmm0");
  out("pmovmskb="); outi((i64)mask); crlf();

  /* Memory-source forms. Five helpers here (paddd, psubd, pcmpeqd, pmaddwd,
     psadbw) once had no _memory twin, so a memory operand produced generated
     code that did not compile while `coverage` still reported it as lifted.
     These cases exercise exactly those five through a memory operand. */
  for (int index = 0; index < LANES; index++) {
    left[index] = (u8)(index * 11 + 5);
    right[index] = (u8)(240 - index * 3);
    result[index] = 0;
  }
  MEMOP("paddd"); out("mem_paddd="); outi((i64)fold(result)); crlf();
  MEMOP("psubd"); out("mem_psubd="); outi((i64)fold(result)); crlf();
  MEMOP("pcmpeqd"); out("mem_pcmpeqd="); outi((i64)fold(result)); crlf();
  MEMOP("pmaddwd"); out("mem_pmaddwd="); outi((i64)fold(result)); crlf();
  MEMOP("psadbw"); out("mem_psadbw="); outi((i64)fold(result)); crlf();
  MEMOP("paddw"); out("mem_paddw="); outi((i64)fold(result)); crlf();
  MEMOP("punpcklbw"); out("mem_unpack_lb="); outi(unpack_matches(result, left, right, 1, 0)); crlf();
  MEMOP("punpckhbw"); out("mem_unpack_hb="); outi(unpack_matches(result, left, right, 1, 1)); crlf();
  MEMOP("punpcklwd"); out("mem_unpack_lw="); outi(unpack_matches(result, left, right, 2, 0)); crlf();
  MEMOP("punpckhwd"); out("mem_unpack_hw="); outi(unpack_matches(result, left, right, 2, 1)); crlf();
  MEMOP("punpckldq"); out("mem_unpack_ld="); outi(unpack_matches(result, left, right, 4, 0)); crlf();
  MEMOP("punpckhdq"); out("mem_unpack_hd="); outi(unpack_matches(result, left, right, 4, 1)); crlf();
  MEMOP("punpcklqdq"); out("mem_unpack_lq="); outi(unpack_matches(result, left, right, 8, 0)); crlf();
  MEMOP("punpckhqdq"); out("mem_unpack_hq="); outi(unpack_matches(result, left, right, 8, 1)); crlf();
  BINOP("unpcklps"); out("reg_unpack_lps="); outi(unpack_matches(result, left, right, 4, 0)); crlf();
  BINOP("unpckhps"); out("reg_unpack_hps="); outi(unpack_matches(result, left, right, 4, 1)); crlf();
  BINOP("unpcklpd"); out("reg_unpack_lpd="); outi(unpack_matches(result, left, right, 8, 0)); crlf();
  BINOP("unpckhpd"); out("reg_unpack_hpd="); outi(unpack_matches(result, left, right, 8, 1)); crlf();
  MEMOP("unpcklps"); out("mem_unpack_lps="); outi(unpack_matches(result, left, right, 4, 0)); crlf();
  MEMOP("unpckhps"); out("mem_unpack_hps="); outi(unpack_matches(result, left, right, 4, 1)); crlf();
  MEMOP("unpcklpd"); out("mem_unpack_lpd="); outi(unpack_matches(result, left, right, 8, 0)); crlf();
  MEMOP("unpckhpd"); out("mem_unpack_hpd="); outi(unpack_matches(result, left, right, 8, 1)); crlf();

  out("packed:done"); crlf();
  return 0;
}
